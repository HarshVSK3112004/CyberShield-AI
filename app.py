"""
CyberShield-AI — single-file entry point.

This consolidates what used to be app.py + pages/{Login,Register,Dashboard,
History,Profile,About}.py into one file with a manual sidebar router, instead
of relying on Streamlit's automatic pages/ folder discovery.

Run with:  streamlit run app.py

Backend logic (database, ML prediction, security checks, chatbot) still
lives in its own modules under database/, prediction/, security/,
chatbot/, and utils/ — only the UI/page layer was merged here.
"""
import streamlit as st
import pandas as pd

from database.db import (
    init_db,
    register_user,
    verify_user,
    reset_password,
    add_scan_history,
    get_history,
    get_user_stats,
    get_auth_logs,
)
from prediction.predictor import predict
from chatbot.chatbot import get_response
from utils.helper import get_logger, is_valid_email

logger = get_logger(__name__)

# ----------------------------
# OPTIONAL SECURITY MODULES
# ----------------------------
# These depend on optional packages (e.g. python-whois) or network access,
# so we import them defensively and disable the related checkbox if a
# module fails to load, instead of crashing the whole app.

try:
    from security.ssl_checker import check_ssl
except ImportError as e:
    logger.warning("SSL checker unavailable: %s", e)
    check_ssl = None

try:
    from security.whois_lookup import get_whois
except ImportError as e:
    logger.warning("WHOIS lookup unavailable: %s", e)
    get_whois = None

try:
    from security.virustotal import check_virustotal
except ImportError as e:
    logger.warning("VirusTotal checker unavailable: %s", e)
    check_virustotal = None


# ============================================================
# PAGE CONFIG + SHARED SESSION STATE
# ============================================================

st.set_page_config(
    page_title="CyberShield-AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "page" not in st.session_state:
    st.session_state.page = "Home"
if "messages" not in st.session_state:
    st.session_state.messages = []


def go_to(page_name: str):
    st.session_state.page = page_name


def require_login() -> bool:
    """Show a warning and return False if the user isn't logged in."""
    if not st.session_state.get("logged_in"):
        st.warning("Please login first.")
        st.info("Use the sidebar to go to **Login**.")
        return False
    return True


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

with st.sidebar:
    st.title("🛡️ CyberShield-AI")

    if st.session_state.logged_in and st.session_state.user:
        st.caption(f"Logged in as **{st.session_state.user['username']}**")
    else:
        st.caption("Not logged in")

    pages = ["Home", "Dashboard", "History", "Profile", "About"]
    if not st.session_state.logged_in:
        pages = ["Home", "Login", "Register", "Forgot Password", "About"]

    # Keep the current page selection valid if login state just changed
    if st.session_state.page not in pages:
        st.session_state.page = "Home"

    choice = st.radio("Navigate", pages, index=pages.index(st.session_state.page))
    st.session_state.page = choice

    st.divider()
    if st.session_state.logged_in:
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.messages = []
            go_to("Home")
            st.rerun()


# ============================================================
# PAGE: HOME
# ============================================================

def page_home():
    st.title("🛡️ CyberShield-AI")
    st.subheader("AI-Powered Phishing URL Detection & Cyber Risk Assessment")

    st.markdown(
        """
        Welcome to **CyberShield-AI** — a tool that combines machine learning,
        URL heuristics, SSL certificate checks, WHOIS domain lookups, and
        VirusTotal reputation data to help you assess whether a link is safe.

        ### Get started
        - 👉 Use the sidebar to **Register** or **Login**.
        - Once logged in, head to the **Dashboard** to check a URL.
        - View your past checks under **History**.
        - Have a question? Chat with the assistant on the Dashboard page.

        ### Why this matters
        Phishing remains one of the most common ways attackers steal credentials
        and financial information. A quick automated check before you click can
        catch many of the obvious red flags — though it's never a substitute for
        good judgment and multi-factor authentication.
        """
    )

    if st.session_state.logged_in and st.session_state.user:
        st.success(
            f"You're logged in as **{st.session_state.user['username']}**. "
            "Head to the Dashboard from the sidebar."
        )
    else:
        st.info("You're not logged in yet. Go to **Login** or **Register** in the sidebar to get started.")


# ============================================================
# PAGE: LOGIN
# ============================================================

def page_login():
    st.title("🔐 Login")

    if st.session_state.get("logged_in"):
        st.success(f"You're already logged in as **{st.session_state.user['username']}**.")
        if st.button("Log out"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.rerun()
        return

    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            result = verify_user(email, password)

            if result["status"] == "ok":
                user = result["user"]
                st.session_state.logged_in = True
                st.session_state.user = user
                st.success(f"Welcome back, {user['username']}!")
                st.info("Head to the **Dashboard** from the sidebar to check a URL.")
                go_to("Dashboard")
                st.rerun()

            elif result["status"] == "locked":
                minutes, seconds = divmod(result["retry_after"], 60)
                st.error(
                    f"🔒 Too many failed attempts. Account temporarily locked. "
                    f"Try again in {minutes}m {seconds}s."
                )

            else:
                st.error("Invalid email or password.")

    st.caption("Forgot your password?")
    if st.button("Reset it here", key="goto_forgot_password"):
        go_to("Forgot Password")
        st.rerun()


# ============================================================
# PAGE: FORGOT PASSWORD
# ============================================================

def page_forgot_password():
    st.title("🔑 Reset Password")
    st.caption(
        "Enter the email and username on your account to set a new password. "
        "This also clears any active login lockout on the account."
    )

    with st.form("forgot_password_form"):
        email = st.text_input("Email")
        username = st.text_input("Username")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Reset Password")

        if submitted:
            if not email or not username or not new_password:
                st.error("Please fill in all fields.")
            elif not is_valid_email(email):
                st.error("Please enter a valid email address.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            elif len(new_password) < 6:
                st.error("Password must be at least 6 characters long.")
            else:
                success, message = reset_password(email, username, new_password)
                if success:
                    st.success(message)
                    st.info("Go to the **Login** page from the sidebar to sign in.")
                else:
                    st.error(message)


# ============================================================
# PAGE: REGISTER
# ============================================================

def page_register():
    st.title("📝 Create an Account")

    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if not username or not email or not password:
                st.error("Please fill in all fields.")
            elif not is_valid_email(email):
                st.error("Please enter a valid email address.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters long.")
            else:
                success, message = register_user(username, email, password)
                if success:
                    st.success(message)
                    st.info("Go to the **Login** page from the sidebar to sign in.")
                else:
                    st.error(message)


# ============================================================
# PAGE: DASHBOARD
# ============================================================

def page_dashboard():
    st.title("🛡️ CyberShield AI Dashboard")

    if not require_login():
        return

    user = st.session_state["user"]
    st.success(f"Welcome **{user['username']}**")
    st.divider()

    # ----------------------------
    # URL INPUT
    # ----------------------------
    st.subheader("🔍 Phishing Website Detection")

    url = st.text_input("Enter Website URL", placeholder="https://example.com")

    run_ssl = st.checkbox("Check SSL Certificate", disabled=check_ssl is None)
    run_whois = st.checkbox("WHOIS Lookup", disabled=get_whois is None)
    run_vt = st.checkbox("VirusTotal Scan", disabled=check_virustotal is None)

    if st.button("Analyze Website", use_container_width=True):
        if url == "":
            st.error("Please enter a URL.")
        else:
            with st.spinner("Analyzing..."):
                result = predict(url)

            verdict = result["verdict"]
            probability = result["probability"]

            if verdict == "Phishing":
                st.error(f"⚠️ Phishing Website Detected\n\nConfidence : {probability:.2%}")
            else:
                st.success(f"✅ Legitimate Website\n\nConfidence : {probability:.2%}")

            # Save history
            add_scan_history(user["id"], url, verdict, probability)
            st.success("Prediction saved to History.")
            st.divider()

            # Model details
            st.subheader("📊 Prediction Details")
            st.write(result)

            # SSL
            if run_ssl and check_ssl:
                st.subheader("🔒 SSL Information")
                st.json(check_ssl(url))

            # WHOIS
            if run_whois and get_whois:
                st.subheader("🌐 WHOIS Information")
                st.json(get_whois(url))

            # VirusTotal
            if run_vt and check_virustotal:
                st.subheader("🦠 VirusTotal Report")
                st.json(check_virustotal(url))

    st.divider()

    # ----------------------------
    # CHATBOT
    # ----------------------------
    st.subheader("🤖 Cyber Assistant")

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    prompt = st.chat_input("Ask me anything about Cyber Security")
    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        reply = get_response(prompt)
        st.session_state.messages.append({"role": "assistant", "content": reply})
        st.rerun()


# ============================================================
# PAGE: HISTORY
# ============================================================

def page_history():
    st.title("📜 Scan History")

    if not require_login():
        return

    user = st.session_state["user"]
    st.success(f"Logged in as **{user['username']}**")
    st.divider()

    history = get_history(user["id"])

    if len(history) == 0:
        st.info("No scan history available.")
        return

    rows = [
        {
            "URL": item["url"],
            "Prediction": item["prediction"],
            "Confidence (%)": round(item["probability"] * 100, 2),
            "Date": item["created_at"],
        }
        for item in history
    ]
    df = pd.DataFrame(rows)

    # Filters
    st.subheader("🔍 Filter Records")
    col1, col2 = st.columns(2)
    with col1:
        prediction_filter = st.selectbox("Prediction", ["All", "Phishing", "Legitimate"])
    with col2:
        search = st.text_input("Search URL")

    filtered = df.copy()
    if prediction_filter != "All":
        filtered = filtered[filtered["Prediction"] == prediction_filter]
    if search:
        filtered = filtered[filtered["URL"].str.contains(search, case=False)]

    # Metrics
    st.divider()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Scans", len(df))
    c2.metric("Phishing", len(df[df["Prediction"] == "Phishing"]))
    c3.metric("Legitimate", len(df[df["Prediction"] == "Legitimate"]))
    st.divider()

    # Table
    st.subheader("📋 Scan Records")
    st.dataframe(filtered, use_container_width=True, hide_index=True)

    # Download
    csv = filtered.to_csv(index=False)
    st.download_button("⬇ Download History", csv, "scan_history.csv", "text/csv")

    # Chart
    st.divider()
    st.subheader("📊 Scan Summary")
    st.bar_chart(df["Prediction"].value_counts())

    st.caption("CyberShield AI • History Module")


# ============================================================
# PAGE: PROFILE
# ============================================================

def page_profile():
    st.title("👤 User Profile")

    if not require_login():
        return

    user = st.session_state["user"]

    st.subheader("Personal Information")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Username", value=user["username"], disabled=True)
    with col2:
        st.text_input("Email", value=user["email"], disabled=True)

    st.divider()

    stats = get_user_stats(user["id"])

    st.subheader("📊 Security Statistics")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Scans", stats["total"])
    c2.metric("Phishing Detected", stats["phishing"])
    c3.metric("Legitimate Websites", stats["safe"])

    st.divider()

    st.subheader("Prediction Distribution")
    st.bar_chart({"Phishing": stats["phishing"], "Legitimate": stats["safe"]})

    st.divider()

    st.subheader("Account Status")
    st.success("🟢 Account Active")
    st.info(
        f"""
**User ID:** {user['id']}

**Username:** {user['username']}

**Email:** {user['email']}

Your CyberShield AI account is active and functioning correctly.
"""
    )

    st.divider()

    st.subheader("🔐 Recent Login Activity")
    st.caption("Security monitoring log — every login attempt on this account, successful or not.")

    logs = get_auth_logs(email=user["email"], limit=20)

    if len(logs) == 0:
        st.info("No login activity recorded yet.")
    else:
        rows = []
        for entry in logs:
            if entry["success"]:
                status = "✅ Success"
            elif entry["reason"] == "locked_out":
                status = "🔒 Blocked (account locked)"
            elif entry["reason"] == "locked_after_max_attempts":
                status = "🔒 Failed (triggered lockout)"
            else:
                status = "❌ Failed"
            rows.append({"Status": status, "Time": entry["created_at"]})

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("🛡 Cyber Safety Tips")
    tips = [
        "Use strong and unique passwords.",
        "Enable Two-Factor Authentication (2FA).",
        "Avoid clicking unknown links.",
        "Verify website URLs before entering credentials.",
        "Keep your browser and operating system updated.",
        "Never download attachments from unknown emails.",
        "Check SSL certificates before making online payments.",
        "Use a password manager for better security.",
    ]
    for tip in tips:
        st.write("✅", tip)

    st.divider()

    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.messages = []
        st.success("Logged out successfully.")
        go_to("Home")
        st.rerun()

    st.caption("CyberShield AI • User Profile")


# ============================================================
# PAGE: ABOUT
# ============================================================

def page_about():
    st.title("ℹ️ About CyberShield-AI")

    st.markdown(
        """
        **CyberShield-AI** is an educational project that demonstrates how multiple
        signals can be combined to assess whether a URL is likely to be a phishing
        attempt:

        1. **Machine learning model** — a TF-IDF + Random Forest classifier trained
           on labeled URL examples (`dataset/phishing.csv`, `models/train_model.py`).
        2. **Heuristic features** — structural red flags like IP-address hosts,
           suspicious keywords, excessive subdomains, and non-HTTPS links
           (`prediction/feature_extractor.py`).
        3. **SSL certificate check** — verifies the target site presents a valid,
           unexpired certificate (`security/ssl_checker.py`).
        4. **WHOIS lookup** — checks domain registration date and registrar, since
           phishing domains are often very recently registered (`security/whois_lookup.py`).
        5. **VirusTotal reputation** (optional) — cross-references community threat
           intelligence (`security/virustotal.py`).

        ### Tech Stack
        - **Frontend:** Streamlit (single-file app with sidebar navigation)
        - **ML:** scikit-learn, pandas
        - **Storage:** SQLite (users + scan history), passwords hashed before storage
        - **Security checks:** Python `ssl`/`socket`, `python-whois`, VirusTotal API v3

        ### Disclaimer
        This tool is built for learning purposes and should **not** be relied on as
        your sole line of defense. Always verify suspicious links through official
        channels, keep software updated, and use multi-factor authentication.
        """
    )


# ============================================================
# ROUTER
# ============================================================

PAGES = {
    "Home": page_home,
    "Login": page_login,
    "Register": page_register,
    "Forgot Password": page_forgot_password,
    "Dashboard": page_dashboard,
    "History": page_history,
    "Profile": page_profile,
    "About": page_about,
}

PAGES[st.session_state.page]()
