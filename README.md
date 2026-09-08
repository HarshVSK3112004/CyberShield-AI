# CyberShield-AI

CyberShield-AI is a Streamlit web app that helps users check whether a URL is likely
a phishing site. It combines a machine learning classifier (TF-IDF + Random Forest)
with rule-based URL heuristics, live SSL certificate checks, WHOIS domain lookups,
and an optional VirusTotal reputation check. It also includes user accounts, a scan
history log, and a simple cybersecurity FAQ chatbot.

## Features

- 🔐 **User accounts** — register/login with hashed passwords (SQLite)
- 🕵️ **Phishing URL detection** — ML model + heuristic feature analysis
- 🔒 **SSL certificate checker** — validity, issuer, expiry
- 🌐 **WHOIS lookup** — domain age, registrar, expiration
- 🦠 **VirusTotal integration** — community reputation score (needs free API key)
- 📊 **Dashboard** — run checks and see a combined risk verdict
- 📜 **Scan history** — every check is logged per user
- 🤖 **Chatbot** — answers common phishing/cybersecurity questions
- 👤 **Profile page** — view account info and stats

## Project Structure

```
CyberShield-AI/
├── app.py                  # Single-file entry point: all pages + sidebar router (Streamlit)
├── chatbot/                # FAQ chatbot (rule-based, or Gemini-backed if configured)
├── database/                # SQLite setup + user/history queries
├── dataset/                  # Training data (phishing.csv)
├── models/                   # Trained model + vectorizer (.pkl) + training script
├── prediction/                # Feature extraction + prediction logic
├── security/                  # SSL / WHOIS / VirusTotal checks
├── utils/                     # Shared helpers
└── requirements.txt
```

## Setup

1. **Create and activate a virtual environment** (in the project root, using VS Code's terminal):

   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Train the model yourself** — a starter model is already included in
   `models/`, but you can retrain it on the sample dataset (or your own, larger one):

   ```bash
   python models/train_model.py
   ```

4. **(Optional) Add a VirusTotal API key** — create a `.env` file in the project root:

   ```
   VIRUSTOTAL_API_KEY=your_key_here
   ```

   Get a free key at https://www.virustotal.com/gui/join-us. Without a key, the app
   will simply skip the VirusTotal check and rely on the ML model + SSL/WHOIS checks.

5. **(Optional) Enable the AI-powered chatbot (Gemini)** — add to the same `.env` file:

   ```
   GEMINI_API_KEY=your_key_here
   GEMINI_MODEL=gemini-2.0-flash   # optional, this is the default
   ```

   Get a free key at https://aistudio.google.com/apikey. Without a key, the chatbot
   falls back to the built-in rule-based FAQ matcher (chatbot/intents.json) — same
   graceful-degradation pattern as the VirusTotal check above.

6. **Run the app:**

   ```bash
   streamlit run app.py
   ```

   Navigation between Home / Login / Register / Dashboard / History / Profile / About
   is handled by a sidebar radio inside `app.py` itself (no separate `pages/` folder).

## Notes

- `dataset/phishing.csv` ships with a small **synthetic sample** so the project runs
  out of the box. For real-world accuracy, replace it with a larger labeled dataset
  (e.g. from Kaggle/PhishTank) and rerun `models/train_model.py`.
- `database/database.db` is created automatically on first run.
- This project is for educational purposes — always verify suspicious links through
  multiple sources before trusting any automated verdict.