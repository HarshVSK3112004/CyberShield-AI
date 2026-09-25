"""
A curated allowlist of well-known, globally trusted domains.

Why this exists
----------------
The ML model is trained on character n-grams of the URL string, including
many real historical phishing URLs that embed a brand name as a spoofed
substring (e.g. "paypal.com.resolvesecure.us" — a real phishing attempt
present in the training data, correctly labeled malicious). This teaches
the model that strings like "paypal.com" are associated with phishing,
which is often true — but a pure character-based model has no built-in
concept of "brand name as the actual registered domain" vs. "brand name
as a spoofed substring elsewhere in a longer domain", so it can also flag
the real paypal.com itself.

Testing also showed the model's "legitimate" training examples skew
heavily toward long-tail hosted URLs with paths (blogspot.com,
netsolhost.com subdomains, etc.), so it under-generalizes to simple,
direct "https://www.brand.com" patterns even for well-known, entirely
unrelated brands (e.g. bbc.com, nytimes.com) — not just payment-related
ones. Retraining with several hundred additional real top-ranked domains
helped, but did not fully close this gap on its own.

This allowlist is the standard mitigation real systems use for exactly
this kind of gap: if the URL's actual registered domain (via tldextract,
not just a substring match) exactly matches a known-trusted entry, the
verdict is forced to Legitimate regardless of what the ML model alone
would have said. The raw ML probability is still reported for
transparency — see prediction/predictor.py.

Provenance
----------
The bulk of this list (452 domains) is real ranked data: the top ~500
domains by domain authority from Kikobeats/top-sites
(github.com/Kikobeats/top-sites), normalized to their registered domain
(eTLD+1) via tldextract. A handful of additional entries were added by
hand for domains this project's own testing specifically exercises
(this project's own Streamlit Cloud hosting domain).

This is intentionally a large-but-finite, sourced list rather than a
claim of exhaustive coverage — a domain not on this list simply falls
through to the ML model + heuristics alone, which is an honest,
documented limitation (see the project report).
"""

TRUSTED_DOMAINS = {
    "20minutos.es", "3ds.com", "4shared.com", "abc.com", "abc.es", "abc.net.au",
    "abcnews.com", "about.com", "aboutads.info", "abril.com.br", "academia.edu", "addthis.com",
    "addtoany.com", "adobe.com", "afternic.com", "akamaihd.net", "alibaba.com", "alicdn.com",
    "aliexpress.com", "amazon.ca", "amazon.co.jp", "amazon.co.uk", "amazon.com", "amazon.de",
    "amazon.es", "amazon.fr", "amazon.it", "amazonaws.com", "ameblo.jp", "amzn.to",
    "android.com", "answers.com", "aol.com", "ap.org", "apache.org", "apnews.com",
    "apple.com", "archive.org", "arxiv.org", "as.com", "asahi.com", "automattic.com",
    "bandcamp.com", "bbc.co.uk", "bbc.com", "behance.net", "berkeley.edu", "biblegateway.com",
    "bild.de", "billboard.com", "bing.com", "bit.ly", "blog.google", "blogger.com",
    "bloglovin.com", "blogspot.com", "bloomberg.com", "bmj.com", "booking.com", "boston.com",
    "box.com", "brandbucket.com", "britannica.com", "businessinsider.com", "businesswire.com", "buydomains.com",
    "buzzfeed.com", "ca.gov", "calameo.com", "cambridge.org", "canva.com", "cbc.ca",
    "cbsnews.com", "cdc.gov", "change.org", "clarin.com", "clickbank.net", "cloudflare.com",
    "cnbc.com", "cnet.com", "cnil.fr", "cnn.com", "cornell.edu", "correios.com.br",
    "cpanel.com", "cpanel.net", "creativecommons.org", "cutt.ly", "dailymail.co.uk", "dailymail.com",
    "dailymotion.com", "dailystar.co.uk", "dan.com", "deezer.com", "dell.com", "depositfiles.com",
    "detik.com", "discord.com", "discord.gg", "disney.com", "disqus.com", "doi.org",
    "domainmarket.com", "doubleclick.net", "dreamstime.com", "dribbble.com", "dropbox.com", "dropcatch.com",
    "dw.com", "ebay.com", "ebay.de", "economist.com", "elmundo.es", "elpais.com",
    "enable-javascript.com", "engadget.com", "estadao.com.br", "euronews.com", "europa.eu", "eventbrite.com",
    "evernote.com", "example.com", "expireddomains.com", "express.co.uk", "facebook.com", "fandom.com",
    "fb.com", "fb.me", "feedburner.com", "fifa.com", "firefox.com", "flickr.com",
    "forbes.com", "forms.gle", "foxnews.com", "francetvinfo.fr", "frontiersin.org", "ft.com",
    "ftc.gov", "geo.io", "ggpht.com", "github.com", "gizmodo.com", "globo.com",
    "gmail.com", "go.com", "goal.com", "godaddy.com", "gofundme.com", "goo.gl",
    "goodreads.com", "google.co.jp", "google.co.uk", "google.com", "google.com.br", "google.de",
    "google.es", "google.fr", "google.it", "google.pl", "google.ru", "googleapis.com",
    "googleblog.com", "googleusercontent.com", "gravatar.com", "greenpeace.org", "gstatic.com", "guardian.co.uk",
    "harvard.edu", "hatena.ne.jp", "hbr.org", "hilton.com", "history.com", "hollywoodreporter.com",
    "home.pl", "hostinger.com", "hotmart.com", "house.gov", "hp.com", "huawei.com",
    "hubspot.com", "huffingtonpost.com", "huffpost.com", "hugedomains.com", "ibm.com", "icann.org",
    "ietf.org", "ig.com.br", "ign.com", "ikea.com", "imageshack.com", "imageshack.us",
    "imdb.com", "imgur.com", "impress.co.jp", "independent.co.uk", "indiatimes.com", "instagram.com",
    "instructables.com", "investopedia.com", "iso.org", "issuu.com", "istockphoto.com", "it.com",
    "jimdofree.com", "joomla.org", "kickstarter.com", "kompas.com", "last.fm", "latimes.com",
    "lavanguardia.com", "lefigaro.fr", "legifrance.gouv.fr", "lemonde.fr", "leparisien.fr", "lg.com",
    "lin.ee", "line.me", "linkedin.com", "linktr.ee", "list-manage.com", "live.com",
    "liveinternet.ru", "livejournal.com", "loc.gov", "lycos.com", "m.me", "mail.ru",
    "marca.com", "marketingplatform.google", "mashable.com", "mayoclinic.org", "mdpi.com", "mediafire.com",
    "medicalnewstoday.com", "medium.com", "mega.nz", "messenger.com", "metro.co.uk", "microsoft.com",
    "mirror.co.uk", "mit.edu", "mozilla.com", "mozilla.org", "msn.com", "myspace.com",
    "mystrikingly.com", "namebright.com", "namecheap.com", "nasa.gov", "nationalgeographic.com", "nature.com",
    "naver.com", "nba.com", "nbcnews.com", "ndtv.com", "netflix.com", "netlify.app",
    "netvibes.com", "networkadvertising.org", "news.com.au", "newsweek.com", "newyorker.com", "nfl.com",
    "nginx.com", "nginx.org", "nhk.or.jp", "nicovideo.jp", "nicsell.com", "nih.gov",
    "nintendo.com", "npr.org", "nps.gov", "nydailynews.com", "nymag.com", "nypost.com",
    "nytimes.com", "office.com", "offset.com", "ok.ru", "opera.com", "oracle.com",
    "ouest-france.fr", "oup.com", "outlook.com", "ovh.com", "ovhcloud.com", "ox.ac.uk",
    "paypal.com", "pbs.org", "people.com", "perfectdomain.com", "pexels.com", "photobucket.com",
    "php.net", "pinterest.com", "pixabay.com", "planalto.gov.br", "playstation.com", "plesk.com",
    "plos.org", "prtimes.jp", "psychologytoday.com", "qq.com", "quora.com", "radiofrance.fr",
    "rakuten.co.jp", "rambler.ru", "rapidshare.com", "rbc.ru", "redbull.com", "reddit.com",
    "reg.ru", "repubblica.it", "researchgate.net", "reuters.com", "rollingstone.com", "rt.com",
    "rtve.es", "safety.google", "sagepub.com", "sakura.ne.jp", "samsung.com", "sapo.pt",
    "sciencedaily.com", "sciencedirect.com", "scmp.com", "scribd.com", "secureserver.net", "sedo.com",
    "sedoparking.com", "sendspace.com", "service-public.fr", "sfgate.com", "shopify.com", "shutterstock.com",
    "sky.com", "skype.com", "slideshare.net", "soundcloud.com", "sourceforge.io", "spiegel.de",
    "spotify.com", "springer.com", "sputniknews.com", "ssl-images-amazon.com", "stackoverflow.com", "standard.co.uk",
    "stanford.edu", "statista.com", "steampowered.com", "stores.jp", "sueddeutsche.de", "surveymonkey.com",
    "t-online.de", "t.co", "t.me", "target.com", "taringa.net", "techcrunch.com",
    "ted.com", "telegra.ph", "telegram.me", "telegram.org", "telegraph.co.uk", "terra.com.br",
    "theatlantic.com", "thedailybeast.com", "theguardian.com", "themeforest.net", "thenai.org", "thesun.co.uk",
    "thetimes.co.uk", "thetimes.com", "theverge.com", "thoughtco.com", "tiktok.com", "time.com",
    "timeweb.ru", "tinyurl.com", "tmz.com", "tripadvisor.com", "trustpilot.com", "twitch.tv",
    "twitter.com", "typepad.com", "ucla.edu", "ucoz.ru", "udemy.com", "un.org",
    "unesco.org", "unicef.org", "unsplash.com", "uol.com.br", "upenn.edu", "usatoday.com",
    "usda.gov", "usgs.gov", "usnews.com", "utexas.edu", "variety.com", "vercel.app",
    "vimeo.com", "vistaprint.com", "vk.com", "vkontakte.ru", "vox.com", "w3.org",
    "wa.me", "wallpapers.com", "walmart.com", "washingtonpost.com", "webmd.com", "weebly.com",
    "weforum.org", "weibo.com", "welt.de", "whatsapp.com", "who.int", "wikia.com",
    "wikihow.com", "wikimedia.org", "wikipedia.org", "wiktionary.org", "wiley.com", "wired.com",
    "wix.com", "wordpress.com", "wordpress.org", "wp.com", "wsj.com", "www.gov.br",
    "www.gov.uk", "x.com", "xbox.com", "xing.com", "yadi.sk", "yahoo.co.jp",
    "yahoo.com", "yandex.com", "yandex.ru", "yelp.com", "youronlinechoices.com", "youtu.be",
    "youtube.com", "ytimg.com", "zdf.de", "zdnet.com", "zendesk.com", "ziddu.com",
    "zippyshare.com", "zoom.us",
    # Hand-added: this project's own hosting infrastructure
    "streamlit.app", "streamlit.io",
}


def is_trusted_domain(registered_domain: str) -> bool:
    """Check whether a registered domain (e.g. 'paypal.com', not a
    subdomain or full URL) is on the trusted allowlist."""
    if not registered_domain:
        return False
    return registered_domain.lower() in TRUSTED_DOMAINS
