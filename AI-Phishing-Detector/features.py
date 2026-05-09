import re
import socket
import whois
from urllib.parse import urlparse
import tldextract
import requests

def extract_features(url):
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. Number of dots
    features.append(url.count('.'))
    
    # 3. Presence of @
    features.append(1 if "@" in url else 0)
    
    # 4. Presence of // (redirection)
    features.append(1 if url.rfind("//") > 7 else 0)
    
    # 5. Presence of - in domain
    domain = urlparse(url).netloc
    features.append(1 if "-" in domain else 0)
    
    # 6. IP Address instead of Domain
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    features.append(1 if re.search(ip_pattern, domain) else 0)
    
    # 7. HTTPS Presence
    features.append(1 if url.startswith("https") else 0)
    
    # 8. Suspicious keywords
    keywords = ["login", "verify", "update", "bank", "secure", "account", "signin", "ebayisapi", "webscr"]
    features.append(1 if any(kw in url.lower() for kw in keywords) else 0)
    
    # 9. Number of subdomains
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.')
    features.append(len(subdomains) if subdomains[0] != "" else 0)
    
    # 10. Shortening Service
    shorteners = ["bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl.com", "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "BudURL.com", "ping.fm", "post.ly", "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.co", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "goo.gl", "bitly.com", "cur.lv", "tinyurl.com", "ow.ly", "bit.ly", "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org", "x.co", "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net"]
    features.append(1 if any(s in url for s in shorteners) else 0)

    return features

def get_feature_names():
    return [
        "url_length", "dots_count", "has_at", "has_double_slash", 
        "has_hyphen_domain", "is_ip", "has_https", "has_suspicious_kw",
        "subdomain_count", "is_shortened"
    ]
