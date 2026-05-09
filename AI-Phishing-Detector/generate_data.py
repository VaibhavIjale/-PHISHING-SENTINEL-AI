import pandas as pd
import random
from features import extract_features, get_feature_names

def generate_synthetic_data(n=1000):
    safe_urls = [
        "https://www.google.com", "https://www.github.com", "https://www.amazon.com",
        "https://www.facebook.com", "https://www.apple.com", "https://www.microsoft.com",
        "https://www.netflix.com", "https://www.wikipedia.org", "https://www.linkedin.com",
        "https://www.twitter.com", "https://www.instagram.com", "https://www.reddit.com",
        "https://www.youtube.com", "https://www.medium.com", "https://www.stackoverflow.com"
    ]
    
    phishing_urls = [
        "http://login-verify-account.com", "http://secure-bank-update.xyz", "http://paypal-verification.net",
        "http://amaz0n-security-check.com", "http://bit.ly/fake-login", "http://192.168.1.1/login.php",
        "http://signin.ebayisapi.dll.verification-update.com", "http://account-update-verify.top",
        "http://verify-your-identity.info", "http://bank-of-america-secure.org"
    ]
    
    data = []
    
    # Generate Safe Samples
    for _ in range(n // 2):
        base_url = random.choice(safe_urls)
        # Add random paths to make it more realistic
        url = base_url + "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 20)))
        features = extract_features(url)
        data.append(features + [0]) # 0 = Safe
        
    # Generate Phishing Samples
    for _ in range(n // 2):
        base_url = random.choice(phishing_urls)
        url = base_url + "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 20)))
        features = extract_features(url)
        data.append(features + [1]) # 1 = Phishing
        
    df = pd.DataFrame(data, columns=get_feature_names() + ["label"])
    df.to_csv("phishing.csv", index=False)
    print("Synthetic dataset 'phishing.csv' generated successfully.")

if __name__ == "__main__":
    generate_synthetic_data()
