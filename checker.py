import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "secure", "verify", "account", "update",
    "bank", "password", "free", "signin"
]

def analyze_url(url):
    score = 0
    reasons = []

    # Add scheme if missing
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # 1. URL length
    if len(url) > 75:
        score += 2
        reasons.append("URL ist sehr lang")

    # 2. Subdomains check
    subdomains = domain.split(".")
    if len(subdomains) > 3:
        score += 2
        reasons.append("Viele Subdomains erkannt")

    # 3. Suspicious words
    full_text = domain + path
    for word in SUSPICIOUS_WORDS:
        if word in full_text.lower():
            score += 2
            reasons.append(f"Verdächtiges Wort gefunden: '{word}'")

    # 4. Numbers in domain (often phishing)
    if re.search(r"\d", domain):
        score += 1
        reasons.append("Zahlen im Domainnamen")

    # 5. HTTPS check
    if parsed.scheme != "https":
        score += 1
        reasons.append("Kein HTTPS")

    # Risk level
    if score <= 2:
        risk = "Low Risk"
    elif score <= 5:
        risk = "Medium Risk"
    else:
        risk = "High Risk"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


def main():
    print("\nPhishing Link Checker")
    print("Type 'exit' to quit\n")

    while True:
        url = input("Enter URL: ")

        if url.lower() == "exit":
            break

        result = analyze_url(url)

        print("\n--- Result ---")
        print("URL:", result["url"])
        print("Score:", result["score"])
        print("Risk:", result["risk"])

        if result["reasons"]:
            print("Reasons:")
            for r in result["reasons"]:
                print(" -", r)

        print("----------------\n")


if __name__ == "__main__":
    main()