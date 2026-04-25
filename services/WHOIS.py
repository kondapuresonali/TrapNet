import whois
from datetime import datetime

def get_domain_info(domain):
    from datetime import datetime

    # 🥇 TRY API FIRST
    try:
        import requests

        url = f"https://api.api-ninjas.com/v1/whois?domain={domain}"
        headers = {"X-Api-Key": "YOUR_API_KEY"}

        res = requests.get(url, headers=headers, timeout=5)

        if res.status_code == 200:
            data = res.json()
            print("API WHOIS:", data)

            creation_date = data.get("creation_date")

            if creation_date:
                creation_date = creation_date.split("T")[0]
                dt = datetime.strptime(creation_date, "%Y-%m-%d")
                age_days = (datetime.now() - dt).days
            else:
                age_days = None

            return {
                "age_days": age_days,
                "registrar": data.get("registrar", "Unknown")
            }

    except Exception as e:
        print("API WHOIS Failed:", e)

    # 🥈 FALLBACK: python-whois
    try:
        import whois

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
        else:
            age_days = None

        return {
            "age_days": age_days,
            "registrar": w.registrar or "Unknown"
        }

    except Exception as e:
        print("LOCAL WHOIS Failed:", e)

    # 🥉 FINAL FALLBACK
    return {
        "age_days": None,
        "registrar": "Protected / Hidden"
    }