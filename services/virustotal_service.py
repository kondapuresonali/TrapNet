import requests

API_KEY = "YOUR_API_KEY"

def check_virustotal(url):
    headers = {"x-apikey": API_KEY}

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    return response.json()