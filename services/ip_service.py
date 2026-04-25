import requests

def get_ip_info(domain):
    try:
        ip = requests.get(f"https://dns.google/resolve?name={domain}").json()
        ip_addr = ip['Answer'][0]['data']

        res = requests.get(f"http://ip-api.com/json/{ip_addr}").json()

        return {
            "ip": ip_addr,
            "country": res['country'],
            "isp": res['isp']
        }
    except:
        return {"error": "IP lookup failed"}