import ssl, socket
from datetime import datetime


def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()  D:

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

        return {"expiry": expiry.strftime("%Y-%m-%d")}

    except Exception as e:
        print("SSL Error:", e)
        return {}
