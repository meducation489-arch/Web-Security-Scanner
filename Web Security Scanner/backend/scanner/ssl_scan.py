import ssl
import socket
from datetime import datetime

def scan_ssl(domain):
    result = {}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days

        result["SSL Available"] = "Yes"
        result["Issuer"] = dict(x[0] for x in cert["issuer"])
        result["Valid From"] = cert["notBefore"]
        result["Valid Until"] = cert["notAfter"]
        result["Days Remaining"] = days_left

        if days_left < 30:
            result["Risk"] = "High (Certificate expiring soon)"
        else:
            result["Risk"] = "Low"

    except Exception as e:
        result["SSL Available"] = "No"
        result["Error"] = str(e)

    return result
