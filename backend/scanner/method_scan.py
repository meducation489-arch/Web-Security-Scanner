import requests

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]

def scan_methods(url):
    allowed = []

    for method in HTTP_METHODS:
        try:
            r = requests.request(method, url, timeout=5)
            if r.status_code < 405:
                allowed.append(method)
        except:
            pass

    return allowed
