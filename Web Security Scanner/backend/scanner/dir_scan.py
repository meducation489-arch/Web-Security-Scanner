import requests

COMMON_DIRS = [
    "admin",
    "login",
    "dashboard",
    "uploads",
    "config",
    "backup",
    "test"
]

def scan_directories(url):
    found = []

    for d in COMMON_DIRS:
        test_url = url.rstrip("/") + "/" + d
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code in [200, 301, 302]:
                found.append(test_url)
        except:
            pass

    return found
