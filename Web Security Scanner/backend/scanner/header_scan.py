import requests

def scan_headers(url):
    result = {}
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header in security_headers:
            if header in headers:
                result[header] = "Present"
            else:
                result[header] = "Missing"

    except Exception as e:
        result["error"] = str(e)

    return result
