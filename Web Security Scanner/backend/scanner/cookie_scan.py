import requests

def scan_cookies(url):
    result = []

    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies

        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in str(cookie._rest),
                "risk": ""
            }

            if not cookie.secure or "HttpOnly" not in str(cookie._rest):
                cookie_info["risk"] = "High"
            else:
                cookie_info["risk"] = "Low"

            result.append(cookie_info)

    except Exception as e:
        result.append({"error": str(e)})

    return result
