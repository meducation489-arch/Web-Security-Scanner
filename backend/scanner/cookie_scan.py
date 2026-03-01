import requests
from datetime import datetime


def analyze_risk(secure, httponly, samesite, expires):
    risk = "Low"
    issues = []

    if not secure:
        issues.append("Not Secure (transmitted over HTTP)")
        risk = "High"

    if not httponly:
        issues.append("Missing HttpOnly (accessible via JS)")
        risk = "High"

    if not samesite:
        issues.append("Missing SameSite attribute")
        if risk != "High":
            risk = "Medium"

    if expires:
        try:
            exp_date = datetime.strptime(expires, "%a, %d-%b-%Y %H:%M:%S %Z")
            if exp_date.year > datetime.now().year + 5:
                issues.append("Very long expiry time")
                if risk == "Low":
                    risk = "Medium"
        except:
            pass

    if not secure and not httponly:
        risk = "Critical"

    return risk, issues


def scan_cookies(url):
    results = []
    security_score = 100

    try:
        response = requests.get(url, timeout=8)
        cookies = response.cookies

        for cookie in cookies:
            secure = cookie.secure
            httponly = "HttpOnly" in str(cookie._rest)
            samesite = cookie._rest.get("SameSite", None)
            expires = cookie.expires

            risk, issues = analyze_risk(
                secure,
                httponly,
                samesite,
                None
            )

            # Deduct score
            if risk == "Critical":
                security_score -= 20
            elif risk == "High":
                security_score -= 10
            elif risk == "Medium":
                security_score -= 5

            results.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite if samesite else "Not Set",
                "risk": risk,
                "issues": issues
            })

    except requests.exceptions.RequestException as e:
        return {"error": f"Connection error: {str(e)}"}

    except Exception as e:
        return {"error": str(e)}

    return {
        "security_score": max(security_score, 0),
        "total_cookies": len(results),
        "cookies": results
    }