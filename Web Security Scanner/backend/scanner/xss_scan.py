import requests

def scan_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ]

    vulnerable = False
    detected_payloads = []

    try:
        for payload in payloads:
            test_url = url + "?q=" + payload
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                vulnerable = True
                detected_payloads.append(payload)

    except Exception as e:
        return {"error": str(e)}

    return {
        "XSS Vulnerable": "Yes" if vulnerable else "No",
        "payloads_detected": detected_payloads if vulnerable else "None"
    }
