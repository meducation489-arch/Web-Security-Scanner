import requests

def scan_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' OR 'a'='a"
    ]

    vulnerable = False
    tested_payloads = []

    try:
        for payload in payloads:
            test_url = url + "?id=" + payload
            response = requests.get(test_url, timeout=5)

            if "sql" in response.text.lower() or "syntax" in response.text.lower():
                vulnerable = True
                tested_payloads.append(payload)

    except Exception as e:
        return {"error": str(e)}

    return {
        "SQL Injection Vulnerable": "Yes" if vulnerable else "No",
        "payloads_tested": tested_payloads if vulnerable else "None"
    }
