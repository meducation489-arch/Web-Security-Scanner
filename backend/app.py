from flask import Flask, jsonify, request
from flask_cors import CORS
from scanner.port_scan import scan_ports
from scanner.header_scan import scan_headers
from scanner.ssl_scan import scan_ssl
from scanner.cookie_scan import scan_cookies
from scanner.sql_scan import scan_sql_injection
from scanner.xss_scan import scan_xss
from scanner.dir_scan import scan_directories
from scanner.method_scan import scan_methods
import socket

app = Flask(__name__)
CORS(app)   # 🔥 THIS LINE FIXES FRONTEND FETCH

# ---------- HOME ----------
@app.route("/")
def home():
    return jsonify({
        "status": "OK",
        "message": "Web Security Scanner Backend Running"
    })

# ---------- PORT SCAN ----------
@app.route("/scan/ports")
def port_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})

    target = url.replace("https://", "").replace("http://", "").split("/")[0]
    ip = socket.gethostbyname(target)
    ports = scan_ports(ip)

    return jsonify({
        "target": target,
        "open_ports": ports
    })

# ---------- HEADERS ----------
@app.route("/scan/headers")
def header_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "security_headers": scan_headers(url)
    })

# ---------- SSL ----------
@app.route("/scan/ssl")
def ssl_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    return jsonify({
        "target": domain,
        "ssl_details": scan_ssl(domain)
    })

# ---------- COOKIES ----------
@app.route("/scan/cookies")
def cookie_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "cookies": scan_cookies(url)
    })

# ---------- SQL ----------
@app.route("/scan/sql")
def sql_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "sql_scan": scan_sql_injection(url)
    })

# ---------- XSS ----------
@app.route("/scan/xss")
def xss_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "xss_scan": scan_xss(url)
    })

# ---------- DIRECTORY ----------
@app.route("/scan/dir")
def dir_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "directories_found": scan_directories(url)
    })

# ---------- METHODS ----------
@app.route("/scan/methods")
def method_scan():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL is required"})
    if not url.startswith("http"):
        url = "http://" + url

    return jsonify({
        "target": url,
        "allowed_methods": scan_methods(url)
    })

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
