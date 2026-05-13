from flask import Flask, jsonify, request
from system import *

app = Flask(__name__)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return jsonify({
        "message": "Cyber Security Assistant API Running"
    })

# ---------------- SYSTEM INFO ----------------
@app.route("/system-info")
def system_info():
    return jsonify(get_system_info())

# ---------------- SYSTEM ANALYSIS ----------------
@app.route("/analyze")
def analyze():
    return jsonify({
        "analysis": analyze_system()
    })

# ---------------- SINGLE PORT SCAN ----------------
@app.route("/port/<int:port>")
def port_scan(port):

    return jsonify({
        "port": port,
        "status": check_port(port)
    })

# ---------------- COMMON PORT SCAN ----------------
@app.route("/common-ports")
def common_ports():

    common_ports = [21,22,23,25,53,80,110,139,143,443]

    results = {}

    for port in common_ports:
        results[port] = check_port(port)

    return jsonify(results)

# ---------------- PORT RANGE SCAN ----------------
@app.route("/range-scan")
def range_scan():

    start = int(request.args.get("start", 1))
    end = int(request.args.get("end", 100))

    results = {}

    for port in range(start, end + 1):
        status = check_port(port)

        if "OPEN" in status:
            results[port] = status

    return jsonify(results)

# ---------------- TROUBLESHOOT ----------------
@app.route("/troubleshoot")
def troubleshoot():

    issue = request.args.get("issue", "").lower()

    if "slow" in issue:
        result = "High CPU/RAM usage possible"

    elif "cpu" in issue:
        result = "Close heavy background processes"

    elif "ram" in issue:
        result = "Close unused apps"

    elif "internet" in issue:
        result = "Restart router and run network troubleshooter"

    elif "virus" in issue:
        result = "Run antivirus scan immediately"

    elif "battery" in issue:
        result = "Reduce brightness and background apps"

    else:
        result = "Restart system and check resources"

    return jsonify({
        "issue": issue,
        "solution": result
    })

# ---------------- SUSPICIOUS PROCESSES ----------------
@app.route("/suspicious-processes")
def suspicious_processes():

    return jsonify({
        "processes": detect_suspicious_processes()
    })

# ---------------- NETWORK CONNECTIONS ----------------
@app.route("/network-connections")
def network_connections():

    return jsonify({
        "ports": check_network_connections()
    })

# ---------------- TOP CPU PROCESSES ----------------
@app.route("/top-processes")
def top_cpu():

    return jsonify({
        "top_processes": top_processes()
    })

# ---------------- STARTUP ITEMS ----------------
@app.route("/startup-items")
def startup_items():

    return jsonify({
        "startup_items": check_startup_items()
    })

# ---------------- MALWARE SCAN ----------------
@app.route("/malware-scan")
def malware():

    return jsonify({
        "suspicious_processes": detect_suspicious_processes(),
        "unusual_ports": check_network_connections(),
        "startup_items": check_startup_items(),
        "top_processes": top_processes(),
        "possible_sources": guess_infection_source(),
        "remedies": remedies()
    })

# ---------------- FULL SYSTEM CHECK ----------------
@app.route("/full-check")
def full_check():

    common_ports = [21,22,23,25,53,80,110,139,143,443]
    port_results = {}

    for port in common_ports:
        port_results[port] = check_port(port)

    return jsonify({
        "system_info": get_system_info(),
        "analysis": analyze_system(),
        "ports": port_results,
        "malware": {
            "suspicious_processes": detect_suspicious_processes(),
            "startup_items": check_startup_items(),
            "top_processes": top_processes()
        }
    })

# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)