from flask import Flask, request, jsonify
from system import get_system_info, analyze_system, check_port
import psutil
import os

app = Flask(__name__)

# ---------------- MALWARE PROCESS CHECK ----------------
def detect_suspicious_processes():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            cpu = proc.info['cpu_percent']
            name = proc.info['name']

            if cpu > 80:
                suspicious.append(f"High CPU Usage: {name}")

            if name and any(x in name.lower() for x in ["temp", "crypt", "miner", "hack"]):
                suspicious.append(f"Suspicious Name: {name}")

        except:
            pass

    return suspicious

# ---------------- NETWORK CONNECTION CHECK ----------------
def check_network_connections():
    connections = psutil.net_connections()
    suspicious_ports = []

    for conn in connections:
        if conn.laddr and conn.laddr.port not in [80, 443, 53]:
            suspicious_ports.append(conn.laddr.port)

    return list(set(suspicious_ports))[:10]

# ---------------- TOP CPU PROCESSES ----------------
def top_processes():
    procs = []

    for p in psutil.process_iter(['name', 'cpu_percent']):
        try:
            procs.append((p.info['name'], p.info['cpu_percent']))
        except:
            pass

    procs.sort(key=lambda x: x[1], reverse=True)
    return procs[:5]

# ---------------- STARTUP CHECK ----------------
def check_startup_items():

    try:
        if os.name == "nt":
            path = os.path.expanduser(
                "~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            )
            return os.listdir(path)

        return ["Startup check not supported on Linux"]

    except:
        return []

# ---------------- CHATBOT LOGIC ----------------
def chatbot_response(message):

    message = message.lower()

    # SYSTEM INFO
    if "system" in message:

        info = get_system_info()

        return f"""
💻 OS: {info['OS']}
🔥 CPU Usage: {info['CPU']}%
🧠 RAM Usage: {info['RAM']}%
"""

    # ANALYZE SYSTEM
    elif "analyze" in message:

        return analyze_system()

    # PORT SCAN
    elif "port" in message:

        ports = [21,22,23,25,53,80,110,139,143,443,445,3389,8080]

        result = []

        for port in ports:
            result.append(f"Port {port}: {check_port(port)}")

        return "\n".join(result)

    # MALWARE SCAN
    elif "malware" in message:

        processes = detect_suspicious_processes()
        ports = check_network_connections()
        startup = check_startup_items()
        top = top_processes()

        response = "\n🦠 MALWARE ANALYSIS\n"

        response += "\n⚠️ Suspicious Processes:\n"

        if processes:
            response += "\n".join(processes)
        else:
            response += "None detected"

        response += "\n\n🌐 Suspicious Ports:\n"

        if ports:
            response += str(ports)
        else:
            response += "None"

        response += "\n\n📂 Startup Items:\n"

        response += "\n".join(startup)

        response += "\n\n🔥 Top CPU Processes:\n"

        for name, cpu in top:
            response += f"\n{name}: {cpu}%"

        return response

    # FULL CHECK
    elif "full" in message:

        info = get_system_info()

        response = f"""
⚙️ FULL SYSTEM CHECK

💻 OS: {info['OS']}
🔥 CPU: {info['CPU']}%
🧠 RAM: {info['RAM']}%

🧠 Analysis:
{analyze_system()}
"""

        response += "\n\n🌐 Common Ports:\n"

        ports = [21,22,23,25,53,80,110,139,143,443]

        for port in ports:
            response += f"\nPort {port}: {check_port(port)}"

        return response

    # ISSUE CHECK
    elif "slow" in message:
        return "⚠️ System may be slow due to high CPU/RAM usage."

    elif "virus" in message:
        return "🛡️ Run antivirus scan immediately."

    else:
        return "🤖 I can help with system analysis, malware scans, full checks, and port scans."

# ---------------- API ----------------
@app.route("/chat", methods=["POST"])
def chat():

    data = request.get_json()

    message = data.get("message", "")

    reply = chatbot_response(message)

    return jsonify({
        "reply": reply
    })

# ---------------- HOME ----------------
@app.route("/")
def home():
    return "Cyber Security Chatbot Running"

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)