import os
import subprocess
from collections import Counter
from flask import Flask, render_template, request

app = Flask(__name__)

APP_NAME = "Firewall Orchestrator"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def run_tshark(file_path, display_filter):
    command = [
        "tshark",
        "-r", file_path,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-E", "separator=,"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20
        )
        return result.stdout.strip().splitlines()
    except Exception as error:
        return [f"ERROR,{str(error)},,"]


def analyze_pcap(file_path):
    ssh_22_rows = run_tshark(file_path, "tcp.port == 22")
    ssh_2222_rows = run_tshark(file_path, "tcp.port == 2222")
    tcp_rows = run_tshark(file_path, "tcp")

    ip_counter = Counter()
    conversations = []

    for row in tcp_rows[:100]:
        parts = row.split(",")
        if len(parts) >= 4:
            src_ip, dst_ip, src_port, dst_port = parts[:4]

            if src_ip:
                ip_counter[src_ip] += 1
            if dst_ip:
                ip_counter[dst_ip] += 1

            conversations.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            })

    detected_22 = len([row for row in ssh_22_rows if row.strip()]) > 0
    detected_2222 = len([row for row in ssh_2222_rows if row.strip()]) > 0

    if detected_22 and not detected_2222:
        risk_level = "High"
        status = "Before Hardening"
        finding = "SSH traffic detected on default port 22."
        recommendation = "Move SSH to a non-default port such as 2222, disable root login, use key-based authentication, and restrict firewall rules."
    elif detected_2222 and not detected_22:
        risk_level = "Low"
        status = "After Hardening"
        finding = "SSH traffic detected on hardened non-default port 2222."
        recommendation = "Maintain firewall allow rule only for the hardened SSH port and continue monitoring logs."
    elif detected_22 and detected_2222:
        risk_level = "Medium"
        status = "Mixed Capture"
        finding = "Both default SSH port 22 and hardened SSH port 2222 were detected."
        recommendation = "Verify that port 22 is fully disabled or blocked after migration to port 2222."
    else:
        risk_level = "Informational"
        status = "No SSH Evidence"
        finding = "No SSH traffic was detected on port 22 or 2222."
        recommendation = "Capture SSH testing traffic again or verify whether the capture file contains the correct interface traffic."

    top_ips = ip_counter.most_common(5)

    return {
        "status": status,
        "risk_level": risk_level,
        "finding": finding,
        "recommendation": recommendation,
        "detected_22": detected_22,
        "detected_2222": detected_2222,
        "ssh_22_count": len(ssh_22_rows),
        "ssh_2222_count": len(ssh_2222_rows),
        "top_ips": top_ips,
        "conversations": conversations[:20],
    }


@app.route("/")
def dashboard():
    summary = {
        "app_name": APP_NAME,
        "security_score": 45,
        "firewall_status": "Not Checked",
        "ssh_status": "Not Checked",
        "wireshark_status": "Ready for analysis",
    }
    return render_template("dashboard.html", summary=summary)


@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    analysis = None
    error = None
    filename = None

    if request.method == "POST":
        if "pcap_file" not in request.files:
            error = "No file part found."
        else:
            file = request.files["pcap_file"]

            if file.filename == "":
                error = "No file selected."
            elif file and allowed_file(file.filename):
                filename = file.filename
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(save_path)
                analysis = analyze_pcap(save_path)
            else:
                error = "Invalid file type. Please upload .pcap or .pcapng file."

    return render_template(
        "analyzer.html",
        analysis=analysis,
        error=error,
        filename=filename
    )


@app.route("/controller")
def controller():
    return render_template("controller.html")


@app.route("/validator")
def validator():
    return render_template("validator.html")


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
