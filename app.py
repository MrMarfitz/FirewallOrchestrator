import os
import re
import json
import platform
import subprocess
import pandas as pd
from collections import Counter
from flask import Flask, render_template, request

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
EVIDENCE_FOLDER = "evidence"
LATEST_FILE = os.path.join(EVIDENCE_FOLDER, "latest_analysis.json")
COMPARE_FILE = os.path.join(EVIDENCE_FOLDER, "compare_analysis.json")
ALLOWED_EXTENSIONS = {"csv"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_json(path, data):
    os.makedirs(EVIDENCE_FOLDER, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_json(path):
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_latest_analysis(data):
    save_json(LATEST_FILE, data)


def load_latest_analysis():
    return load_json(LATEST_FILE)


def detect_port(info_text, port):
    patterns = [
        rf"→\s*{port}\b",
        rf"->\s*{port}\b",
        rf"\b{port}\s*→",
        rf"\b{port}\s*->",
        rf":{port}\b",
        rf"port\s*{port}\b",
        rf"\b{port}\s+\[",
    ]

    return any(re.search(pattern, info_text, re.IGNORECASE) for pattern in patterns)


def analyze_csv(file_path, filename):
    df = pd.read_csv(file_path)
    columns = list(df.columns)

    source_col = "Source" if "Source" in columns else None
    destination_col = "Destination" if "Destination" in columns else None
    protocol_col = "Protocol" if "Protocol" in columns else None
    info_col = "Info" if "Info" in columns else None

    if not info_col:
        return {
            "filename": filename,
            "valid": False,
            "status": "Invalid CSV",
            "risk_level": "High",
            "score": 0,
            "finding": "CSV tidak memiliki kolom Info dari Wireshark.",
            "recommendation": "Export ulang CSV dari Wireshark dengan kolom No., Time, Source, Destination, Protocol, Length, dan Info.",
            "total_packets": int(len(df)),
            "detected_22": False,
            "detected_2222": False,
            "ssh_packets": 0,
            "top_protocols": [],
            "top_ips": [],
            "rows": [],
        }

    df["Info"] = df[info_col].astype(str)
    all_info = " ".join(df["Info"].tolist())

    detected_22 = detect_port(all_info, "22")
    detected_2222 = detect_port(all_info, "2222")

    if protocol_col:
        ssh_rows = df[df[protocol_col].astype(str).str.contains("SSH", case=False, na=False)]
        top_protocols = df[protocol_col].astype(str).value_counts().head(5)
    else:
        ssh_rows = df[df["Info"].str.contains("SSH", case=False, na=False)]
        top_protocols = pd.Series(dtype=int)

    ip_counter = Counter()

    if source_col:
        ip_counter.update(df[source_col].dropna().astype(str).tolist())

    if destination_col:
        ip_counter.update(df[destination_col].dropna().astype(str).tolist())

    if detected_22 and not detected_2222:
        status = "Before Hardening"
        risk_level = "High"
        score = 35
        finding = "SSH masih menggunakan port default 22. Ini berarti akses remote server masih mudah ditebak dan perlu hardening."
        recommendation = "Block port 22, pindahkan SSH ke port 2222, gunakan SSH key, dan aktifkan firewall default deny."

    elif detected_2222 and not detected_22:
        status = "After Hardening"
        risk_level = "Low"
        score = 85
        finding = "SSH sudah terdeteksi pada port 2222. Ini menunjukkan akses remote sudah lebih aman dari konfigurasi default."
        recommendation = "Pertahankan port 2222, pastikan port 22 tetap diblokir, dan review log login secara berkala."

    elif detected_22 and detected_2222:
        status = "Mixed Evidence"
        risk_level = "Medium"
        score = 60
        finding = "CSV menunjukkan port 22 dan 2222 sama-sama muncul. Kemungkinan data berisi kondisi sebelum dan sesudah hardening."
        recommendation = "Pisahkan capture before dan after, lalu pastikan port 22 benar-benar tidak muncul setelah hardening."

    else:
        status = "No SSH Evidence"
        risk_level = "Informational"
        score = 50
        finding = "CSV tidak menunjukkan bukti SSH port 22 atau 2222."
        recommendation = "Capture ulang traffic saat Windows mencoba SSH ke Kali Linux server."

    preview_cols = [
        c for c in ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        if c in columns
    ]

    rows = df[preview_cols].head(12).fillna("").to_dict(orient="records")

    return {
        "filename": filename,
        "valid": True,
        "status": status,
        "risk_level": risk_level,
        "score": score,
        "finding": finding,
        "recommendation": recommendation,
        "total_packets": int(len(df)),
        "detected_22": bool(detected_22),
        "detected_2222": bool(detected_2222),
        "ssh_packets": int(len(ssh_rows)),
        "top_protocols": [[str(k), int(v)] for k, v in top_protocols.items()],
        "top_ips": [[str(k), int(v)] for k, v in ip_counter.most_common(5)],
        "rows": rows,
    }


def run_local_command(command):
    if platform.system().lower() == "windows":
        return {
            "success": False,
            "output": "Live Kali Control hanya jalan saat app dijalankan langsung di Kali Linux. Di Windows, gunakan fitur Analyzer, Compare, dan Report."
        }

    allowed_commands = [
        "hostname -I",
        "/usr/sbin/ufw status verbose",
        "/usr/sbin/ufw deny 22/tcp",
        "/usr/sbin/ufw allow 2222/tcp",
        "/usr/sbin/ufw default deny incoming",
        "/usr/sbin/ufw default allow outgoing",
        "/usr/sbin/ufw --force enable",
        "/usr/bin/ss -tulnp",
    ]

    if command not in allowed_commands:
        return {
            "success": False,
            "output": "Command not allowed."
        }

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=20
        )

        output = result.stdout if result.stdout else result.stderr

        return {
            "success": result.returncode == 0,
            "output": output
        }

    except Exception as e:
        return {
            "success": False,
            "output": str(e)
        }


@app.route("/")
def dashboard():
    latest = load_latest_analysis()

    if not latest:
        summary = {
            "has_data": False,
            "security_score": "-",
            "risk_level": "No Data",
            "status": "No Evidence Uploaded",
            "finding": "Belum ada data. Upload CSV Wireshark dulu di menu Analyzer.",
        }
    else:
        summary = {
            "has_data": True,
            "security_score": latest["score"],
            "risk_level": latest["risk_level"],
            "status": latest["status"],
            "finding": latest["finding"],
        }

    return render_template("dashboard.html", summary=summary)


@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    analysis = None
    error = None

    if request.method == "POST":
        file = request.files.get("csv_file")

        if not file or file.filename == "":
            error = "Pilih file CSV dulu."

        elif not allowed_file(file.filename):
            error = "Format salah. Upload file Wireshark .csv."

        else:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            filename = file.filename
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            analysis = analyze_csv(save_path, filename)
            save_latest_analysis(analysis)

    return render_template(
        "analyzer.html",
        analysis=analysis,
        error=error,
        latest=load_latest_analysis()
    )


@app.route("/compare", methods=["GET", "POST"])
def compare():
    before_analysis = None
    after_analysis = None
    comparison = None
    error = None

    if request.method == "POST":
        before_file = request.files.get("before_csv")
        after_file = request.files.get("after_csv")

        if not before_file or before_file.filename == "":
            error = "Upload Before Hardening CSV dulu."

        elif not after_file or after_file.filename == "":
            error = "Upload After Hardening CSV dulu."

        elif not allowed_file(before_file.filename) or not allowed_file(after_file.filename):
            error = "Format salah. Upload file .csv dari Wireshark."

        else:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            os.makedirs(EVIDENCE_FOLDER, exist_ok=True)

            before_path = os.path.join(UPLOAD_FOLDER, "before_" + before_file.filename)
            after_path = os.path.join(UPLOAD_FOLDER, "after_" + after_file.filename)

            before_file.save(before_path)
            after_file.save(after_path)

            before_analysis = analyze_csv(before_path, before_file.filename)
            after_analysis = analyze_csv(after_path, after_file.filename)

            score_diff = after_analysis["score"] - before_analysis["score"]

            if before_analysis["detected_22"] and after_analysis["detected_2222"] and not after_analysis["detected_22"]:
                result = "Hardening berhasil. Bukti before menunjukkan port 22, sedangkan bukti after menunjukkan SSH berpindah ke port 2222."
                improvement = "Risk reduced"

            elif before_analysis["detected_22"] and after_analysis["detected_22"]:
                result = "Hardening belum berhasil. Port 22 masih terdeteksi pada file after."
                improvement = "No clear improvement"

            elif after_analysis["detected_2222"]:
                result = "After CSV menunjukkan SSH hardened port 2222. Kondisi lebih aman dibanding konfigurasi default."
                improvement = "Improved"

            else:
                result = "Belum ada bukti SSH yang cukup pada file after. Perlu capture ulang saat testing SSH."
                improvement = "Need more evidence"

            comparison = {
                "before_score": before_analysis["score"],
                "after_score": after_analysis["score"],
                "score_diff": score_diff,
                "before_status": before_analysis["status"],
                "after_status": after_analysis["status"],
                "before_risk": before_analysis["risk_level"],
                "after_risk": after_analysis["risk_level"],
                "before_port22": before_analysis["detected_22"],
                "after_port22": after_analysis["detected_22"],
                "before_port2222": before_analysis["detected_2222"],
                "after_port2222": after_analysis["detected_2222"],
                "result": result,
                "improvement": improvement,
            }

            save_json(COMPARE_FILE, {
                "before": before_analysis,
                "after": after_analysis,
                "comparison": comparison
            })

    return render_template(
        "compare.html",
        before_analysis=before_analysis,
        after_analysis=after_analysis,
        comparison=comparison,
        error=error
    )


@app.route("/controller")
def controller():
    latest = load_latest_analysis()

    if not latest:
        return render_template(
            "controller.html",
            latest=None,
            message="Belum ada data. Upload CSV Wireshark dulu di menu Analyzer.",
            rules=[],
            commands=[],
            suspicious_ips=[],
            ssh_result=None,
            executed_command=None
        )

    suspicious_ips = latest.get("top_ips", [])[:5]

    commands = [
        {
            "title": "Check Kali IP",
            "desc": "Melihat IP server Kali.",
            "command": "hostname -I"
        },
        {
            "title": "Check UFW Status",
            "desc": "Melihat status firewall UFW.",
            "command": "/usr/sbin/ufw status verbose"
        },
        {
            "title": "Block Default SSH Port 22",
            "desc": "Menutup SSH port default 22.",
            "command": "/usr/sbin/ufw deny 22/tcp"
        },
        {
            "title": "Allow Hardened SSH Port 2222",
            "desc": "Membuka port SSH hardened 2222.",
            "command": "/usr/sbin/ufw allow 2222/tcp"
        },
        {
            "title": "Default Deny Incoming",
            "desc": "Menolak semua traffic masuk kecuali yang diizinkan.",
            "command": "/usr/sbin/ufw default deny incoming"
        },
        {
            "title": "Check Open Ports",
            "desc": "Melihat port yang terbuka di Kali.",
            "command": "/usr/bin/ss -tulnp"
        }
    ]

    if latest.get("detected_22"):
        message = "Controller membaca hasil Analyzer: SSH port 22 terdeteksi. Firewall hardening diperlukan."
        rules = [
            "Block inbound traffic to 22/tcp",
            "Allow inbound traffic only to 2222/tcp",
            "Set default deny incoming traffic",
            "Review top IP addresses from CSV evidence",
            "Capture ulang setelah hardening untuk bukti after"
        ]

    elif latest.get("detected_2222"):
        message = "Controller membaca hasil Analyzer: SSH port 2222 terdeteksi. Konfigurasi lebih aman, tetap perlu monitoring."
        rules = [
            "Keep 2222/tcp allowed",
            "Keep 22/tcp blocked",
            "Monitor failed login attempts",
            "Review firewall rule regularly"
        ]

    else:
        message = "Controller membaca hasil Analyzer: belum ada bukti SSH. Capture ulang traffic SSH diperlukan."
        rules = [
            "Verify CSV was exported from correct Wireshark capture",
            "Check source and destination IP",
            "Run SSH testing traffic again",
            "Upload new CSV after testing"
        ]

    return render_template(
        "controller.html",
        latest=latest,
        message=message,
        rules=rules,
        commands=commands,
        suspicious_ips=suspicious_ips,
        ssh_result=None,
        executed_command=None
    )


@app.route("/run-command", methods=["POST"])
def run_command():
    command = request.form.get("command")
    result = run_local_command(command)

    latest = load_latest_analysis()
    suspicious_ips = latest.get("top_ips", [])[:5] if latest else []

    commands = [
        {
            "title": "Check Kali IP",
            "desc": "Melihat IP server Kali.",
            "command": "hostname -I"
        },
        {
            "title": "Check UFW Status",
            "desc": "Melihat status firewall UFW.",
            "command": "/usr/sbin/ufw status verbose"
        },
        {
            "title": "Block Default SSH Port 22",
            "desc": "Menutup SSH port default 22.",
            "command": "/usr/sbin/ufw deny 22/tcp"
        },
        {
            "title": "Allow Hardened SSH Port 2222",
            "desc": "Membuka port SSH hardened 2222.",
            "command": "/usr/sbin/ufw allow 2222/tcp"
        },
        {
            "title": "Default Deny Incoming",
            "desc": "Menolak semua traffic masuk kecuali yang diizinkan.",
            "command": "/usr/sbin/ufw default deny incoming"
        },
        {
            "title": "Check Open Ports",
            "desc": "Melihat port yang terbuka di Kali.",
            "command": "/usr/bin/ss -tulnp"
        }
    ]

    return render_template(
        "controller.html",
        latest=latest,
        rules=["Command executed locally on Kali Linux server."],
        message="Local Kali Control result:",
        commands=commands,
        suspicious_ips=suspicious_ips,
        ssh_result=result,
        executed_command=command
    )


@app.route("/validator")
def validator():
    latest = load_latest_analysis()

    if not latest:
        return render_template(
            "validator.html",
            latest=None,
            level="Need Evidence",
            score="-",
            checklist=[
                ["Wireshark Evidence", "No CSV uploaded", "warning"],
                ["SSH Port", "Unknown", "warning"],
                ["Firewall Rule", "Unknown", "warning"],
                ["Zero-Trust Status", "Not evaluated", "warning"],
            ]
        )

    if latest.get("detected_2222") and not latest.get("detected_22"):
        level = "More Secure"
        score = 85
        checklist = [
            ["Wireshark Evidence", "CSV analyzed", "safe"],
            ["SSH Port", "2222 detected", "safe"],
            ["Default Port 22", "Not detected", "safe"],
            ["Firewall Rule", "Allow only 2222/tcp", "safe"],
            ["Root Login", "Must be disabled manually", "warning"],
            ["Password Auth", "Use SSH key-based auth", "warning"],
        ]

    elif latest.get("detected_22"):
        level = "Not Secure"
        score = 35
        checklist = [
            ["Wireshark Evidence", "CSV analyzed", "safe"],
            ["SSH Port", "Default port 22 detected", "danger"],
            ["Default Port 22", "Still exposed", "danger"],
            ["Firewall Rule", "Block 22/tcp needed", "danger"],
            ["Root Login", "Check sshd_config", "warning"],
            ["Password Auth", "Disable after key setup", "warning"],
        ]

    else:
        level = "Partial Evidence"
        score = 50
        checklist = [
            ["Wireshark Evidence", "CSV analyzed", "safe"],
            ["SSH Port", "No SSH evidence", "warning"],
            ["Default Port 22", "Not found in CSV", "warning"],
            ["Firewall Rule", "Need further testing", "warning"],
        ]

    return render_template(
        "validator.html",
        latest=latest,
        level=level,
        score=score,
        checklist=checklist
    )


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(EVIDENCE_FOLDER, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=True)