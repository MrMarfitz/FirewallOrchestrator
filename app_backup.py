from flask import Flask, render_template

app = Flask(__name__)

APP_NAME = "Firewall Orchestrator"


@app.route("/")
def dashboard():
    summary = {
        "app_name": APP_NAME,
        "security_score": 45,
        "firewall_status": "Not Checked",
        "ssh_status": "Not Checked",
        "wireshark_status": "No file analyzed yet",
    }
    return render_template("dashboard.html", summary=summary)


@app.route("/analyzer")
def analyzer():
    return render_template("analyzer.html")


@app.route("/controller")
def controller():
    return render_template("controller.html")


@app.route("/validator")
def validator():
    return render_template("validator.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
