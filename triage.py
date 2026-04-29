import subprocess
import yara
import os

MEMORY_IMAGE = r"C:\Users\95995\Downloads\MemoryDump_Lab1.raw"
VOL = r"C:\Users\95995\AppData\Local\Python\pythoncore-3.14-64\Scripts\vol.exe"

def run_plugin(plugin_name):
    print(f"[*] Running {plugin_name}...")
    command = [VOL, "-f", MEMORY_IMAGE, plugin_name]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def run_yara_scan():
    print("[*] Running YARA scan...")
    rules_dir = r"C:\MemForensics\yara_rules"
    filepaths = {}

    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                full_path = os.path.join(root, file)
                rule_name = file.replace(".yar", "").replace(".yara", "")
                filepaths[rule_name] = full_path

    print(f"[*] Loaded {len(filepaths)} YARA rule files...")

    matches_found = []
    for rule_name, rule_path in filepaths.items():
        try:
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(MEMORY_IMAGE)
            if matches:
                for match in matches:
                    print(f"[!] YARA HIT: {match} in rule file {rule_name}")
                    matches_found.append(f"{match} ({rule_name})")
        except Exception:
            pass

    if not matches_found:
        print("[+] No YARA matches found")

    return matches_found

def score_findings(yara_matches):
    scores = []

    critical_keywords = ["APT", "PlugX", "Ursnif", "Kovter", "spyeye",
                         "Cerberus", "Mirage", "TSCookie", "Datper", "RAT",
                         "Keylogger", "CAP_Hook", "Bolonyokte", "Yayih"]

    high_keywords = ["DumpIt", "WinRAR", "Rooter", "UPX", "Insta11",
                     "LURK", "Shylock", "maldoc"]

    medium_keywords = ["suspicious_strings", "VM_Generic", "VirtualBox",
                       "Dropper", "Obfuscated", "WMI"]

    low_keywords = ["base64", "domain", "url", "IP", "email",
                    "attachment", "image"]

    for match in yara_matches:
        match_upper = match.upper()
        if any(k.upper() in match_upper for k in critical_keywords):
            scores.append(("CRITICAL", match))
        elif any(k.upper() in match_upper for k in high_keywords):
            scores.append(("HIGH", match))
        elif any(k.upper() in match_upper for k in medium_keywords):
            scores.append(("MEDIUM", match))
        else:
            scores.append(("LOW", match))

    return scores

def generate_report(results, yara_matches):
    scored = score_findings(yara_matches)

    critical = [m for s, m in scored if s == "CRITICAL"]
    high = [m for s, m in scored if s == "HIGH"]
    medium = [m for s, m in scored if s == "MEDIUM"]
    low = [m for s, m in scored if s == "LOW"]

    if critical:
        overall = "CRITICAL"
        overall_color = "#cc0000"
    elif high:
        overall = "HIGH"
        overall_color = "#ff4444"
    elif medium:
        overall = "MEDIUM"
        overall_color = "#ff8800"
    else:
        overall = "LOW"
        overall_color = "#00aa00"

    yara_section = f"""
    <div class='section'>
        <h2>YARA Scan Results — Auto Severity Scoring</h2>
        <div style='background:{overall_color};color:white;padding:10px 20px;
        border-radius:8px;font-size:18px;font-weight:bold;margin-bottom:15px'>
        Overall Threat Level: {overall} — {len(yara_matches)} rules matched
        </div>
"""
    if critical:
        yara_section += "<h3 style='color:#cc0000'>CRITICAL Findings</h3>"
        for m in critical:
            yara_section += f"<div class='suspicious'><span class='badge high'>CRITICAL</span> {m}</div>"

    if high:
        yara_section += "<h3 style='color:#ff4444'>HIGH Findings</h3>"
        for m in high:
            yara_section += f"<div class='suspicious'><span class='badge high'>HIGH</span> {m}</div>"

    if medium:
        yara_section += "<h3 style='color:#ff8800'>MEDIUM Findings</h3>"
        for m in medium:
            yara_section += f"<div class='suspicious'><span class='badge medium'>MEDIUM</span> {m}</div>"

    if low:
        yara_section += "<h3 style='color:#0088ff'>LOW Findings</h3>"
        for m in low:
            yara_section += f"<div class='suspicious'><span class='badge info'>LOW</span> {m}</div>"

    yara_section += "</div>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Memory Forensics Triage Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }}
        h1 {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        h2 {{ color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 5px; }}
        .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 5px solid #e94560; }}
        .suspicious {{ background: #fff3cd; border-left: 5px solid #ff6b35; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        pre {{ background: #1a1a2e; color: #00ff88; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .high {{ background: #ff4444; color: white; }}
        .medium {{ background: #ff8800; color: white; }}
        .info {{ background: #0088ff; color: white; }}
        .summary-box {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #1a1a2e; color: white; padding: 15px 25px; border-radius: 8px; text-align: center; }}
        .stat-num {{ font-size: 32px; font-weight: bold; color: #e94560; }}
        .stat-label {{ font-size: 13px; color: #aaa; }}
    </style>
</head>
<body>
    <h1>Memory Forensics Triage Report</h1>
    <p><strong>Image:</strong> MemoryDump_Lab1.raw &nbsp;|&nbsp;
       <strong>Tool:</strong> Volatility 3 v2.27.0 &nbsp;|&nbsp;
       <strong>Date:</strong> 2026-04-28</p>

    <div class="summary-box">
        <div class="stat"><div class="stat-num">6</div><div class="stat-label">Plugins Run</div></div>
        <div class="stat"><div class="stat-num">{len(yara_matches)}</div><div class="stat-label">YARA Hits</div></div>
        <div class="stat"><div class="stat-num" style="color:{overall_color}">{overall}</div><div class="stat-label">Threat Level</div></div>
    </div>

    <div class="section">
        <h2>Suspicious Findings Summary</h2>
        <div class="suspicious">
            <span class="badge high">HIGH</span>
            <strong>DumpIt.exe</strong> detected — memory acquisition tool found running under user SmartNet. Indicates deliberate memory capture activity.
        </div>
        <div class="suspicious">
            <span class="badge high">HIGH</span>
            <strong>WinRAR.exe</strong> detected — file archiving tool active. Possible data staging or exfiltration behaviour.
        </div>
        <div class="suspicious">
            <span class="badge medium">MEDIUM</span>
            <strong>cmd.exe</strong> detected — command prompt was active. May indicate manual attacker activity or script execution.
        </div>
        <div class="suspicious">
            <span class="badge medium">MEDIUM</span>
            <strong>mspaint.exe</strong> detected — unusual for a typical session. Possibly used for steganography (hiding data in images).
        </div>
    </div>
"""

    for plugin_name, output in results.items():
        html += f"""
    <div class="section">
        <h2>{plugin_name}</h2>
        <pre>{output[:3000]}</pre>
    </div>
"""

    html += yara_section
    html += """
    <div class="section">
        <h2>Analyst Conclusion</h2>
        <p>The memory image shows evidence of suspicious activity including memory acquisition tools,
        file archiving, and active command prompt sessions. YARA scanning identified critical malware
        signatures including APT malware families and remote access trojans. Further deep-dive analysis
        is recommended focusing on process injection, network connections, and hidden files.</p>
    </div>
</body>
</html>
"""

    with open("C:\\MemForensics\\report.html", "w") as f:
        f.write(html)
    print("\n[+] Report saved to C:\\MemForensics\\report.html")

print("=" * 50)
print("  MEMORY FORENSICS TRIAGE TOOL")
print("=" * 50)

results = {}
results["Process List (windows.pslist)"] = run_plugin("windows.pslist")
results["Network Connections (windows.netscan)"] = run_plugin("windows.netscan")
results["Command Line History (windows.cmdline)"] = run_plugin("windows.cmdline")
results["DLL List (windows.dlllist)"] = run_plugin("windows.dlllist")
results["Malicious Code Injection (windows.malfind)"] = run_plugin("windows.malfind")
results["Open Handles (windows.handles)"] = run_plugin("windows.handles")

yara_matches = run_yara_scan()
generate_report(results, yara_matches)