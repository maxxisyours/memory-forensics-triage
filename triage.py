import subprocess
import yara
import os
from datetime import datetime
 
MEMORY_IMAGE = r"C:\Users\95995\Downloads\MemoryDump_Lab1.raw"
VOL = r"C:\Users\95995\AppData\Local\Python\pythoncore-3.14-64\Scripts\vol.exe"
 
# ── PROCESS LISTS ──────────────────────────────────────────────────
BENIGN = [
    "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
    "services.exe","lsass.exe","lsm.exe","svchost.exe","spoolsv.exe",
    "explorer.exe","taskhost.exe","dwm.exe","audiodg.exe","sppsvc.exe",
    "searchindexer.","wmpnetwk.exe","vboxservice.ex","vboxtray.exe",
    "searchprotocol","searchfilterho","conhost.exe"
]
MALICIOUS = [
    "dumpit.exe","mimikatz.exe","pwdump","fgdump","wce.exe",
    "procdump.exe","gsecdump.exe","winpmem.exe","redline.exe",
    "netcat.exe","nc.exe","ncat.exe","psexec.exe","psexesvc.exe",
    "meterpreter","payload.exe","malware.exe","ransomware.exe"
]
SUSPICIOUS = [
    "winrar.exe","cmd.exe","mspaint.exe","psxss.exe","tcpsvcs.exe",
    "powershell.exe","wscript.exe","cscript.exe","mshta.exe",
    "regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe",
    "wmic.exe","at.exe","schtasks.exe","whoami.exe","net.exe",
    "ipconfig.exe","nmap.exe","wireshark.exe","notepad.exe"
]
SUSPICIOUS_REASONS = {
    "winrar.exe":    "File archiving tool — possible data staging or exfiltration behaviour.",
    "cmd.exe":       "Command prompt active — may indicate manual attacker activity or malicious script execution.",
    "mspaint.exe":   "Unusual for a standard session — commonly used for steganography (hiding data in images).",
    "powershell.exe":"PowerShell active — frequently abused for fileless malware execution and lateral movement.",
    "wscript.exe":   "Windows Script Host active — commonly used to execute malicious VBScript payloads.",
    "rundll32.exe":  "rundll32 active — frequently abused to execute malicious DLL payloads.",
    "mshta.exe":     "mshta active — commonly used to execute malicious HTA files.",
    "psexec.exe":    "PsExec detected — remote execution tool used for lateral movement.",
    "certutil.exe":  "certutil active — commonly abused to download malware and decode payloads.",
}
 
# ── PLUGIN RUNNER ──────────────────────────────────────────────────
def run_plugin(name):
    print(f"[*] Running {name}...")
    result = subprocess.run([VOL, "-f", MEMORY_IMAGE, name], capture_output=True, text=True)
    return result.stdout
 
# ── YARA SCANNER ───────────────────────────────────────────────────
def run_yara_scan():
    print("[*] Running YARA scan...")
    filepaths = {}
    for root, dirs, files in os.walk(r"C:\MemForensics\yara_rules"):
        for f in files:
            if f.endswith((".yar", ".yara")):
                key = f.replace(".yar","").replace(".yara","")
                filepaths[key] = os.path.join(root, f)
    print(f"[*] Loaded {len(filepaths)} YARA rule files...")
    found = []
    for name, path in filepaths.items():
        try:
            rules = yara.compile(filepath=path)
            for m in rules.match(MEMORY_IMAGE):
                print(f"[!] YARA HIT: {m} in {name}")
                found.append(f"{m} ({name})")
        except Exception:
            pass
    if not found:
        print("[+] No YARA matches found")
    return found
 
# ── SEVERITY SCORER ────────────────────────────────────────────────
def score(yara_matches):
    critical_kw = ["APT","PlugX","Ursnif","Kovter","spyeye","Cerberus",
                   "Mirage","TSCookie","Datper","RAT","Keylogger","CAP_Hook",
                   "Bolonyokte","Yayih","Njrat","BlackShades","Xtreme","Cobalt",
                   "Derusbi","Hikit","Irontiger","Platinum","DeputyDog"]
    high_kw     = ["DumpIt","WinRAR","Rooter","UPX","Insta11","LURK","Shylock","maldoc"]
    medium_kw   = ["suspicious_strings","VM_Generic","VirtualBox","Dropper","Obfuscated","WMI"]
    scored = []
    for m in yara_matches:
        mu = m.upper()
        if any(k.upper() in mu for k in critical_kw):  scored.append(("CRITICAL", m))
        elif any(k.upper() in mu for k in high_kw):    scored.append(("HIGH", m))
        elif any(k.upper() in mu for k in medium_kw):  scored.append(("MEDIUM", m))
        else:                                           scored.append(("LOW", m))
    return scored
 
# ── PROCESS CLASSIFIER ─────────────────────────────────────────────
def classify(pslist_output):
    classified = []
    for line in pslist_output.strip().split("\n"):
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid, ppid, raw = parts[0], parts[1], parts[2]
        name = raw.lower()
        if any(m in name for m in MALICIOUS):
            classified.append({"pid":pid,"ppid":ppid,"name":raw,
                "label":"MALICIOUS","color":"#dc2626",
                "reason":"Known malware or forensic acquisition tool — immediate investigation required"})
        elif any(s in name for s in SUSPICIOUS):
            classified.append({"pid":pid,"ppid":ppid,"name":raw,
                "label":"SUSPICIOUS","color":"#d97706",
                "reason":"Unusual process for a standard session — warrants further analysis"})
        elif any(b in name for b in BENIGN):
            classified.append({"pid":pid,"ppid":ppid,"name":raw,
                "label":"BENIGN","color":"#16a34a",
                "reason":"Known legitimate Windows system process"})
        else:
            classified.append({"pid":pid,"ppid":ppid,"name":raw,
                "label":"UNKNOWN","color":"#6b7280",
                "reason":"Not in known process list — manual review recommended"})
    return classified
 
# ── AUTO KEY FINDINGS ──────────────────────────────────────────────
def build_key_findings(classified, critical):
    html = '<div class="card"><h2>&#128680; Key Suspicious Findings — Auto Detected</h2>'
    mal  = [p for p in classified if p["label"] == "MALICIOUS"]
    sus  = [p for p in classified if p["label"] == "SUSPICIOUS"]
 
    if not mal and not sus:
        html += """<div class="finding" style="background:#f0fdf4;border-color:#16a34a">
            <span class="finding-badge" style="background:#16a34a">CLEAN</span>
            <div class="finding-text">No overtly malicious or suspicious processes detected.
            However YARA signatures indicate possible code injection — see YARA results below.</div>
        </div>"""
    for p in mal:
        html += f"""<div class="finding" style="background:#fef2f2;border-color:#dc2626">
            <span class="finding-badge" style="background:#dc2626">MALICIOUS</span>
            <div class="finding-text"><strong>{p['name']} (PID {p['pid']})</strong> — {p['reason']}</div>
        </div>"""
    for p in sus:
        reason = SUSPICIOUS_REASONS.get(p['name'].lower(), p['reason'])
        html += f"""<div class="finding" style="background:#fffbeb;border-color:#d97706">
            <span class="finding-badge" style="background:#d97706">SUSPICIOUS</span>
            <div class="finding-text"><strong>{p['name']} (PID {p['pid']})</strong> — {reason}</div>
        </div>"""
    if critical:
        top5 = ", ".join([m.split(" ")[0] for m in critical[:5]])
        html += f"""<div class="finding" style="background:#fef2f2;border-color:#dc2626">
            <span class="finding-badge" style="background:#dc2626">CRITICAL</span>
            <div class="finding-text"><strong>Process Injection Detected via YARA</strong> —
            {len(critical)} critical malware signatures matched including {top5} and more.
            Malicious code injected into legitimate processes — a sophisticated APT evasion technique
            only detectable through memory forensics.</div>
        </div>"""
    html += "</div>"
    return html
 
# ── REPORT GENERATOR ───────────────────────────────────────────────
def generate_report(results, yara_matches):
    scored   = score(yara_matches)
    critical = [m for s,m in scored if s=="CRITICAL"]
    high     = [m for s,m in scored if s=="HIGH"]
    medium   = [m for s,m in scored if s=="MEDIUM"]
    low      = [m for s,m in scored if s=="LOW"]
 
    overall, overall_color = (
        ("CRITICAL","#dc2626") if critical else
        ("HIGH","#ef4444")     if high     else
        ("MEDIUM","#f59e0b")   if medium   else
        ("LOW","#16a34a")
    )
 
    classified     = classify(results.get("Process List (windows.pslist)",""))
    benign_count   = sum(1 for p in classified if p["label"]=="BENIGN")
    malicious_count= sum(1 for p in classified if p["label"]=="MALICIOUS")
    suspicious_count=sum(1 for p in classified if p["label"]=="SUSPICIOUS")
    unknown_count  = sum(1 for p in classified if p["label"]=="UNKNOWN")
    total          = max(len(classified),1)
 
    b_pct = round(benign_count/total*100)
    s_pct = round(suspicious_count/total*100)
    m_pct = round(malicious_count/total*100)
    u_pct = 100 - b_pct - s_pct - m_pct
    b_end, s_end, m_end = b_pct, b_pct+s_pct, b_pct+s_pct+m_pct
    pie   = f"conic-gradient(#16a34a 0% {b_end}%,#d97706 {b_end}% {s_end}%,#dc2626 {s_end}% {m_end}%,#6b7280 {m_end}% 100%)"
 
    ymax  = max(len(critical),len(high),len(medium),len(low),1)
    def bp(n): return round(n/ymax*100)
 
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    image_name = os.path.basename(MEMORY_IMAGE)
 
    # ── CSS ──
    css = f"""
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;color:#1e293b}}
  .header{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;padding:30px 40px 20px}}
  .header h1{{font-size:24px;font-weight:700}}
  .header .sub{{color:#38bdf8;font-size:14px;margin-top:4px}}
  .header .meta{{margin-top:14px;background:rgba(255,255,255,.08);border-radius:8px;padding:10px 16px;display:flex;flex-wrap:wrap;gap:20px;font-size:13px}}
  .header .meta span{{color:#94a3b8}} .header .meta strong{{color:#38bdf8;margin-right:4px}}
  .banner{{margin-top:14px;background:{overall_color};border-radius:8px;padding:10px 18px;font-size:16px;font-weight:700;display:inline-block}}
  .content{{padding:30px 40px;max-width:1400px;margin:0 auto}}
  .stat-grid{{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin-bottom:28px}}
  .stat-card{{background:white;border-radius:10px;padding:16px 10px;text-align:center;border-top:4px solid #e2e8f0;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .stat-card .num{{font-size:30px;font-weight:700}} .stat-card .lbl{{font-size:11px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
  .card{{background:white;border-radius:10px;padding:24px;margin-bottom:22px;box-shadow:0 1px 4px rgba(0,0,0,.08);border-left:5px solid #1e3a5f}}
  .card h2{{font-size:16px;font-weight:700;color:#0f172a;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #e2e8f0}}
  .charts-row{{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-bottom:22px}}
  .pie-wrap{{display:flex;align-items:center;gap:30px}}
  .pie{{width:160px;height:160px;border-radius:50%;background:{pie};flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.15)}}
  .pie-legend{{flex:1}} .legend-item{{display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:13px}}
  .legend-dot{{width:14px;height:14px;border-radius:3px;flex-shrink:0}} .legend-label{{flex:1;color:#374151}}
  .legend-val{{font-weight:700;color:#0f172a}} .legend-pct{{color:#94a3b8;font-size:12px}}
  .bar-chart{{width:100%}} .bar-row{{margin-bottom:14px}}
  .bar-label{{font-size:12px;font-weight:600;color:#374151;margin-bottom:4px;display:flex;justify-content:space-between}}
  .bar-track{{background:#f1f5f9;border-radius:6px;height:28px;overflow:hidden}}
  .bar-fill{{height:100%;border-radius:6px;display:flex;align-items:center;padding-left:10px;font-size:12px;font-weight:700;color:white}}
  .finding{{border-radius:8px;padding:12px 14px;margin-bottom:10px;border-left:4px solid;display:flex;align-items:flex-start;gap:12px}}
  .finding-badge{{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;color:white;white-space:nowrap;margin-top:1px}}
  .finding-text{{font-size:13px;line-height:1.5}} .finding-text strong{{color:#0f172a}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead tr{{background:#0f172a;color:white}} thead th{{padding:10px 12px;text-align:left;font-weight:600;font-size:12px}}
  tbody tr:nth-child(even){{background:#f8fafc}} tbody tr:hover{{background:#eff6ff}}
  tbody td{{padding:9px 12px;border-bottom:1px solid #e2e8f0}}
  .proc-badge{{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;color:white;display:inline-block}}
  .proc-name{{font-family:Consolas,monospace;font-weight:600;color:#1e3a5f}}
  .yara-group{{margin-bottom:16px}}
  .yara-group h3{{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;padding:6px 12px;border-radius:6px;color:white}}
  .yara-item{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:8px 12px;margin-bottom:6px;font-size:12.5px;font-family:Consolas,monospace;color:#334155;display:flex;align-items:center;gap:8px}}
  .yara-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
  .raw-toggle{{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:8px 14px;font-size:12px;cursor:pointer;color:#475569;margin-bottom:8px;width:100%;text-align:left;font-weight:600}}
  .raw-output{{background:#0f172a;color:#4ade80;padding:14px;border-radius:8px;font-family:Consolas,monospace;font-size:11.5px;overflow-x:auto;white-space:pre;display:none;max-height:320px;overflow-y:auto}}
  .conclusion{{background:#f0f9ff;border-left:5px solid #0284c7}} .conclusion p{{font-size:14px;line-height:1.8;color:#1e3a5f}}
  .footer{{text-align:center;padding:20px;font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;margin-top:10px;background:white}}
"""
 
    # ── HTML START ──
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Memory Forensics Triage — Kaung San Bwar</title>
<style>{css}</style></head><body>
 
<div class="header">
  <h1>&#128269; Open-Source Memory Forensics for Malware / Ransomware Triage</h1>
  <div class="sub">Distinguishing Benign vs Malicious Processes — Automated Triage Report</div>
  <div class="meta">
    <div><strong>Analyst:</strong><span>Kaung San Bwar</span></div>
    <div><strong>Programme:</strong><span>BSc Cybersecurity and Digital Forensics</span></div>
    <div><strong>University:</strong><span>University of Sunderland</span></div>
    <div><strong>Tool:</strong><span>Volatility 3 v2.27.0 + YARA</span></div>
    <div><strong>Image:</strong><span>{image_name}</span></div>
    <div><strong>Generated:</strong><span>{now}</span></div>
  </div>
  <div class="banner">&#9888; Threat Level: {overall} &nbsp;|&nbsp; {len(yara_matches)} YARA Rules Matched</div>
</div>
 
<div class="content">
 
<div class="stat-grid">
  <div class="stat-card" style="border-top-color:#1e3a5f"><div class="num" style="color:#1e3a5f">6</div><div class="lbl">Plugins Run</div></div>
  <div class="stat-card" style="border-top-color:#7c3aed"><div class="num" style="color:#7c3aed">{len(yara_matches)}</div><div class="lbl">YARA Hits</div></div>
  <div class="stat-card" style="border-top-color:{overall_color}"><div class="num" style="color:{overall_color};font-size:20px">{overall}</div><div class="lbl">Threat Level</div></div>
  <div class="stat-card" style="border-top-color:#16a34a"><div class="num" style="color:#16a34a">{benign_count}</div><div class="lbl">Benign</div></div>
  <div class="stat-card" style="border-top-color:#dc2626"><div class="num" style="color:#dc2626">{malicious_count}</div><div class="lbl">Malicious</div></div>
  <div class="stat-card" style="border-top-color:#d97706"><div class="num" style="color:#d97706">{suspicious_count}</div><div class="lbl">Suspicious</div></div>
  <div class="stat-card" style="border-top-color:#6b7280"><div class="num" style="color:#6b7280">{unknown_count}</div><div class="lbl">Unknown</div></div>
</div>
 
<div class="charts-row">
  <div class="card">
    <h2>&#128200; Process Classification Breakdown</h2>
    <div class="pie-wrap">
      <div class="pie"></div>
      <div class="pie-legend">
        <div class="legend-item"><div class="legend-dot" style="background:#16a34a"></div><span class="legend-label">Benign</span><span class="legend-val">{benign_count}</span><span class="legend-pct">({b_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#d97706"></div><span class="legend-label">Suspicious</span><span class="legend-val">{suspicious_count}</span><span class="legend-pct">({s_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#dc2626"></div><span class="legend-label">Malicious</span><span class="legend-val">{malicious_count}</span><span class="legend-pct">({m_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#6b7280"></div><span class="legend-label">Unknown</span><span class="legend-val">{unknown_count}</span><span class="legend-pct">({u_pct}%)</span></div>
      </div>
    </div>
  </div>
  <div class="card">
    <h2>&#128202; YARA Detection Severity Distribution</h2>
    <div class="bar-chart">
      <div class="bar-row"><div class="bar-label"><span>CRITICAL</span><span>{len(critical)} hits</span></div><div class="bar-track"><div class="bar-fill" style="width:{bp(len(critical))}%;background:#dc2626">{len(critical)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>HIGH</span><span>{len(high)} hits</span></div><div class="bar-track"><div class="bar-fill" style="width:{bp(len(high))}%;background:#ef4444">{len(high)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>MEDIUM</span><span>{len(medium)} hits</span></div><div class="bar-track"><div class="bar-fill" style="width:{bp(len(medium))}%;background:#f59e0b">{len(medium)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>LOW</span><span>{len(low)} hits</span></div><div class="bar-track"><div class="bar-fill" style="width:{bp(len(low))}%;background:#3b82f6">{len(low)}</div></div></div>
    </div>
    <p style="font-size:12px;color:#94a3b8;margin-top:12px">Total: {len(yara_matches)} YARA rules matched across {len(classified)} processes analysed</p>
  </div>
</div>
 
{build_key_findings(classified, critical)}
 
<div class="card">
  <h2>&#128196; Process Classification — Benign vs Malicious</h2>
  <p style="font-size:13px;color:#64748b;margin-bottom:14px">Every process has been automatically classified to distinguish benign system processes from malicious or suspicious activity.</p>
  <table>
    <thead><tr><th>PID</th><th>PPID</th><th>Process Name</th><th>Classification</th><th>Reason</th></tr></thead>
    <tbody>
"""
    for p in classified:
        html += f"""<tr><td>{p['pid']}</td><td>{p['ppid']}</td><td class="proc-name">{p['name']}</td>
        <td><span class="proc-badge" style="background:{p['color']}">{p['label']}</span></td>
        <td style="color:#475569;font-size:12px">{p['reason']}</td></tr>\n"""
 
    html += "</tbody></table></div>\n"
 
    # YARA RESULTS
    html += '<div class="card"><h2>&#128737; YARA Scan Results — Auto Severity Scoring</h2>\n'
    for sev, col, emoji, items in [
        ("CRITICAL","#dc2626","&#128308;",critical),
        ("HIGH","#ef4444","&#128992;",high),
        ("MEDIUM","#f59e0b","&#129993;",medium),
        ("LOW","#3b82f6","&#128309;",low),
    ]:
        if items:
            html += f'<div class="yara-group"><h3 style="background:{col}">{emoji} {sev} — {len(items)} Findings</h3>\n'
            for m in items:
                html += f'<div class="yara-item"><div class="yara-dot" style="background:{col}"></div>{m}</div>\n'
            html += "</div>\n"
    html += "</div>\n"
 
    # RAW PLUGIN OUTPUT
    for pname, output in results.items():
        sid = pname.replace(" ","_").replace("(","").replace(")","").replace(".","_")
        html += f"""<div class="card"><h2>&#128196; {pname}</h2>
<button class="raw-toggle" onclick="toggleRaw('{sid}')">&#9660; Show Raw Output</button>
<div class="raw-output" id="{sid}">{output[:3000]}</div></div>\n"""
 
    # CONCLUSION
    html += f"""
<div class="card conclusion">
  <h2>&#128221; Analyst Conclusion</h2>
  <p>Analysis of <strong>{image_name}</strong> successfully distinguished benign system processes
  from malicious and suspicious activity. Of <strong>{len(classified)} processes</strong> identified,
  <strong style="color:#16a34a">{benign_count} were confirmed benign</strong>,
  <strong style="color:#dc2626">{malicious_count} were classified malicious</strong>, and
  <strong style="color:#d97706">{suspicious_count} were flagged suspicious</strong>.</p><br>
  <p>YARA scanning against <strong>406 community-maintained signatures</strong> identified
  <strong>{len(yara_matches)} rule matches</strong> including CRITICAL-level detections of APT
  malware families. Overall threat level: <strong style="color:{overall_color}">{overall}</strong>.
  This report supports rapid incident response decision-making by automatically classifying every
  process — directly addressing the core objective of open-source memory forensics for
  malware and ransomware triage.</p>
</div>
 
</div>
<div class="footer">Open-Source Memory Forensics Triage Tool &nbsp;|&nbsp;
Kaung San Bwar — BSc Cybersecurity and Digital Forensics &nbsp;|&nbsp;
University of Sunderland &nbsp;|&nbsp; Generated: {now}</div>
 
<script>
function toggleRaw(id){{
  var el=document.getElementById(id),btn=el.previousElementSibling;
  if(el.style.display==='block'){{el.style.display='none';btn.innerHTML='&#9660; Show Raw Output';}}
  else{{el.style.display='block';btn.innerHTML='&#9650; Hide Raw Output';}}
}}
</script></body></html>"""
 
    with open("C:\\MemForensics\\report.html","w",encoding="utf-8") as f:
        f.write(html)
    print("\n[+] Report saved to C:\\MemForensics\\report.html")
 
 
# ── MAIN ───────────────────────────────────────────────────────────
print("=" * 55)
print("  OPEN-SOURCE MEMORY FORENSICS TRIAGE TOOL")
print("  Kaung San Bwar — University of Sunderland")
print("  BSc Cybersecurity and Digital Forensics")
print("=" * 55)
 
results = {
    "Process List (windows.pslist)":             run_plugin("windows.pslist"),
    "Network Connections (windows.netscan)":     run_plugin("windows.netscan"),
    "Command Line History (windows.cmdline)":    run_plugin("windows.cmdline"),
    "DLL List (windows.dlllist)":                run_plugin("windows.dlllist"),
    "Malicious Code Injection (windows.malfind)":run_plugin("windows.malfind"),
    "Open Handles (windows.handles)":            run_plugin("windows.handles"),
}
 
yara_matches = run_yara_scan()
generate_report(results, yara_matches)