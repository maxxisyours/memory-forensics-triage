import subprocess
import yara
import os
import argparse
from datetime import datetime

# ── CLI ARGUMENTS 
parser = argparse.ArgumentParser(
    description="Open-Source Memory Forensics Triage Tool — Kaung San Bwar"
)
parser.add_argument(
    "-f", "--file",
    default=r"C:\Users\95995\Downloads\MemoryDump_Lab3.raw",
    help="Path to memory image file (default: MemoryDump_Lab1.raw)"
)
parser.add_argument(
    "--vol",
    default=r"C:\Users\95995\AppData\Local\Python\pythoncore-3.14-64\Scripts\vol.exe",
    help="Path to Volatility 3 executable"
)
parser.add_argument(
    "--yara-dir",
    default=r"C:\MemForensics\yara_rules",
    help="Path to YARA rules directory"
)
parser.add_argument(
    "-o", "--output",
    default=r"C:\MemForensics\report.html",
    help="Output HTML report path"
)
args = parser.parse_args()

MEMORY_IMAGE = args.file
VOL          = args.vol
YARA_DIR     = args.yara_dir
OUTPUT       = args.output

# ── PROCESS LISTS 
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
    "winrar.exe":     "File archiving tool — possible data staging or exfiltration behaviour.",
    "cmd.exe":        "Command prompt active — may indicate manual attacker activity or malicious script execution.",
    "mspaint.exe":    "Unusual for a standard session — commonly used for steganography (hiding data in images).",
    "powershell.exe": "PowerShell active — frequently abused for fileless malware execution and lateral movement.",
    "wscript.exe":    "Windows Script Host active — commonly used to execute malicious VBScript payloads.",
    "rundll32.exe":   "rundll32 active — frequently abused to execute malicious DLL payloads.",
    "mshta.exe":      "mshta active — commonly used to execute malicious HTA files.",
    "psexec.exe":     "PsExec detected — remote execution tool used for lateral movement.",
    "certutil.exe":   "certutil active — commonly abused to download malware and decode payloads.",
}

# ── PPID VALIDATION MAP 
VALID_PARENTS = {
    "smss.exe":         ["system"],
    "csrss.exe":        ["smss.exe"],
    "wininit.exe":      ["smss.exe"],
    "winlogon.exe":     ["smss.exe"],
    "lsass.exe":        ["wininit.exe"],
    "services.exe":     ["wininit.exe"],
    "svchost.exe":      ["services.exe"],
    "spoolsv.exe":      ["services.exe"],
    "taskhost.exe":     ["services.exe", "svchost.exe"],
    "explorer.exe":     ["userinit.exe", "winlogon.exe"],
    "conhost.exe":      ["csrss.exe", "cmd.exe", "powershell.exe"],
    "cmd.exe":          ["explorer.exe", "services.exe", "svchost.exe", "cmd.exe"],
    "powershell.exe":   ["explorer.exe", "cmd.exe", "services.exe", "svchost.exe", "wmiprvse.exe"],
    "wscript.exe":      ["explorer.exe", "cmd.exe", "powershell.exe"],
    "cscript.exe":      ["explorer.exe", "cmd.exe", "powershell.exe"],
    "mshta.exe":        ["explorer.exe", "cmd.exe", "powershell.exe"],
    "rundll32.exe":     ["explorer.exe", "svchost.exe", "services.exe"],
    "regsvr32.exe":     ["explorer.exe", "cmd.exe"],
}

# ── SUSPICIOUS NETWORK INDICATORS 
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor / C2 port",
    31337: "Elite backdoor port",
    6666:  "Common RAT port",
    6667:  "IRC — often used for C2 bot communication",
    1234:  "Common test / backdoor port",
    9999:  "Common RAT / backdoor port",
    8888:  "Common C2 beacon port",
    2222:  "Alternative SSH / backdoor",
    5555:  "Android ADB / common RAT port",
    65535: "Maximum port value — often chosen by malware",
}

SAFE_IP_PREFIXES = [
    "127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.2", "172.3", "::", "0.0.0.0", "*", "", "N/A"
]

SENSITIVE_PROCS = {"lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe"}


# ── PLUGIN RUNNER 
def run_plugin(name):
    print(f"[*] Running {name}...")
    try:
        result = subprocess.run(
            [VOL, "-f", MEMORY_IMAGE, name],
            capture_output=True, text=True,
            timeout=120  # 2-minute hard timeout per plugin
        )
        output = result.stdout
        if not output and result.stderr:
            output = f"[!] Plugin error: {result.stderr[:500]}"
        return output
    except subprocess.TimeoutExpired:
        print(f"[!] {name} timed out after 120 seconds")
        return f"[!] Plugin '{name}' timed out after 120 seconds — image may be corrupted or too large."
    except FileNotFoundError:
        print(f"[!] Volatility not found at: {VOL}")
        return f"[!] Volatility executable not found at path: {VOL}"
    except Exception as e:
        print(f"[!] {name} failed: {e}")
        return f"[!] Plugin '{name}' failed: {str(e)}"


# ── YARA SCANNER 
def run_yara_scan():
    print("[*] Running YARA scan...")
    filepaths = {}
    for root, dirs, files in os.walk(YARA_DIR):
        for f in files:
            if f.endswith((".yar", ".yara")):
                key = f.replace(".yar", "").replace(".yara", "")
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


# ── SEVERITY SCORER 
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
        if any(k.upper() in mu for k in critical_kw):   scored.append(("CRITICAL", m))
        elif any(k.upper() in mu for k in high_kw):     scored.append(("HIGH",     m))
        elif any(k.upper() in mu for k in medium_kw):   scored.append(("MEDIUM",   m))
        else:                                            scored.append(("LOW",      m))
    return scored


# ── PPID ANOMALY CHECKER 
def check_ppid_anomaly(proc_name, parent_name, ppid):
    """Return warning string if process has unexpected parent, else None."""
    name   = proc_name.lower()
    parent = parent_name.lower()
    if name in VALID_PARENTS and parent not in ("unknown", ""):
        expected = VALID_PARENTS[name]
        if parent not in expected:
            return (f"PPID anomaly — '{proc_name}' spawned by '{parent_name}' "
                    f"(PID {ppid}). Expected parent(s): {expected}. "
                    f"Possible PPID spoofing or process hollowing.")
    return None


# ── PROCESS CLASSIFIER 
def classify(pslist_output):
    # First pass: build PID -> name map for PPID lookups
    pid_to_name = {}
    rows = []
    for line in pslist_output.strip().split("\n"):
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid, ppid, raw = parts[0], parts[1], parts[2]
        pid_to_name[pid] = raw.lower()
        rows.append((pid, ppid, raw))

    classified = []
    for pid, ppid, raw in rows:
        name      = raw.lower()
        ppid_name = pid_to_name.get(ppid, "unknown")
        anomaly   = check_ppid_anomaly(name, ppid_name, ppid)

        if any(m in name for m in MALICIOUS):
            label  = "MALICIOUS"
            color  = "#dc2626"
            reason = "Known malware or forensic acquisition tool — immediate investigation required."
        elif any(s in name for s in SUSPICIOUS):
            label  = "SUSPICIOUS"
            color  = "#d97706"
            reason = SUSPICIOUS_REASONS.get(name, "Unusual process — warrants further analysis.")
        elif any(b in name for b in BENIGN):
            label  = "BENIGN"
            color  = "#16a34a"
            reason = "Known legitimate Windows system process."
        else:
            label  = "UNKNOWN"
            color  = "#6b7280"
            reason = "Not in known process list — manual review recommended."

        # Upgrade BENIGN to SUSPICIOUS if PPID anomaly detected
        if anomaly and label == "BENIGN":
            label  = "SUSPICIOUS"
            color  = "#d97706"
            reason = anomaly

        classified.append({
            "pid": pid, "ppid": ppid, "name": raw,
            "ppid_name": ppid_name,
            "label": label, "color": color,
            "reason": reason,
            "anomaly": anomaly or ""
        })
    return classified


# ── NETWORK ANALYSER 
def analyse_network(netscan_output):
    """Parse windows.netscan output and flag suspicious connections."""
    connections = []
    for line in netscan_output.strip().split("\n"):
        parts = line.split()
        # Vol3 netscan: Offset  Proto  LocalAddr  ForeignAddr  State  PID  Owner  [Created]
        if len(parts) < 7:
            continue
        if not parts[0].startswith("0x"):   # skip headers
            continue
        try:
            proto      = parts[1]
            local_addr = parts[2]
            foreign    = parts[3]
            state      = parts[4]
            pid        = parts[5]
            owner      = parts[6] if len(parts) > 6 else "N/A"

            # Split foreign address into IP and port
            if ":" in foreign:
                last_col     = foreign.rfind(":")
                foreign_ip   = foreign[:last_col]
                try:
                    foreign_port = int(foreign[last_col + 1:])
                except ValueError:
                    foreign_port = 0
            else:
                foreign_ip   = foreign
                foreign_port = 0

            flags = []

            # 1. Flag known bad ports
            if foreign_port in SUSPICIOUS_PORTS:
                flags.append(f"Port {foreign_port} — {SUSPICIOUS_PORTS[foreign_port]}")

            # 2. Flag ESTABLISHED connections to external (non-private) IPs
            if state == "ESTABLISHED":
                is_internal = any(foreign_ip.startswith(p) for p in SAFE_IP_PREFIXES)
                if not is_internal:
                    flags.append(f"Active external connection to {foreign_ip}:{foreign_port}")

            # 3. Flag sensitive system processes with any active network connection
            if state == "ESTABLISHED" and owner.lower() in SENSITIVE_PROCS:
                flags.append(
                    f"CRITICAL — sensitive system process '{owner}' has active connection. "
                    "Possible code injection or credential theft."
                )

            connections.append({
                "proto":        proto,
                "local":        local_addr,
                "foreign":      foreign,
                "foreign_ip":   foreign_ip,
                "foreign_port": foreign_port,
                "state":        state,
                "pid":          pid,
                "owner":        owner,
                "suspicious":   bool(flags),
                "flags":        "; ".join(flags) if flags else ""
            })
        except Exception:
            continue
    return connections


# ── MALFIND PARSER 
def parse_malfind(malfind_output):
    """
    Parse windows.malfind tabular output.
    Vol3 columns: PID  Process  Start VPN  End VPN  Tag  Protection  ...
    Flags PE headers (MZ in hex dump) and RWX memory (PAGE_EXECUTE_READWRITE).
    """
    hits    = []
    current = {}

    for line in malfind_output.split("\n"):
        stripped = line.strip()
        parts    = stripped.split()

        # New entry: first column is a digit (PID)
        if parts and parts[0].isdigit() and len(parts) >= 5:
            if current:
                hits.append(current)
            protection = " ".join(parts[5:]) if len(parts) > 5 else ""
            current = {
                "pid":        parts[0],
                "process":    parts[1] if len(parts) > 1 else "N/A",
                "start_vpn":  parts[2] if len(parts) > 2 else "N/A",
                "end_vpn":    parts[3] if len(parts) > 3 else "N/A",
                "tag":        parts[4] if len(parts) > 4 else "N/A",
                "protection": protection,
                "has_pe":     False,
                "has_rwx":    False,
            }
            prot_upper = protection.upper()
            if "EXECUTE_READWRITE" in prot_upper or "EXECUTE_WRITECOPY" in prot_upper:
                current["has_rwx"] = True

        elif current:
            # Check hex dump lines for MZ header (PE signature = 4d 5a)
            lower = stripped.lower()
            if "4d 5a" in lower or (stripped.startswith("4d") and "5a" in lower[:10]):
                current["has_pe"] = True

    if current:
        hits.append(current)

    # Report only entries with a PE header OR executable+writable memory
    return [h for h in hits if h["has_pe"] or h["has_rwx"]]


# ── NETWORK HTML SECTION 
def build_network_section(connections):
    if not connections:
        return ('<div class="card"><h2>&#127760; Network Connections — windows.netscan</h2>'
                '<p style="color:#64748b;font-size:13px">No network connections parsed from netscan output. '
                'Raw output is shown in the collapsed section below.</p></div>')

    sus_count = sum(1 for c in connections if c["suspicious"])
    total     = len(connections)

    html = (
        f'<div class="card">'
        f'<h2>&#127760; Network Connections — windows.netscan</h2>'
        f'<p style="font-size:13px;color:#64748b;margin-bottom:14px">'
        f'{total} connections parsed — '
        f'<strong style="color:#dc2626">{sus_count} flagged suspicious</strong>. '
        f'Suspicious rows are highlighted in red.</p>'
        f'<table><thead><tr>'
        f'<th>Proto</th><th>Local Address</th><th>Foreign Address</th>'
        f'<th>State</th><th>PID</th><th>Owner Process</th><th>Flags</th>'
        f'</tr></thead><tbody>'
    )

    for c in connections:
        row_bg   = 'background:#fef2f2' if c["suspicious"] else ''
        addr_col = 'color:#dc2626;font-weight:600' if c["suspicious"] else ''
        if c["flags"]:
            flag_html = f'<span style="color:#dc2626;font-size:11px;font-weight:600">&#9888; {c["flags"]}</span>'
        else:
            flag_html = '<span style="color:#16a34a;font-size:11px">&#10003; Clean</span>'
        state_col = ('#16a34a' if c['state'] == 'LISTEN'
                     else '#dc2626' if c['state'] == 'ESTABLISHED'
                     else '#64748b')
        html += (
            f'<tr style="{row_bg}">'
            f'<td style="font-family:Consolas,monospace;font-size:12px">{c["proto"]}</td>'
            f'<td style="font-family:Consolas,monospace;font-size:12px">{c["local"]}</td>'
            f'<td style="font-family:Consolas,monospace;font-size:12px;{addr_col}">{c["foreign"]}</td>'
            f'<td><span style="font-size:11px;font-weight:700;color:{state_col}">{c["state"]}</span></td>'
            f'<td>{c["pid"]}</td>'
            f'<td class="proc-name">{c["owner"]}</td>'
            f'<td style="font-size:12px">{flag_html}</td>'
            f'</tr>'
        )

    html += '</tbody></table></div>'
    return html


# ── MALFIND HTML SECTION 
def build_malfind_section(hits):
    if not hits:
        return ('<div class="card"><h2>&#128737; Code Injection — windows.malfind</h2>'
                '<p style="color:#16a34a;font-size:13px;font-weight:600">'
                '&#10003; No PE headers or RWX memory regions detected by malfind.</p></div>')

    html = (
        f'<div class="card">'
        f'<h2>&#128737; Code Injection Analysis — windows.malfind</h2>'
        f'<p style="font-size:13px;color:#64748b;margin-bottom:14px">'
        f'<strong style="color:#dc2626">{len(hits)} injection indicator(s) detected</strong>. '
        f'PE headers (MZ signature) or PAGE_EXECUTE_READWRITE memory found — '
        f'classic signs of process hollowing, DLL injection, or shellcode staging.</p>'
        f'<table><thead><tr>'
        f'<th>PID</th><th>Process</th><th>Start VPN</th>'
        f'<th>Protection</th><th>PE Header (MZ)</th><th>RWX Memory</th><th>Risk</th>'
        f'</tr></thead><tbody>'
    )

    for h in hits:
        pe_icon  = ('<span style="color:#dc2626;font-weight:700">&#10008; YES</span>'
                    if h["has_pe"] else '<span style="color:#64748b">No</span>')
        rwx_icon = ('<span style="color:#dc2626;font-weight:700">&#10008; YES</span>'
                    if h["has_rwx"] else '<span style="color:#64748b">No</span>')
        risk     = ("CRITICAL" if (h["has_pe"] and h["has_rwx"])
                    else "HIGH" if h["has_pe"] else "MEDIUM")
        risk_col = "#dc2626" if risk == "CRITICAL" else "#ef4444" if risk == "HIGH" else "#f59e0b"
        html += (
            f'<tr style="background:#fef2f2">'
            f'<td>{h["pid"]}</td>'
            f'<td class="proc-name">{h["process"]}</td>'
            f'<td style="font-family:Consolas,monospace;font-size:12px">{h["start_vpn"]}</td>'
            f'<td style="font-family:Consolas,monospace;font-size:11px;color:#7c3aed">{h["protection"]}</td>'
            f'<td>{pe_icon}</td>'
            f'<td>{rwx_icon}</td>'
            f'<td><span class="proc-badge" style="background:{risk_col}">{risk}</span></td>'
            f'</tr>'
        )

    html += '</tbody></table></div>'
    return html


# ── AUTO KEY FINDINGS 
def build_key_findings(classified, critical, net_connections, malfind_hits):
    html = '<div class="card"><h2>&#128680; Key Suspicious Findings — Auto Detected</h2>'

    mal     = [p for p in classified if p["label"] == "MALICIOUS"]
    sus     = [p for p in classified if p["label"] == "SUSPICIOUS"]
    net_sus = [c for c in net_connections if c["suspicious"]]

    if not mal and not sus and not critical and not net_sus and not malfind_hits:
        html += ('<div class="finding" style="background:#f0fdf4;border-color:#16a34a">'
                 '<span class="finding-badge" style="background:#16a34a">CLEAN</span>'
                 '<div class="finding-text">No overtly malicious or suspicious indicators detected. '
                 'Continue with manual review of raw plugin output below.</div></div>')

    for p in mal:
        html += (f'<div class="finding" style="background:#fef2f2;border-color:#dc2626">'
                 f'<span class="finding-badge" style="background:#dc2626">MALICIOUS</span>'
                 f'<div class="finding-text"><strong>{p["name"]} (PID {p["pid"]})</strong>'
                 f' — {p["reason"]}</div></div>')

    for p in sus:
        reason      = p["anomaly"] if p["anomaly"] else SUSPICIOUS_REASONS.get(p["name"].lower(), p["reason"])
        badge_col   = "#7c3aed" if p["anomaly"] else "#d97706"
        badge_label = "PPID ANOMALY" if p["anomaly"] else "SUSPICIOUS"
        html += (f'<div class="finding" style="background:#fffbeb;border-color:{badge_col}">'
                 f'<span class="finding-badge" style="background:{badge_col}">{badge_label}</span>'
                 f'<div class="finding-text"><strong>{p["name"]} (PID {p["pid"]})</strong>'
                 f' — {reason}</div></div>')

    if critical:
        top5 = ", ".join([m.split(" ")[0] for m in critical[:5]])
        html += (f'<div class="finding" style="background:#fef2f2;border-color:#dc2626">'
                 f'<span class="finding-badge" style="background:#dc2626">CRITICAL — YARA</span>'
                 f'<div class="finding-text"><strong>Process Injection Detected via YARA</strong> — '
                 f'{len(critical)} critical malware signatures matched including {top5} and more. '
                 f'Malicious code injected into legitimate processes — a sophisticated APT evasion '
                 f'technique only detectable through memory forensics.</div></div>')

    if malfind_hits:
        procs = ", ".join(set(h["process"] for h in malfind_hits[:5]))
        html += (f'<div class="finding" style="background:#fef2f2;border-color:#dc2626">'
                 f'<span class="finding-badge" style="background:#dc2626">CRITICAL — INJECTION</span>'
                 f'<div class="finding-text"><strong>Code Injection Detected via malfind</strong> — '
                 f'{len(malfind_hits)} memory region(s) with PE headers or RWX protection in: {procs}. '
                 f'Direct indicator of process hollowing, DLL injection, or shellcode in memory.</div></div>')

    if net_sus:
        sample = "; ".join(f'{c["owner"]} -> {c["foreign"]}' for c in net_sus[:3])
        html += (f'<div class="finding" style="background:#fef2f2;border-color:#dc2626">'
                 f'<span class="finding-badge" style="background:#dc2626">SUSPICIOUS — NETWORK</span>'
                 f'<div class="finding-text"><strong>{len(net_sus)} Suspicious Network Connection(s)</strong>'
                 f' — {sample}{"..." if len(net_sus) > 3 else ""}. '
                 f'Possible C2 communication or data exfiltration — see Network Connections section.</div></div>')

    html += "</div>"
    return html


# ── REPORT GENERATOR 
def generate_report(results, yara_matches):
    scored   = score(yara_matches)
    critical = [m for s, m in scored if s == "CRITICAL"]
    high     = [m for s, m in scored if s == "HIGH"]
    medium   = [m for s, m in scored if s == "MEDIUM"]
    low      = [m for s, m in scored if s == "LOW"]

    overall, overall_color = (
        ("CRITICAL", "#dc2626") if critical else
        ("HIGH",     "#ef4444") if high     else
        ("MEDIUM",   "#f59e0b") if medium   else
        ("LOW",      "#16a34a")
    )

    classified       = classify(results.get("Process List (windows.pslist)", ""))
    benign_count     = sum(1 for p in classified if p["label"] == "BENIGN")
    malicious_count  = sum(1 for p in classified if p["label"] == "MALICIOUS")
    suspicious_count = sum(1 for p in classified if p["label"] == "SUSPICIOUS")
    unknown_count    = sum(1 for p in classified if p["label"] == "UNKNOWN")
    anomaly_count    = sum(1 for p in classified if p["anomaly"])
    total            = max(len(classified), 1)

    net_connections = analyse_network(results.get("Network Connections (windows.netscan)", ""))
    net_suspicious  = sum(1 for c in net_connections if c["suspicious"])
    malfind_hits    = parse_malfind(results.get("Malicious Code Injection (windows.malfind)", ""))

    b_pct = round(benign_count / total * 100)
    s_pct = round(suspicious_count / total * 100)
    m_pct = round(malicious_count / total * 100)
    u_pct = 100 - b_pct - s_pct - m_pct
    b_end, s_end, m_end = b_pct, b_pct + s_pct, b_pct + s_pct + m_pct
    pie = (f"conic-gradient(#16a34a 0% {b_end}%,"
           f"#d97706 {b_end}% {s_end}%,"
           f"#dc2626 {s_end}% {m_end}%,"
           f"#6b7280 {m_end}% 100%)")

    ymax = max(len(critical), len(high), len(medium), len(low), 1)
    def bp(n): return round(n / ymax * 100)

    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    image_name = os.path.basename(MEMORY_IMAGE)

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
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:28px}}
  .stat-card{{background:white;border-radius:10px;padding:16px 10px;text-align:center;border-top:4px solid #e2e8f0;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .stat-card .num{{font-size:28px;font-weight:700}} .stat-card .lbl{{font-size:11px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
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
  .bar-fill{{height:100%;border-radius:6px;display:flex;align-items:center;padding-left:10px;font-size:12px;font-weight:700;color:white;min-width:30px}}
  .finding{{border-radius:8px;padding:12px 14px;margin-bottom:10px;border-left:4px solid;display:flex;align-items:flex-start;gap:12px}}
  .finding-badge{{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;color:white;white-space:nowrap;margin-top:1px;flex-shrink:0}}
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
  <div class="stat-card" style="border-top-color:#1e3a5f">
    <div class="num" style="color:#1e3a5f">8</div><div class="lbl">Plugins Run</div></div>
  <div class="stat-card" style="border-top-color:#7c3aed">
    <div class="num" style="color:#7c3aed">{len(yara_matches)}</div><div class="lbl">YARA Hits</div></div>
  <div class="stat-card" style="border-top-color:{overall_color}">
    <div class="num" style="color:{overall_color};font-size:18px">{overall}</div><div class="lbl">Threat Level</div></div>
  <div class="stat-card" style="border-top-color:#16a34a">
    <div class="num" style="color:#16a34a">{benign_count}</div><div class="lbl">Benign</div></div>
  <div class="stat-card" style="border-top-color:#dc2626">
    <div class="num" style="color:#dc2626">{malicious_count}</div><div class="lbl">Malicious</div></div>
  <div class="stat-card" style="border-top-color:#d97706">
    <div class="num" style="color:#d97706">{suspicious_count}</div><div class="lbl">Suspicious</div></div>
  <div class="stat-card" style="border-top-color:#6b7280">
    <div class="num" style="color:#6b7280">{unknown_count}</div><div class="lbl">Unknown</div></div>
  <div class="stat-card" style="border-top-color:#7c3aed">
    <div class="num" style="color:#7c3aed">{anomaly_count}</div><div class="lbl">PPID Anomalies</div></div>
  <div class="stat-card" style="border-top-color:#0284c7">
    <div class="num" style="color:#0284c7">{len(net_connections)}</div><div class="lbl">Net Connections</div></div>
  <div class="stat-card" style="border-top-color:#dc2626">
    <div class="num" style="color:#dc2626">{len(malfind_hits)}</div><div class="lbl">Injections</div></div>
</div>

<div class="charts-row">
  <div class="card">
    <h2>&#128200; Process Classification Breakdown</h2>
    <div class="pie-wrap">
      <div class="pie"></div>
      <div class="pie-legend">
        <div class="legend-item"><div class="legend-dot" style="background:#16a34a"></div>
          <span class="legend-label">Benign</span>
          <span class="legend-val">{benign_count}</span><span class="legend-pct">({b_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#d97706"></div>
          <span class="legend-label">Suspicious</span>
          <span class="legend-val">{suspicious_count}</span><span class="legend-pct">({s_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#dc2626"></div>
          <span class="legend-label">Malicious</span>
          <span class="legend-val">{malicious_count}</span><span class="legend-pct">({m_pct}%)</span></div>
        <div class="legend-item"><div class="legend-dot" style="background:#6b7280"></div>
          <span class="legend-label">Unknown</span>
          <span class="legend-val">{unknown_count}</span><span class="legend-pct">({u_pct}%)</span></div>
      </div>
    </div>
  </div>
  <div class="card">
    <h2>&#128202; YARA Detection Severity Distribution</h2>
    <div class="bar-chart">
      <div class="bar-row"><div class="bar-label"><span>CRITICAL</span><span>{len(critical)} hits</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:{bp(len(critical))}%;background:#dc2626">{len(critical)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>HIGH</span><span>{len(high)} hits</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:{bp(len(high))}%;background:#ef4444">{len(high)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>MEDIUM</span><span>{len(medium)} hits</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:{bp(len(medium))}%;background:#f59e0b">{len(medium)}</div></div></div>
      <div class="bar-row"><div class="bar-label"><span>LOW</span><span>{len(low)} hits</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:{bp(len(low))}%;background:#3b82f6">{len(low)}</div></div></div>
    </div>
    <p style="font-size:12px;color:#94a3b8;margin-top:12px">
      Total: {len(yara_matches)} YARA rules matched across {len(classified)} processes analysed</p>
  </div>
</div>

{build_key_findings(classified, critical, net_connections, malfind_hits)}

<div class="card">
  <h2>&#128196; Process Classification — Benign vs Malicious</h2>
  <p style="font-size:13px;color:#64748b;margin-bottom:14px">
    Every process automatically classified. Purple rows indicate PPID anomalies —
    a common sign of PPID spoofing or process hollowing.</p>
  <table>
    <thead><tr>
      <th>PID</th><th>PPID</th><th>Process Name</th><th>Parent Name</th>
      <th>Classification</th><th>Reason / PPID Anomaly</th>
    </tr></thead>
    <tbody>
"""
    for p in classified:
        anomaly_note = (
            f'<br><span style="color:#7c3aed;font-size:11px;font-weight:600">'
            f'&#9888; {p["anomaly"]}</span>'
        ) if p["anomaly"] else ""
        row_bg = 'background:#faf5ff' if p["anomaly"] else ''
        html += (
            f'<tr style="{row_bg}">'
            f'<td>{p["pid"]}</td>'
            f'<td>{p["ppid"]}</td>'
            f'<td class="proc-name">{p["name"]}</td>'
            f'<td style="font-family:Consolas,monospace;font-size:12px;color:#64748b">{p["ppid_name"]}</td>'
            f'<td><span class="proc-badge" style="background:{p["color"]}">{p["label"]}</span></td>'
            f'<td style="color:#475569;font-size:12px">{p["reason"]}{anomaly_note}</td>'
            f'</tr>\n'
        )

    html += "</tbody></table></div>\n"

    html += build_network_section(net_connections) + "\n"
    html += build_malfind_section(malfind_hits) + "\n"

    html += '<div class="card"><h2>&#128737; YARA Scan Results — Auto Severity Scoring</h2>\n'
    for sev, col, emoji, items in [
        ("CRITICAL", "#dc2626", "&#128308;", critical),
        ("HIGH",     "#ef4444", "&#128992;", high),
        ("MEDIUM",   "#f59e0b", "&#129993;", medium),
        ("LOW",      "#3b82f6", "&#128309;", low),
    ]:
        if items:
            html += (f'<div class="yara-group">'
                     f'<h3 style="background:{col}">{emoji} {sev} — {len(items)} Findings</h3>\n')
            for m in items:
                html += (f'<div class="yara-item">'
                         f'<div class="yara-dot" style="background:{col}"></div>{m}</div>\n')
            html += "</div>\n"
    html += "</div>\n"

    for pname, output in results.items():
        sid = pname.replace(" ", "_").replace("(", "").replace(")", "").replace(".", "_")
        html += (
            f'<div class="card"><h2>&#128196; {pname}</h2>\n'
            f'<button class="raw-toggle" onclick="toggleRaw(\'{sid}\')">&#9660; Show Raw Output</button>\n'
            f'<div class="raw-output" id="{sid}">{output[:3000]}</div></div>\n'
        )

    html += f"""
<div class="card conclusion">
  <h2>&#128221; Analyst Conclusion</h2>
  <p>Analysis of <strong>{image_name}</strong> successfully distinguished benign system processes
  from malicious and suspicious activity. Of <strong>{len(classified)} processes</strong> identified,
  <strong style="color:#16a34a">{benign_count} were confirmed benign</strong>,
  <strong style="color:#dc2626">{malicious_count} were classified malicious</strong>, and
  <strong style="color:#d97706">{suspicious_count} were flagged suspicious</strong>.
  PPID validation identified <strong style="color:#7c3aed">{anomaly_count} parent-process
  anomaly(ies)</strong>, indicating potential PPID spoofing or process hollowing.</p><br>
  <p>Network analysis of <strong>{len(net_connections)} connections</strong> flagged
  <strong style="color:#dc2626">{net_suspicious} suspicious connection(s)</strong> for further
  investigation. Code injection analysis via malfind revealed
  <strong style="color:#dc2626">{len(malfind_hits)} memory region(s)</strong> with PE headers
  or executable-writable pages — direct indicators of process injection in memory.</p><br>
  <p>YARA scanning against community-maintained signatures identified
  <strong>{len(yara_matches)} rule matches</strong> including CRITICAL-level detections of APT
  malware families. Overall threat level: <strong style="color:{overall_color}">{overall}</strong>.
  This report supports rapid incident response decision-making by automatically classifying every
  process and network connection — directly addressing the core objective of open-source memory
  forensics for malware and ransomware triage.</p>
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

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[+] Report saved to {OUTPUT}")


# ── MAIN 
print("=" * 55)
print("  OPEN-SOURCE MEMORY FORENSICS TRIAGE TOOL")
print("  Kaung San Bwar — University of Sunderland")
print("  BSc(Hons) Cybersecurity and Digital Forensics")
print("=" * 55)
print(f"[*] Memory Image : {MEMORY_IMAGE}")
print(f"[*] Volatility   : {VOL}")
print(f"[*] YARA Rules   : {YARA_DIR}")
print(f"[*] Output       : {OUTPUT}")
print("=" * 55)

results = {
    "Process List (windows.pslist)":              run_plugin("windows.pslist"),
    "Network Connections (windows.netscan)":      run_plugin("windows.netscan"),
    "Command Line History (windows.cmdline)":     run_plugin("windows.cmdline"),
    "DLL List (windows.dlllist)":                 run_plugin("windows.dlllist"),
    "Malicious Code Injection (windows.malfind)": run_plugin("windows.malfind"),
    "Open Handles (windows.handles)":             run_plugin("windows.handles"),
    "Registry Hives (windows.registry.hivelist)": run_plugin("windows.registry.hivelist"),
    "VAD Info (windows.vadinfo)":                 run_plugin("windows.vadinfo"),
}

yara_matches = run_yara_scan()
generate_report(results, yara_matches)
