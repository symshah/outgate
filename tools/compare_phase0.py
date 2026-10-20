import json, subprocess, sys

# MIB_TCP_STATE enum name -> netstat text
STATE_MAP = {"Established":"ESTABLISHED","Listen":"LISTENING","SynSent":"SYN_SENT","SynReceived":"SYN_RECEIVED","FinWait1":"FIN_WAIT_1","FinWait2":"FIN_WAIT_2","TimeWait":"TIME_WAIT","Close":"CLOSED","CloseWait":"CLOSE_WAIT","LastAck":"LAST_ACK","Closing":"CLOSING"}

def norm_ip(ip):
    # netstat shows 0.0.0.0 for any; MIB too. Keep as-is.
    return ip.strip()

def split_ep(s):
    ip, port = s.rsplit(":", 1)
    return ip, int(port)

# --- outboundctl side (fields: pid, process, local "ip:port", remote "ip:port", proto, state) ---
out = subprocess.run(["G:/OutboundWin/src/outboundctl/bin/Debug/net8.0/outboundctl.exe","flows","--json"], capture_output=True, text=True)
rows = json.loads(out.stdout)
parsed = []
for r in rows:
    li, lp = split_ep(r["local"])
    ri, rp = split_ep(r["remote"])
    parsed.append({"pid":r["pid"],"process":r.get("process",""),
                   "proto":r["proto"],"state":r["state"],  # enum name, e.g. "Established"
                   "localIp":li,"localPort":lp,"remoteIp":ri,"remotePort":rp})
tcp_rows = [r for r in parsed if r["proto"]=="tcp"]
udp_rows = [r for r in parsed if r["proto"]=="udp"]

# --- netstat side ---
ns_out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
ns_tcp, ns_udp = [], []
for line in ns_out.splitlines():
    p = line.split()
    if len(p) < 5: continue
    proto = p[0].upper()
    if proto == "TCP":
        la, lp = p[1].rsplit(":",1); ra, rp = p[2].rsplit(":",1)
        ns_tcp.append({"local":la.strip("[]"),"lport":int(lp),"remote":ra.strip("[]"),"rport":int(rp),"state":p[3],"pid":int(p[4])})
    elif proto == "UDP":
        la, lp = p[1].rsplit(":",1)
        ns_udp.append({"local":la,"lport":int(lp),"pid":int(p[2]) if len(p)>2 else None})

# netstat UDP lines: "UDP 0.0.0.0:53 *:* 4" -> p = [UDP, local, remote, pid]
ns_udp = []
for line in ns_out.splitlines():
    p = line.split()
    if len(p) >= 4 and p[0].upper()=="UDP":
        la, lp = p[1].rsplit(":",1)
        ns_udp.append({"local":la,"lport":int(lp),"pid":int(p[3])})

def compare_tcp(n=20):
    lines = []
    checked = 0; ok = 0
    for r in tcp_rows:
        if checked >= n: break
        # find netstat match by local addr+port AND remote addr+port (both directions exist)
        cands = [x for x in ns_tcp if x["local"]==r["localIp"] and x["lport"]==r["localPort"]
                 and x["remote"]==r["remoteIp"] and x["rport"]==r["remotePort"]]
        checked += 1
        state_txt = STATE_MAP.get(r["state"], str(r["state"]))
        if not cands:
            lines.append(f"NO-MATCH   {r['localIp']}:{r['localPort']} -> {r['remoteIp']}:{r['remotePort']} state={state_txt} pid={r['pid']}")
            continue
        m = cands[0]
        match = (m["state"]==state_txt and m["pid"]==r["pid"])
        if match: ok += 1
        lines.append(f"{'OK' if match else 'MISMATCH'}   ctl={r['localIp']}:{r['localPort']}->{r['remoteIp']}:{r['remotePort']} {state_txt} pid={r['pid']} | netstat={m['local']}:{m['lport']}->{m['remote']}:{m['rport']} {m['state']} pid={m['pid']}")
    return lines, checked, ok

def compare_udp(n=20):
    lines = []; checked = 0; ok = 0
    for r in udp_rows:
        if checked >= n: break
        cands = [x for x in ns_udp if x["local"]==r["localIp"] and x["lport"]==r["localPort"]]
        checked += 1
        if not cands:
            lines.append(f"NO-MATCH   {r['localIp']}:{r['localPort']} pid={r['pid']}")
            continue
        m = cands[0]
        match = (m["pid"]==r["pid"])
        if match: ok += 1
        lines.append(f"{'OK' if match else 'MISMATCH'}   ctl={r['localIp']}:{r['localPort']} pid={r['pid']} | netstat={m['local']}:{m['lport']} pid={m['pid']}")
    return lines, checked, ok

tcp_lines, tcp_checked, tcp_ok = compare_tcp(20)
udp_lines, udp_checked, udp_ok = compare_udp(20)

report = []
report.append("## Phase 0 — live check: outboundctl vs netstat -ano")
report.append("")
report.append(f"outboundctl rows: TCP={len(tcp_rows)} UDP={len(udp_rows)} (total {len(rows)})")
report.append(f"netstat -ano lines: TCP={len(ns_tcp)} UDP={len(ns_udp)}")
report.append(f"TCP count delta: {abs(len(tcp_rows)-len(ns_tcp))} (transient connections between the two snapshots are expected)")
report.append("")
report.append("### 20 TCP rows (all states) — outboundctl vs netstat -ano")
report.extend(tcp_lines)
report.append(f"\nTCP checked={tcp_checked}, matched={tcp_ok}")
report.append("")
report.append("### 20 UDP rows — outboundctl vs netstat -ano")
report.extend(udp_lines)
report.append(f"\nUDP checked={udp_checked}, matched={udp_ok}")

text = "\n".join(report) + "\n"
with open("G:/OutboundWin/PROGRESS.md","a",encoding="utf-8") as f:
    f.write("\n" + text)
print(text)
print(f"\nRESULT tcp {tcp_ok}/{tcp_checked} udp {udp_ok}/{udp_checked}")
