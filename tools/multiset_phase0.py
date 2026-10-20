import json, subprocess
from collections import Counter

def split_ep(s):
    ip, port = s.rsplit(":", 1)
    return ip.strip("[]"), int(port)

out = subprocess.run(["G:/OutboundWin/src/outboundctl/bin/Debug/net8.0/outboundctl.exe","flows","--json"], capture_output=True, text=True)
rows = json.loads(out.stdout)
parsed = []
for r in rows:
    li, lp = split_ep(r["local"]); ri, rp = split_ep(r["remote"])
    parsed.append({"pid":r["pid"],"proto":r["proto"],"state":r["state"],
                   "localIp":li,"localPort":lp,"remoteIp":ri,"remotePort":rp})

ns_out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
ns_tcp, ns_udp = [], []
for line in ns_out.splitlines():
    p = line.split()
    if len(p) < 4: continue
    if p[0].upper()=="TCP":
        la, lp = split_ep(p[1]); ra, rp = split_ep(p[2])
        ns_tcp.append((la,lp,ra,rp,p[3],int(p[4])))
    elif p[0].upper()=="UDP" and len(p)>=4:
        la, lp = split_ep(p[1])
        ns_udp.append((la,lp,int(p[3])))

# Multiset comparison (shared ports like mDNS 5353 have many PIDs per endpoint)
ctl_tcp = Counter((r["localIp"],r["localPort"],r["remoteIp"],r["remotePort"],r["state"].upper(),r["pid"]) for r in parsed if r["proto"]=="tcp")
ns_tcp_c  = Counter((a,b,c,d,s,pid) for a,b,c,d,s,pid in ns_tcp)
# state names differ: ctl "Established" vs netstat "ESTABLISHED" -> normalize both to upper already; map ctl enum->netstat text
STATE_MAP={"ESTABLISHED":"ESTABLISHED","LISTEN":"LISTENING","SYNSENT":"SYN_SENT","SYNRECEIVED":"SYN_RECEIVED","FINWAIT1":"FIN_WAIT_1","FINWAIT2":"FIN_WAIT_2","TIMEWAIT":"TIME_WAIT","CLOSE":"CLOSED","CLOSEWAIT":"CLOSE_WAIT","LASTACK":"LAST_ACK","CLOSING":"CLOSING"}
ctl_tcp = Counter((a,b,c,d,STATE_MAP.get(s,s),pid) for a,b,c,d,s,pid in ctl_tcp.elements())

tcp_common = sum((ctl_tcp & ns_tcp_c).values())
tcp_only_ctl = sum((ctl_tcp - ns_tcp_c).values())
tcp_only_ns  = sum((ns_tcp_c - ctl_tcp).values())

ctl_udp = Counter((r["localIp"],r["localPort"],r["pid"]) for r in parsed if r["proto"]=="udp")
ns_udp_c = Counter(ns_udp)
udp_common = sum((ctl_udp & ns_udp_c).values())
udp_only_ctl = sum((ctl_udp - ns_udp_c).values())
udp_only_ns  = sum((ns_udp_c - ctl_udp).values())

print(f"TCP: outboundctl={sum(ctl_tcp.values())} netstat={sum(ns_tcp_c.values())} exact-match-rows={tcp_common} only-in-ctl={tcp_only_ctl} only-in-netstat={tcp_only_ns}")
if tcp_only_ctl or tcp_only_ns:
    print("  ctl-only sample:", list((ctl_tcp - ns_tcp_c).elements())[:5])
    print("  ns-only sample: ", list((ns_tcp_c - ctl_tcp).elements())[:5])
print(f"UDP: outboundctl={sum(ctl_udp.values())} netstat={sum(ns_udp_c.values())} exact-match-rows={udp_common} only-in-ctl={udp_only_ctl} only-in-netstat={udp_only_ns}")
if udp_only_ctl or udp_only_ns:
    print("  ctl-only sample:", list((ctl_udp - ns_udp_c).elements())[:5])
    print("  ns-only sample: ", list((ns_udp_c - ctl_udp).elements())[:5])
