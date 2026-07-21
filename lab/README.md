# SENTINEL Live-Traffic Validation Lab

Step 1 toward real server-level deployment: a VirtualBox lab where the
Windows host (standing in for "the protected server") watches live traffic
from an attacker VM and a benign-traffic VM, and the existing trained model
detects attacks in real time — detection + logging/alerting only, no active
blocking yet.

## 1. Network topology

Each VM gets **two adapters**:

- **Adapter 1 — VirtualBox Host-Only Network** (`192.168.56.0/24`). This is
  the lab network — the only traffic the host captures. VirtualBox assigns
  the host itself `192.168.56.1` on this adapter automatically.
- **Adapter 2 — NAT** (VirtualBox's built-in per-VM NAT). Used only to
  install tools (`apt install nmap hydra hping3 slowhttptest curl`) and
  update the VM. Traffic here is isolated per VM and never reaches the
  host-only adapter, so it never pollutes captures.

Static IPs (deterministic `src_ip` in logs beats DHCP for this):

| Role | Host-only IP |
|---|---|
| Windows host (capture point, "the server") | `192.168.56.1` |
| Attacker VM (Kali or similar) | `192.168.56.10` |
| Benign-traffic VM | `192.168.56.20` |

Set the static IP inside each VM on the host-only interface (e.g. on
Debian/Kali: edit `/etc/network/interfaces` or use `nmcli`/Network Manager
GUI), matching the table above. Leave the NAT adapter on DHCP.

This mirrors the long-term goal directly: the host stands in for the
protected server now; moving to a real deployment later only changes which
interface Scapy binds to (a real NIC in promiscuous mode instead of this
host-only virtual adapter) and the BPF filter — nothing else changes.

## 2. Windows host prerequisites

- **Npcap** — required for Scapy to capture packets on Windows. Install
  from [npcap.com](https://npcap.com/) with **"Install Npcap in WinPcap
  API-compatible Mode"** checked.
- **Administrator shell** — run `sentinel.py live` (and the M2/M3 smoke
  tests below) from an elevated PowerShell/terminal, unless Npcap was
  installed with **"Restrict Npcap driver's access to Administrators
  only"** unchecked.
- Resolve the Npcap device name for the VirtualBox host-only adapter:

  ```python
  from scapy.arch.windows import get_windows_if_list
  for iface in get_windows_if_list():
      print(iface["name"], "|", iface["description"])
  ```

  Look for the entry whose description contains "VirtualBox Host-Only
  Ethernet Adapter" (the name may be suffixed, e.g. "Adapter #2", if you
  already had one from a prior VirtualBox install). Use the matching
  `name` string as `--interface` below.

## 3. Milestones

Run these in order — each is independently verifiable before moving on.
None of them pass `--enforce-blocks`, so no OS firewall rule is ever
applied; detections are logged/alerted/blacklisted-to-file only.

### M1 — Lab network reachable

From each VM: `ping 192.168.56.1` (the host) and `ping` the other VM.
From the host: `ping 192.168.56.10` and `ping 192.168.56.20`.
Confirm the host-only adapter is up:

```powershell
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*VirtualBox*" }
```

### M2 — Host captures live packets from VM traffic

No new code — smoke-test the existing packet logger directly:

```python
from forensics.packet_logger import PacketLogger
logger_ = PacketLogger()
logger_.start_live_capture(interface="<resolved Npcap name>",
                            bpf_filter="net 192.168.56.0/24")
# generate ping/curl traffic from a VM, then:
print(logger_.summary())
```

Confirm `packet_count > 0` and a new file appears under `pcap/`.

### M3 — FlowCollector assembles one known flow correctly

Start the target service on the host:

```
python lab\target_service.py --host 192.168.56.1 --port 80
```

From the benign VM: `curl http://192.168.56.1/`

Verify with a short script:

```python
from scapy.utils import rdpcap
from core.flow_collector import FlowCollector

collector = FlowCollector()
for pkt in rdpcap("pcap/<the M2 capture file>.pcap"):
    collector.ingest_packet(pkt)
df = collector.flush_all()
print(df[["destination_port", "total_fwd_packets", "total_backward_packets",
          "syn_flag_count", "fin_flag_count", "flow_duration"]])
```

Expect exactly one row with `destination_port == 80`, `syn_flag_count >= 1`,
`fin_flag_count >= 1`, and forward/backward packet counts that match the
curl request by eye.

### M4 — Single attack type detected

```
python sentinel.py live --interface "<resolved Npcap name>" --model models\benchmarkids_binary.pkl
```

From the attacker VM: `nmap -sS 192.168.56.1`

Tail `logs\sentinel.log` and confirm flows from `192.168.56.10` show
`attack_class=PortScan` (or `ATTACK` if the multiclass model isn't loaded)
with a MITRE `T1046` mapping, while concurrent `curl`/ping traffic from the
benign VM stays classified benign.

**Run order matters for this milestone**: start the benign VM's traffic a
minute or two *before* the attacker VM. `SentinelIPS._run_anomaly()` fits
its IsolationForest baseline on the first ~100-flow batch it sees — letting
clean traffic accumulate first keeps that baseline uncontaminated by attack
flows.

### M5 — Mixed concurrent benign + attack, end-to-end sanity

Run for 5-10 minutes with the benign VM's traffic (curl loop / browsing)
plus 2-3 more attack types from the attacker VM:

- `hping3 -S --flood -p 80 192.168.56.1` (DoS/DDoS-style flood)
- `hydra -l admin -P wordlist.txt 192.168.56.1 http-post-form "/login:username=^USER^&password=^PASS^:invalid"` (BruteForce)
- `curl "http://192.168.56.1/search?q=' OR '1'='1"` (SQLi-shaped payload string)

On `Ctrl+C`, confirm:
- `ips.summary()` banner shows sane flow/attack/fps totals.
- `logs\sentinel.log` shows a correct mix of benign and attack entries.
- `pcap\` has forensic frames for the detected attacks.
- `threat_intel\ip_blacklist.txt` picked up `192.168.56.10` (passive
  record-keeping from the response layer — confirms the log-only wiring
  works).
- `Get-NetFirewallRule -DisplayName "SENTINEL_BLOCK*"` returns **nothing**,
  proving no active block fired — this step is detect-and-log only by
  design. Active countermeasures are the next step after this lab passes.
