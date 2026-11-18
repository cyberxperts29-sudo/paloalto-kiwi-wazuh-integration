# Palo Alto + Kiwi Syslog + Wazuh: decoder fixes, detection rules & auto-block

A full detection-and-response pipeline for **Palo Alto PAN-OS 11** on AWS:

- **Patched Palo Alto decoder** — fixes 3 bugs that break Wazuh's built-in decoder on PAN-OS 11.
- **Custom rules** (IDs 110200+) — port-scan, config-tampering and exploit detection, MITRE ATT&CK mapped.
- **Active Response** — Wazuh auto-blocks attackers on the firewall through the Palo Alto API (Dynamic Address Groups).
- **Kiwi relay filter** — smart routing that cuts ~50% of the noise before it reaches the SIEM.

Tested on **Wazuh 4.14.7** and **PAN-OS 11.2**.

```
Attacker → Palo Alto VM-Series → Kiwi Syslog (filter) → Wazuh (decode + correlate)
                ▲                                                     │
                └──────── Palo Alto API ◄── Active Response ◄─────────┘
                         (tag IP → Dynamic Address Group → blocked)
```

## Why

Most "firewall + SIEM" guides stop at "point syslog at Wazuh." On a modern
Palo Alto the events don't parse, land under the wrong fields, or bury you in
noise. This repo makes the pipeline actually work — and then makes it respond.

## What's inside

| Path | What it does |
| --- | --- |
| `decoders/paloalto-decoder-fixes.md` | The 3 decoder bugs and the exact regex fixes |
| `rules/paloalto_custom_rules.xml` | 12 rules (110200–110222), MITRE ATT&CK mapped |
| `active-response/paloalto-block.py` | Tags the attacker IP via the Palo Alto User-ID API |
| `active-response/paloalto_api.conf.example` | Config template (credentials stay out of the script) |
| `active-response/ossec.conf.snippet.xml` | Syslog listener + Active Response wiring |
| `kiwi/kiwi-filter.md` | The Kiwi smart-routing filter + measured results |

## Detection rules

| Rule | Level | Detects | MITRE |
| --- | --- | --- | --- |
| 110201 | 5 | Probe on SSH/Telnet/SMB/RDP/VNC/SQL | T1046 |
| 110202 | 10 | 15 ports in 60s from one IP = port scan | T1046 |
| 110211 | 5 | Successful config change | T1562.004 |
| 110213 | 10 | Security-critical setting changed (rules, log-forwarding, zone-protection) | T1562.004 |
| 110214 | 12 | Logging config deleted — possible log tampering | T1562.006 |
| 110220 | 12 | Critical vulnerability exploit blocked | T1190 |
| 110221 | 13 | Exploit against a public-facing app from the Internet | T1190 |
| 110222 | 14 | Repeated exploit attempts = active attacker | T1190 |

## Install

### 1. Palo Alto → send logs to Kiwi
*Device → Server Profiles → Syslog* → add the Kiwi server (UDP 514), then attach
it under *Device → Log Settings* (System, Config) and in your security rules'
*Log Forwarding* profile (Traffic, Threat).

### 2. Kiwi → forward (and filter) to Wazuh
Create a **Forward-to-Wazuh** rule that sends to the Wazuh manager (UDP 514), then
add the filter in [`kiwi/kiwi-filter.md`](kiwi/kiwi-filter.md).

### 3. Wazuh → decoder + rules
Follow [`decoders/paloalto-decoder-fixes.md`](decoders/paloalto-decoder-fixes.md), then:
```bash
sudo cp rules/paloalto_custom_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/paloalto_custom_rules.xml
sudo chmod 660 /var/ossec/etc/rules/paloalto_custom_rules.xml
```
Add the `<remote>` block from the snippet to `ossec.conf`, restart, and test with `wazuh-logtest`.

### 4. Auto-block (optional)
On the Palo Alto: create a tag `wazuh-blocked`, a **Dynamic Address Group**
`Wazuh-Blocked` matching `'wazuh-blocked'`, and a top-of-list security policy that
denies that group. Generate an API key. Then on Wazuh:
```bash
sudo cp active-response/paloalto-block.py /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/paloalto-block.py
sudo chmod 750 /var/ossec/active-response/bin/paloalto-block.py

sudo cp active-response/paloalto_api.conf.example /var/ossec/etc/paloalto_api.conf
sudo nano /var/ossec/etc/paloalto_api.conf      # fill in firewall IP + API key
sudo chown root:wazuh /var/ossec/etc/paloalto_api.conf
sudo chmod 640 /var/ossec/etc/paloalto_api.conf
```
Add the `<command>` and `<active-response>` blocks from the snippet, then restart.

## Safety

- Private and whitelisted IPs are never blocked.
- Every block carries a 1-hour timeout and auto-expires.
- Credentials live in a separate config file, never in the script.
- **Before production:** use a dedicated least-privilege API account, a trusted TLS certificate (`verify_tls=yes`), never expose the management interface to the Internet, and review auto-blocks.

## Write-up

Full walkthrough on Medium (2 parts): decoder fixes & detection, then auto-block & smart routing — *MEDIUM_LINK*

## Author

Muhammad Ahmad Abid — SOC Analyst. Feedback, issues and PRs welcome.

## License

GPL-2.0, the same licence as the Wazuh ruleset.
