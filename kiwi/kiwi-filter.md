# Kiwi Syslog Server — smart routing filter

Kiwi NG sits between the firewall and Wazuh as a relay. Without a filter it
forwards *everything*, including thousands of routine drop/allow events an hour
from Internet background scans.

Add a filter to the **Forward-to-Wazuh** rule so only security-relevant logs
reach the SIEM:

- **Field:** Message text
- **Filter type:** RegExp
- **Include:**
  ```
  (THREAT|CONFIG|,deny,|,drop,|reset-both)
  ```

This forwards THREAT, CONFIG and denied/dropped traffic, and drops routine
`allow` traffic and informational SYSTEM logs.

**Measured result (controlled test):** of every 6 representative logs, 6/6
reached Wazuh before the filter and 3/3 after — a consistent ~50% reduction,
with no loss of security-relevant events.

> Note: Kiwi strips the original syslog header (timestamp/hostname) when it
> forwards, so the Wazuh decoder keys off the message body, not the header.
