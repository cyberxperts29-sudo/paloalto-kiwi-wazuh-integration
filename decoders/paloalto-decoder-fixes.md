# Fixing Wazuh's built-in Palo Alto decoder for PAN-OS 11

Wazuh ships `ruleset/decoders/0505-paloalto_decoders.xml`. On PAN-OS 11 (tested on
11.2, AWS PAYG VM-Series) it fails in three ways. The fix is to **override** the
built-in decoder with a patched copy:

1. In `ossec.conf`, inside `<ruleset>`:
   ```xml
   <decoder_exclude>ruleset/decoders/0505-paloalto_decoders.xml</decoder_exclude>
   ```
2. Copy the built-in file to `/var/ossec/etc/decoders/0505-paloalto_decoders.xml`
   and apply the three fixes below.
3. `chown wazuh:wazuh` + `chmod 660`, then restart the manager.

Tested on **Wazuh 4.14.7**.

---

## Bug 1 — Serial number is digits-only (`\d+`)

AWS PAYG VM-Series serials are alphanumeric (e.g. `4CA8C3D1088C4EA`). The decoder
matches the serial with `\d+`, so the whole log is rejected.

**Fix:** `\d+` → `\w+` for the serial-number field in every prematch/regex.
Related to upstream issue **#19675** (still present on `master`).

## Bug 2 — Commas inside quoted fields shift every later field

Fields like a SYSTEM description are quoted and may contain commas:
`"Connection to Update server ... completed, initiated by ..."`.
The decoder reads each field as `[^,]*`, which stops at the comma inside the
quotes, shifting all following fields.

**Fix:** make the affected field quote-aware:
```
("[^"]*"|[^,]*)
```
**Caveat:** applying this globally pushes the (very long) threat decoder past
Wazuh's regex-size limit and triggers `error 1104 (maximum regex string size)`,
and the manager will not start. Scope the change to only the fields that need it.

## Bug 3 — CONFIG decoder expects phantom fields

The CONFIG sub-decoder was written for PAN-OS 9/10, which send
`before-change-detail` and `after-change-detail` after `configuration-path`.
PAN-OS 11 does not send them, so every following field shifts by two
(`sequence_number`, `device_name`, timestamps all land wrong).

**Fix:**
- Remove `before_change_detail` and `after_change_detail` from the CONFIG
  field order.
- Make `configuration_path` quote-aware: `("[^"]*"|[^,]*)`.
- Read the tail fields (`device_name`, `high_resolution_timestamp`, `full_path`)
  **from the end of the line** instead of by position, so they can never shift:
  ```
  ,([^,]*),([^,]*),([^,]*),[^,]*,(\d{4}-\d{2}-\d{2}T[^,]*),(.*)$
  <order>device_name, device_group, audit_comment, high_resolution_timestamp, full_path</order>
  ```

## Verify

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a TRAFFIC, CONFIG and THREAT line; all fields should decode,
# and rules 110200 / 110213 / 110221 should fire.
```
