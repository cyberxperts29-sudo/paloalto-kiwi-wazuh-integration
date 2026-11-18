#!/usr/bin/env python3
import sys, json, ipaddress, configparser, urllib.parse, urllib.request, ssl, time

CONF = "/var/ossec/etc/paloalto_api.conf"
LOG  = "/var/ossec/logs/active-responses.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(time.strftime("%Y/%m/%d %H:%M:%S") + " paloalto-block: " + msg + "\n")

def skip_ip(ip, whitelist):
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return o.is_private or o.is_loopback or o.is_reserved or o.is_multicast or ip in whitelist

def panos(fw, key, vsys, ip, tag, timeout, action, verify):
    if action == "add":
        inner = f'<register><entry ip="{ip}"><tag><member timeout="{timeout}">{tag}</member></tag></entry></register>'
    else:
        inner = f'<unregister><entry ip="{ip}"><tag><member>{tag}</member></tag></entry></unregister>'
    payload = f'<uid-message><version>2.0</version><type>update</type><payload>{inner}</payload></uid-message>'
    params = urllib.parse.urlencode({"type":"user-id","key":key,"vsys":vsys,"cmd":payload})
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(f"https://{fw}/api/?{params}", context=ctx, timeout=10) as r:
        return r.read().decode()

def main():
    raw = sys.stdin.readline()
    if not raw:
        sys.exit(0)
    data = json.loads(raw)
    command = data.get("command")
    adata = data.get("parameters", {}).get("alert", {}).get("data", {})
    ip = adata.get("source_address") or adata.get("srcip")
    if not ip:
        log("no source IP in alert, skipping"); sys.exit(0)

    c = configparser.ConfigParser(); c.read(CONF); s = c["paloalto"]
    whitelist = [x.strip() for x in s.get("whitelist", "").split(",") if x.strip()]
    if skip_ip(ip, whitelist):
        log(f"{ip} private/whitelisted, skip"); sys.exit(0)

    action = "add" if command == "add" else "delete"
    try:
        resp = panos(s.get("firewall"), s.get("api_key"), s.get("vsys","vsys1"),
                     ip, s.get("tag","wazuh-blocked"), s.get("tag_timeout","3600"),
                     action, s.getboolean("verify_tls", fallback=False))
        if 'status="success"' in resp:
            log(f"{action} {ip} tag={s.get('tag')} -> SUCCESS")
        else:
            log(f"{action} {ip} -> UNEXPECTED {resp[:150]}")
    except Exception as e:
        log(f"{action} {ip} -> ERROR {e}")

if __name__ == "__main__":
    main()
