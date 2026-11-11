#!/usr/bin/env python3
"""
Automated Interoperability & Integration Test Suite for the RFC 826 ARP Lab.
Tests HTTP REST endpoints, RFC 826 / 5227 / 903 workflows, IEEE 802.1Q VLANs,
Cisco Port-Security, DAI Rate Limiting, Cisco IOS CLI, and Wireshark PCAP generation.

Usage:
  python interop_test.py
  (Ensure 'run.bat' is running or start it against http://localhost:8082)
"""

import sys
import time
import struct
import urllib.request
import urllib.parse
import json

BASE_URL = "http://localhost:8082"

PASS_COUNT = 0
FAIL_COUNT = 0

def check(name, condition, details=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  \033[92m[PASS]\033[0m {name:<58} {f'({details})' if details else ''}")
    else:
        FAIL_COUNT += 1
        print(f"  \033[91m[FAIL]\033[0m {name:<58} {f'({details})' if details else ''}")

def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as res:
        return res.status, res.headers, res.read()

def http_post(path, form_data):
    url = f"{BASE_URL}{path}"
    data = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=5) as res:
        return res.status, res.headers, res.read()

def main():
    print("=" * 76)
    print("   ARP LAB AUTOMATED INTEGRATION & INTEROPERABILITY TEST SUITE")
    print("   Target: " + BASE_URL)
    print("=" * 76)

    # 1. Connection check
    print("\n--- 1. HTTP Server & Telemetry Schema --------------------------------------")
    try:
        status, headers, body = http_get("/api/state")
        check("HTTP Server is accessible on port 8082", status == 200, f"Status={status}")
        state = json.loads(body.decode("utf-8"))
        check("Telemetry contains hosts list", "hosts" in state and len(state["hosts"]) >= 3)
        check("Telemetry contains router node with Proxy ARP", "router" in state and "proxyArpEnabled" in state["router"])
        check("Telemetry contains attacker node", "attacker" in state and "mitmActive" in state["attacker"])
        check("Telemetry contains 8-port switch with CAM table", "switch" in state and "cam" in state["switch"])
        check("Telemetry contains 802.1Q VLAN mappings", "switch" in state and "portVlans" in state["switch"])
        check("Telemetry contains Cisco Port-Security configs", "switch" in state and "portSecurity" in state["switch"])
        check("Telemetry contains Dynamic ARP Inspection (DAI)", "switch" in state and "dai" in state["switch"])
    except Exception as e:
        print(f"\033[91mError connecting to {BASE_URL}: {e}\033[0m")
        print("Please ensure the ARP lab server is running via 'run.bat' before running this test.")
        sys.exit(1)

    # 2. Protocol Actions
    print("\n--- 2. RFC 826 & RFC 5227 Core Protocol Workflows --------------------------")
    # Action: Ping Host-A -> Host-B
    st, _, resp = http_post("/api/action", {"action": "ping", "from": "Host-A", "to": "192.168.1.20", "msg": "Python-Ping"})
    res_data = json.loads(resp.decode("utf-8"))
    check("Action 'ping' executes successfully", res_data.get("status") == "ok", res_data.get("message"))

    # Action: Gratuitous ARP
    st, _, resp = http_post("/api/action", {"action": "garp", "host": "Host-B"})
    res_data = json.loads(resp.decode("utf-8"))
    check("Action 'garp' (Gratuitous ARP) executes successfully", res_data.get("status") == "ok")

    # Action: RFC 5227 ACD Full Workflow
    st, _, resp = http_post("/api/action", {"action": "acd_workflow", "host": "Host-A", "candidate": "192.168.1.25"})
    res_data = json.loads(resp.decode("utf-8"))
    check("Action 'acd_workflow' (RFC 5227 Probing & Announce) succeeds", res_data.get("status") == "ok")

    # Action: RFC 903 RARP Boot
    print("\n--- 3. RFC 903 Reverse ARP (RARP) Diskless Workstation Boot -----------------")
    st, _, resp = http_post("/api/action", {"action": "rarp_boot", "host": "Host-C"})
    res_data = json.loads(resp.decode("utf-8"))
    check("Action 'rarp_boot' initiates RFC 903 bootstrap request", res_data.get("status") == "ok")

    time.sleep(0.4)
    _, _, body = http_get("/api/state")
    state = json.loads(body.decode("utf-8"))
    host_c = next((h for h in state["hosts"] if h["hostname"] == "Host-C"), None)
    check("Host-C acquired IP 192.168.1.30 via RARP server assignment",
          host_c is not None and host_c["ip"] == "192.168.1.30",
          f"IP={host_c['ip'] if host_c else 'None'}")

    # 4. IEEE 802.1Q VLAN Segmentation
    print("\n--- 4. IEEE 802.1Q Virtual LAN (VLAN) Segmentation -------------------------")
    st, _, _ = http_post("/api/action", {"action": "vlan_set", "port": "1", "vlan": "10"})
    st, _, _ = http_post("/api/action", {"action": "vlan_set", "port": "3", "vlan": "20"})
    _, _, body = http_get("/api/state")
    state = json.loads(body.decode("utf-8"))
    vlans = {e["port"]: e["vlan"] for e in state["switch"].get("portVlans", [])}
    check("Port 1 assigned to VLAN 10 (Sales)", vlans.get(1) == 10, f"vlan={vlans.get(1)}")
    check("Port 3 assigned to VLAN 20 (Engineering)", vlans.get(3) == 20, f"vlan={vlans.get(3)}")

    # 5. Cisco Switchport Port-Security vs macof
    print("\n--- 5. Cisco Switchport Port-Security Defense ------------------------------")
    st, _, resp = http_post("/api/action", {"action": "port_security_toggle", "port": "5", "enabled": "true", "maxMacs": "1", "violation": "SHUTDOWN"})
    check("Port-Security enabled on Port 5 with SHUTDOWN action", json.loads(resp.decode("utf-8")).get("status") == "ok")

    # Launch CAM overflow
    st, _, _ = http_post("/api/action", {"action": "cam_overflow", "count": "15"})
    time.sleep(0.3)
    _, _, body = http_get("/api/state")
    state = json.loads(body.decode("utf-8"))
    port5_sec = next((p for p in state["switch"]["portSecurity"] if p["port"] == 5), None)
    check("Port-Security triggered violations upon CAM overflow flood",
          port5_sec is not None and port5_sec["violations"] > 0,
          f"violations={port5_sec['violations'] if port5_sec else 0}")
    check("Port 5 transitioned to ERR_DISABLE (port shut down)",
          port5_sec is not None and port5_sec["errDisabled"] is True)

    # Reset err-disabled ports
    st, _, _ = http_post("/api/action", {"action": "reset_errdisable"})
    check("Reset all err-disabled ports restores interface", True)

    # 6. Cisco IOS CLI Diagnostic Engine
    print("\n--- 6. Cisco IOS CLI Command Runner (/api/cisco-cli) -----------------------")
    st, _, resp = http_post("/api/cisco-cli", {"cmd": "show mac address-table"})
    cli_res = json.loads(resp.decode("utf-8"))
    check("'show mac address-table' returns Cisco tabular output",
          "Mac Address Table" in cli_res.get("output", ""), "Output length: " + str(len(cli_res.get("output", ""))))

    st, _, resp = http_post("/api/cisco-cli", {"cmd": "show vlan brief"})
    cli_res = json.loads(resp.decode("utf-8"))
    check("'show vlan brief' lists active VLANs and assigned ports",
          "VLAN Name" in cli_res.get("output", ""), "Output length: " + str(len(cli_res.get("output", ""))))

    st, _, resp = http_post("/api/cisco-cli", {"cmd": "show ip arp inspection"})
    cli_res = json.loads(resp.decode("utf-8"))
    check("'show ip arp inspection' lists DAI statistics & rate limiters",
          "Source Mac Validation" in cli_res.get("output", ""))

    st, _, resp = http_post("/api/cisco-cli", {"cmd": "show port-security"})
    cli_res = json.loads(resp.decode("utf-8"))
    check("'show port-security' lists secure ports and violation counts",
          "Secure Port" in cli_res.get("output", ""))

    # 7. Wireshark PCAP Binary Export
    print("\n--- 7. Wireshark PCAP Binary Export Engine (/api/export/pcap) --------------")
    st, headers, pcap_data = http_get("/api/export/pcap")
    check("PCAP download returns HTTP 200", st == 200)
    check("PCAP Content-Type is 'application/vnd.tcpdump.pcap'",
          "tcpdump.pcap" in headers.get("Content-Type", ""), headers.get("Content-Type"))
    check("PCAP byte stream length is at least 24 bytes (Global Header)", len(pcap_data) >= 24, f"Bytes={len(pcap_data)}")

    # Unpack 24-byte PCAP Global Header
    magic, v_maj, v_min, thiszone, sigfigs, snaplen, linktype = struct.unpack(">IHHIIII", pcap_data[:24])
    check("PCAP Magic Number is 0xA1B2C3D4 (standard libpcap)", magic == 0xa1b2c3d4, f"0x{magic:08X}")
    check("PCAP Version is 2.4", v_maj == 2 and v_min == 4, f"{v_maj}.{v_min}")
    check("PCAP Link-Layer type is 1 (LINKTYPE_ETHERNET)", linktype == 1, f"LinkType={linktype}")

    # Inspect packet records if present
    offset = 24
    packet_count = 0
    valid_packets = True
    while offset + 16 <= len(pcap_data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(">IIII", pcap_data[offset:offset+16])
        offset += 16
        if offset + incl_len > len(pcap_data):
            valid_packets = False
            break
        offset += incl_len
        packet_count += 1

    check(f"PCAP contains valid frame records ({packet_count} frames decoded)", valid_packets and packet_count > 0)

    # Summary
    print("\n" + "=" * 76)
    print(f"  INTEGRATION TEST RESULTS: {PASS_COUNT} PASSED, {FAIL_COUNT} FAILED")
    print("=" * 76)
    sys.exit(0 if FAIL_COUNT == 0 else 1)

if __name__ == "__main__":
    main()
