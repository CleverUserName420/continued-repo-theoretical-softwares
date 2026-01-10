import os
import sys
import json
import re
import csv
import datetime
from collections import defaultdict

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]

def parse_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    if not m:
        return None
    return tuple(map(int, m.groups()))

def get_16_prefix(ip):
    parsed = parse_ip(ip)
    if not parsed:
        return None
    return f"{parsed[0]}.{parsed[1]}"

def get_24_prefix(ip):
    parsed = parse_ip(ip)
    if not parsed:
        return None
    return f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

def load_iocs_from_py(py_path):
    scope = {}
    with open(py_path, "r") as f:
        exec(f.read(), scope)
    ioc_dicts = [v for v in scope.values() if isinstance(v, dict)]
    if not ioc_dicts:
        print(f"[ERROR] No dictionaries found in {py_path}.")
        return {}, set()
    ioc_dict = max(ioc_dicts, key=lambda x: len(x))
    iocs = set()
    ioc_detail = {}
    for k in ioc_dict.keys():
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", k):
            iocs.add(k.strip())
            ioc_detail[k.strip()] = (ioc_dict[k], "py", py_path)
        elif isinstance(ioc_dict[k], dict) and "IP_Address" in ioc_dict[k]:
            ip = ioc_dict[k]["IP_Address"]
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                iocs.add(ip.strip())
                ioc_detail[ip.strip()] = (ioc_dict[k], "py", py_path)
    print(f"[DEBUG] Loaded {len(iocs)} IPs from {os.path.basename(py_path)}")
    return ioc_detail, iocs

def load_iocs_from_json(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    iocs = set()
    ioc_detail = {}
    for entry_list in data.values():
        for entry in entry_list:
            ioc_val = entry.get("ioc_value")
            if not ioc_val:
                continue
            ip_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", ioc_val)
            if ip_match:
                ip = ip_match.group(1).strip()
                iocs.add(ip)
                if ip not in ioc_detail:
                    ioc_detail[ip] = []
                ioc_detail[ip].append((entry, "json", json_path))
    print(f"[DEBUG] Loaded {len(iocs)} IPs from {os.path.basename(json_path)}")
    return ioc_detail, iocs

def load_iocs_from_txt(txt_path):
    with open(txt_path, "r") as f:
        lines = [line.strip() for line in f if re.match(r"\d{1,3}(?:\.\d{1,3}){3}", line)]
    iocs = set()
    ioc_detail = {}
    for line in lines:
        ip_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
        if ip_match:
            ip = ip_match.group(1).strip()
            iocs.add(ip)
            ioc_detail[ip] = ({"ioc_value": line}, "txt", txt_path)
    print(f"[DEBUG] Loaded {len(iocs)} IPs from {os.path.basename(txt_path)}")
    return ioc_detail, iocs

def print_ioc_full(ip, iocdict_py, iocdict_json, iocdict_txt):
    results = []
    if ip in iocdict_py:
        print("  [*] IOC from Python IOC file:")
        print(f"    src: {iocdict_py[ip][2]}")
        print(json.dumps(iocdict_py[ip][0], indent=2, default=str))
        results.append((iocdict_py[ip][0], "py", iocdict_py[ip][2]))
    if ip in iocdict_json:
        for idx, (val, _, path) in enumerate(iocdict_json[ip]):
            label = f" [#{idx+1}]" if len(iocdict_json[ip]) > 1 else ""
            print(f"  [*] IOC from JSON IOC file{label}:")
            print(f"    src: {path}")
            print(json.dumps(val, indent=2, default=str))
            results.append((val, "json", path))
    if ip in iocdict_txt:
        print("  [*] IOC from TXT IOC file:")
        print(f"    src: {iocdict_txt[ip][2]}\n    value: {iocdict_txt[ip][0]['ioc_value']}")
        results.append((iocdict_txt[ip][0], "txt", iocdict_txt[ip][2]))
    return results

def main():
    ioc_files = []
    print("Enter the filepaths for your IOC lists (supports .json, .py, .txt).")
    while True:
        path = input("Enter IOC file path: ").strip()
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            print("File does not exist. Try again.")
            continue
        ioc_files.append(path)
        again = input("Add another IOC file? (y/n): ").strip().lower()
        if again != 'y':
            break

    ip_file = None
    while not ip_file:
        path = input("\nEnter file path containing IP addresses to check: ").strip()
        path = os.path.expanduser(path)
        if os.path.exists(path):
            ip_file = path
        else:
            print("File not found. Try again.")

    proceed = input("Proceed with match analysis? (y/n): ").strip().lower()
    if proceed != "y":
        print("Exiting.")
        return

    # --- Loading IOC data dynamically
    all_ioc_ips = set()
    iocdict_py, iocdict_json, iocdict_txt = {}, {}, {}

    for f in ioc_files:
        ext = os.path.splitext(f)[-1].lower()
        if ext == ".py":
            part, ips = load_iocs_from_py(f)
            iocdict_py.update(part)
            all_ioc_ips.update(ips)
        elif ext == ".json":
            part, ips = load_iocs_from_json(f)
            for k, v in part.items():
                if k not in iocdict_json:
                    iocdict_json[k] = []
                iocdict_json[k].extend(v)
            all_ioc_ips.update(ips)
        elif ext == ".txt":
            part, ips = load_iocs_from_txt(f)
            iocdict_txt.update(part)
            all_ioc_ips.update(ips)
        else:
            print(f"Unsupported extension for file: {f}. Skipping.")

    ioc_by_16 = defaultdict(set)
    ioc_by_24 = defaultdict(set)
    for ip in all_ioc_ips:
        pfx16 = get_16_prefix(ip)
        pfx24 = get_24_prefix(ip)
        if pfx16:
            ioc_by_16[pfx16].add(ip)
        if pfx24:
            ioc_by_24[pfx24].add(ip)

    # Load candidate input IPs
    with open(ip_file, "r") as f:
        input_ips = set()
        for line in f:
            ip = line.strip().split(":")[0]
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                input_ips.add(ip)

    print(f"\n[DEBUG] Total unique IOCs loaded from all sources: {len(all_ioc_ips)}")
    print(f"[DEBUG] IPs to check: {len(input_ips)}")

    matched = input_ips.intersection(all_ioc_ips)
    not_matched = input_ips - matched

    print("\nMatched (EXACT):")
    for ip in sorted(matched):
        print(ip)
        print_ioc_full(ip, iocdict_py, iocdict_json, iocdict_txt)

    print("\nMatched (/24 - first 3 octets match, last differs):")
    partial_24_hits = []
    for ip in sorted(not_matched):
        prefix = get_24_prefix(ip)
        candidates = [ioc_ip for ioc_ip in ioc_by_24.get(prefix, set()) if ioc_ip != ip]
        if candidates:
            print(f"{ip} ~ {', '.join(sorted(candidates))}  [same /24 prefix]")
            partial_24_hits.append(ip)
            for hit_ip in candidates:
                print_ioc_full(hit_ip, iocdict_py, iocdict_json, iocdict_txt)

    print("\nFuzzy/Similar matches ('same /16' OR typo):")
    fuzzy_hits = []
    for ip in sorted(not_matched - set(partial_24_hits)):
        prefix = get_16_prefix(ip)
        got_fuzzy = False
        candidates = ioc_by_16[prefix] if prefix in ioc_by_16 else set()
        for ioc_ip in candidates:
            if levenshtein(ip, ioc_ip) <= 2 and ip != ioc_ip:
                print(f"{ip} ~ {ioc_ip}   [levenshtein, /16]")
                fuzzy_hits.append(ip)
                print_ioc_full(ioc_ip, iocdict_py, iocdict_json, iocdict_txt)
                got_fuzzy = True
                break
        if not got_fuzzy and candidates:
            ioc_ip = next(iter(candidates))
            print(f"{ip} ~ {ioc_ip}   [same /16]")
            fuzzy_hits.append(ip)
            print_ioc_full(ioc_ip, iocdict_py, iocdict_json, iocdict_txt)

    print("\n--- Summary ---")
    print(f"Exact matches: {len(matched)}")
    print(f"/24 partial matches (first 3 octets): {len(partial_24_hits)}")
    print(f"Fuzzy/similar matches: {len(fuzzy_hits)}")
    print(f"Total inputs checked: {len(input_ips)}")

if __name__ == "__main__":
    main()
