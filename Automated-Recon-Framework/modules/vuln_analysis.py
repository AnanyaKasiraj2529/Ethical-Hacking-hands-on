import re

def extract_cves(nmap_data):
    cves = []

    for host in nmap_data.values():
        for proto in host.get("protocols", {}).values():
            for port_data in proto.values():
                scripts = port_data.get("script", {})

                for output in scripts.values():
                    found = re.findall(r'CVE-\d{4}-\d+', str(output))
                    cves.extend(found)

    return list(set(cves))


def calculate_risk_score(open_ports, cves):
    score = 0

    score += len(open_ports) * 2
    score += len(cves) * 5

    if 22 in open_ports:
        score += 3
    if 80 in open_ports or 443 in open_ports:
        score += 2

    if score < 5:
        return "Low"
    elif score < 15:
        return "Medium"
    else:
        return "High"
