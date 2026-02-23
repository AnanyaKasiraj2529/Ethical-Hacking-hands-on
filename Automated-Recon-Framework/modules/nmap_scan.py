import nmap

def run_nmap(target):
    scanner = nmap.PortScanner()

    # Advanced scan
    scanner.scan(target, arguments='-sV -sC --script vuln')

    results = {}

    for host in scanner.all_hosts():
        host_data = {
            "state": scanner[host].state(),
            "protocols": {}
        }

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            proto_data = {}

            for port in ports:
                port_info = scanner[host][proto][port]
                proto_data[port] = {
                    "state": port_info.get("state"),
                    "service": port_info.get("name"),
                    "version": port_info.get("version"),
                    "product": port_info.get("product"),
                    "extrainfo": port_info.get("extrainfo"),
                    "script": port_info.get("script", {})
                }

            host_data["protocols"][proto] = proto_data

        results[host] = host_data

    return results
