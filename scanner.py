import socket
import argparse


def scan_tcp(ip, port):
    result = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            service = socket.getservbyport(port)
            result = f"TCP Port {port} is open - Service: {service}"
    except socket.error as e:
        result = f"TCP Port {port} is closed - {e}"
    return result


def scan_udp(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.sendto(b'', (ip, port))
            service = socket.getservbyport(port, 'udp')
            return f"UDP Port {port} is open - Service: {service}"
    except (socket.error, socket.timeout):
        return f"UDP Port {port} is closed"


def scan_ip_range(ip, mask, ports, results):
    subnet_mask = 32 - mask
    base_ip = ip.split('.')[:-1]  # Get the first three octets of the IP address

    for ip_suffix in range(1, 2 ** subnet_mask):
        current_ip = "{}.{}".format('.'.join(base_ip), ip_suffix)
        for port in ports:
            result = scan_tcp(current_ip, port)
            results.append(f"{current_ip}: {result}")
            result = scan_udp(current_ip, port)
            results.append(f"{current_ip}: {result}")


def scan_ports(port_type, start_port, end_port, results):
    if port_type == 'tcp':
        scanner_func = scan_tcp
    elif port_type == 'udp':
        scanner_func = scan_udp
    else:
        raise ValueError("Invalid port type. Use 'tcp' or 'udp'.")

    for port in range(start_port, end_port + 1):
        results.append(scanner_func("192.168.1.1", port))


def main():
    parser = argparse.ArgumentParser(description="Network Scanning Tool")

    # IP Scan
    parser.add_argument('--ipscan', '-i', action='store_true', help="IP scan mode")
    parser.add_argument('--m', '-m', type=int, help="Subnet mask (e.g., 24)")
    parser.add_argument('--ip', '-ip', nargs='+', help="IP addresses to scan")

    # Port Scan
    parser.add_argument('-portscan', '-p', action='store_true', help="Port scan mode")
    parser.add_argument('--tcp', '-tcp', nargs=2, type=int, help="TCP port range (e.g., 1 1000)")
    parser.add_argument('--udp', '-udp', nargs=2, type=int, help="UDP port range (e.g., 1 1000)")

    args = parser.parse_args()

    results = []

    if args.ipscan:
        if args.m is None or args.ip is None:
            print("For IP scanning, both --m and --ip arguments are required.")
        else:
            ports = range(1, 100)  # Specify your default port range
            for ip in args.ip:
                scan_ip_range(ip, args.m, ports, results)

    elif args.portscan:
        if args.tcp is not None:
            start_port, end_port = args.tcp
            scan_ports('tcp', start_port, end_port, results)

        if args.udp is not None:
            start_port, end_port = args.udp
            scan_ports('udp', start_port, end_port, results)

    for result in results:
        print(result)

    with open("C:\\scan_results_ip.txt", "w") as file:
        for result in results:
            file.write(result + "\n")


if __name__ == "__main__":
    main()
