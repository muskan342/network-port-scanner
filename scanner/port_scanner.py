
import socket
import ipaddress


# STEP 1: Validate target IP address or hostname

def validate_target(target):

    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:

        try:
            socket.gethostbyname(target)
            return True

        except socket.gaierror:
            return False


# STEP 2: Validate port range

def validate_ports(start_port, end_port):

    if not (1 <= start_port <= 65535):
        return False

    if not (1 <= end_port <= 65535):
        return False

    if start_port > end_port:
        return False

    return True


# STEP 3: Identify commonly associated services

def identify_service(port):

    common_services = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MYSQL",
        5432: "POSTGRESQL",
        8080: "HTTP-ALT"
    }

    if port in common_services:
        return common_services[port]

    try:
        return socket.getservbyport(port, "tcp").upper()

    except OSError:
        return "UNKNOWN"


# STEP 4: Scan an individual TCP port

def scan_port(target, port):

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(0.5)

            result = sock.connect_ex((target, port))

            if result == 0:
                return True

            return False

    except socket.error:
        return False


# STEP 5: Scan the selected port range

def scan_target(target, start_port, end_port):

    open_ports = []

    print("\n" + "=" * 50)
    print("       NETWORK SECURITY SCANNER")
    print("=" * 50)

    print(f"Target: {target}")
    print(f"Port Range: {start_port}-{end_port}")

    print("-" * 50)

    for port in range(start_port, end_port + 1):

        if scan_port(target, port):

            service = identify_service(port)

            print(
                f"[OPEN] Port: {port} | "
                f"Service: {service}"
            )

            open_ports.append({
                "port": port,
                "service": service
            })

    print("-" * 50)

    print(f"Total Open Ports: {len(open_ports)}")

    print("Scan Completed!")

    print("=" * 50)

    return open_ports


# STEP 6: Main function

def main():

    target = input("Enter target IP or hostname: ").strip()

    if not validate_target(target):

        print("Invalid target. Please try again.")
        return

    try:

        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

    except ValueError:

        print("Please enter valid numeric ports.")
        return

    if not validate_ports(start_port, end_port):

        print("Invalid port range!")
        return

    scan_target(target, start_port, end_port)


# STEP 7: Execute program

if __name__ == "__main__":
    main()

