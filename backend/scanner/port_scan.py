import socket

def scan_ports(target):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass

    return open_ports
