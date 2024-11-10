import psutil
import socket
import threading
from scapy.all import sniff, IP, TCP, send

class PortBlocker:
    def __init__(self):
        self.sockets = {}

    def block_port(self, port):
        if port in self.sockets:
            print(f"Port {port} is already blocked.")
            return

        try:
            # Create a socket and bind it to the specified port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            self.sockets[port] = s
            print(f"Port {port} is now blocked. Press Ctrl+C to unblock.")
            
            # Keep the socket open to block the port
            while True:
                conn, _ = s.accept()
                conn.close()
        except Exception as e:
            print(f"Failed to block port {port}: {e}")

    def unblock_port(self, port):
        if port in self.sockets:
            self.sockets[port].close()
            del self.sockets[port]
            print(f"Port {port} is now unblocked.")
        else:
            print(f"Port {port} is not currently blocked.")

def scan_processes_with_ports(name_filter):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'connections']):
        if name_filter.lower() in proc.info['name'].lower():
            for conn in proc.info['connections']:
                if conn.status == psutil.CONN_LISTEN:
                    processes.append((proc.info['name'], proc.info['pid'], conn.laddr.port))
    return processes

def block_ports_by_pid(pid, port_blocker):
    try:
        connections = psutil.net_connections(kind='inet')
        ports = [conn.laddr.port for conn in connections if conn.pid == pid and conn.status == psutil.CONN_LISTEN]
        if ports:
            print(f"Blocking ports: {ports}")
            for port in ports:
                block_thread = threading.Thread(target=port_blocker.block_port, args=(port,))
                block_thread.start()
        else:
            print(f"No listening ports found for process {pid}.")
    except psutil.NoSuchProcess:
        print(f"No process found with PID {pid}.")
    except Exception as e:
        print(f"Failed to block ports for process {pid}: {e}")

def close_localhost_sockets_by_pid(pid):
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.pid == pid and (conn.laddr.ip == '127.0.0.1' or conn.laddr.ip == '::1'):
                try:
                    # Send a TCP reset packet to close the connection
                    ip = IP(src=conn.laddr.ip, dst=conn.raddr.ip)
                    tcp = TCP(sport=conn.laddr.port, dport=conn.raddr.port, flags="R")
                    send(ip/tcp, verbose=0)
                    print(f"Closed socket on port {conn.laddr.port} for PID {pid}")
                except Exception as e:
                    print(f"Failed to close socket on port {conn.laddr.port} for PID {pid}: {e}")
    except psutil.NoSuchProcess:
        print(f"No process found with PID {pid}.")
    except Exception as e:
        print(f"Failed to close sockets for process {pid}: {e}")

def monitor_port(port):
    def packet_callback(packet):
        if packet.haslayer(TCP):
            if packet[TCP].sport == port or packet[TCP].dport == port:
                print(f"Packet: {packet.summary()}")
                print(f"Source IP: {packet[IP].src}, Source Port: {packet[TCP].sport}")
                print(f"Destination IP: {packet[IP].dst}, Destination Port: {packet[TCP].dport}")
                print(f"Payload: {bytes(packet[TCP].payload)}")

    print(f"Monitoring port {port}...")
    sniff(filter=f"tcp port {port}", prn=packet_callback, store=0)

def scan_sockets_in_port_range(start_port, end_port):
    active_sockets = []
    for conn in psutil.net_connections():
        if start_port <= conn.laddr.port <= end_port:
            active_sockets.append(conn)
    return active_sockets

def main_menu():
    port_blocker = PortBlocker()
    monitoring_thread = None
    while True:
        if monitoring_thread and monitoring_thread.is_alive():
            continue

        print("\nMenu:")
        print("1. Scan processes by name")
        print("2. Block a port")
        print("3. Unblock a port")
        print("4. Block all ports used by a process (by PID)")
        print("5. Monitor a port")
        print("6. Scan for all active sockets")
        print("7. Scan for sockets in a port range")
        print("8. Close all localhost sockets for a specific PID")
        print("9. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            name_filter = input("Enter the process name filter: ")
            matching_processes = scan_processes_with_ports(name_filter)
            if matching_processes:
                print(f"Found {len(matching_processes)} matching processes:")
                for name, pid, port in matching_processes:
                    print(f"Process Name: {name}, PID: {pid}, Port: {port}")
            else:
                print(f"No processes found matching the name '{name_filter}'")
        elif choice == '2':
            port_to_block = int(input("Enter the port number to block: "))
            block_thread = threading.Thread(target=port_blocker.block_port, args=(port_to_block,))
            block_thread.start()
        elif choice == '3':
            port_to_unblock = int(input("Enter the port number to unblock: "))
            port_blocker.unblock_port(port_to_unblock)
        elif choice == '4':
            pid_to_block_ports = int(input("Enter the PID of the process to block ports: "))
            block_ports_by_pid(pid_to_block_ports, port_blocker)
        elif choice == '5':
            port_to_monitor = int(input("Enter the port number to monitor: "))
            monitoring_thread = threading.Thread(target=monitor_port, args=(port_to_monitor,))
            monitoring_thread.start()
        elif choice == '6':
            print("Scanning for all active sockets...")
            for conn in psutil.net_connections():
                print(f"PID: {conn.pid}, Laddr: {conn.laddr}, Raddr: {conn.raddr}, Status: {conn.status}")
        elif choice == '7':
            start_port = int(input("Enter the start port number: "))
            end_port = int(input("Enter the end port number: "))
            active_sockets = scan_sockets_in_port_range(start_port, end_port)
            if active_sockets:
                print(f"Found {len(active_sockets)} active sockets in port range {start_port}-{end_port}:")
                for conn in active_sockets:
                    print(f"PID: {conn.pid}, Laddr: {conn.laddr}, Raddr: {conn.raddr}, Status: {conn.status}")
            else:
                print(f"No active sockets found in port range {start_port}-{end_port}.")
        elif choice == '8':
            pid_to_close_sockets = int(input("Enter the PID of the process to close localhost sockets: "))
            close_localhost_sockets_by_pid(pid_to_close_sockets)
        elif choice == '9':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()