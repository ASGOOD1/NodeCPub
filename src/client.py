# client.py - Clientul Alt 
# Permite aceleasi lucruri si trateaza aceleasi erori si comenzi ca si client.c
#
#
#
#


import hashlib
import os
import random
import select
import socket
import sys
import argparse

HOST        = "127.0.0.1"
PORT        = 8080
BUFFER_SIZE = 65536   
TIMEOUT_MS  = 10_000  

#Computare hash
def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Functii pentru citire cu timeout(select.poll)
def poll_readline(sock_file, timeout_ms: int = TIMEOUT_MS) -> str:
    poller = select.poll()
    poller.register(sock_file.fileno(), select.POLLIN)
    events = poller.poll(timeout_ms)
    if not events:
        print("[!] Timeout waiting for response.")
        return ""
    line = sock_file.readline()
    return line.decode(errors="ignore").strip() if line else ""

#Asemator (functia generata este mai stabila decat cea create de mine initial)
def poll_recv_bytes(sock_file, size: int,
                    timeout_ms: int = TIMEOUT_MS) -> bytes:
   
    poller = select.poll()
    poller.register(sock_file.fileno(), select.POLLIN)
    received = 0
    chunks   = []

    while received < size:
        events = poller.poll(timeout_ms)
        if not events:
            print(f"\n[!] Timeout download ({received}/{size} bytes).")
            break

        to_read = min(BUFFER_SIZE, size - received)
        chunk   = sock_file.read(to_read)
        if not chunk:
            print(f"\n[!] Connection closed at {received}/{size} bytes.")
            break

        chunks.append(chunk)
        received += len(chunk)
        pct = received * 100 // size if size else 100
        print(f"\rDownload: {received}/{size} bytes ({pct}%)",
              end="", flush=True)

    return b"".join(chunks)


def main():
    parser = argparse.ArgumentParser(description="Client for file management server")
    parser.add_argument("--host", default=HOST, help="Server IP address")
    parser.add_argument("-u", default=None, help="Username for registration")
    parser.add_argument("-p", default=None, help="Password for registration")
    args = parser.parse_args()
    host = args.host
    user_arg = args.u
    pw_arg   = args.p

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, PORT))
    except ConnectionRefusedError:
        print(f"[!] Connection error {host}:{PORT}")
        sys.exit(1)
    
    sock_file = sock.makefile("rb", buffering=BUFFER_SIZE)
    if(user_arg is not None and pw_arg is not None):
        user     = user_arg.strip()[:63]
        pw       = pw_arg.strip()[:63]
        hash_hex = sha256_hash(pw)

        sock.sendall(f"REGISTER {user} {hash_hex}\n".encode())
        resp = poll_readline(sock_file, timeout_ms=5_000)
        if not resp:
            print("[!] The server does not respond.")
            sock.close()
            sys.exit(1)
        if "OK" not in resp:
            print(f"Registration failed: {resp}")
            sock.close()
            sys.exit(1)
        print("Registration successful.")
    if(user_arg is None and pw_arg is not None):
        print("[!] Password provided without username.")
        sock.close()
        sys.exit(1)
    if(user_arg is not None and pw_arg is None):
        print("[!] Username provided without password.")
        sock.close()
        sys.exit(1)

    user     = input("User: ").strip()[:63]
    pw       = input("Parola: ").strip()[:63]
    hash_hex = sha256_hash(pw)


    #Trimitem comanda de login
    sock.sendall(f"LOGIN {user} {hash_hex}\n".encode())

    resp = poll_readline(sock_file, timeout_ms=5_000)
    if not resp:
        print("[!] The server does not respond.")
        sock.close()
        sys.exit(1)
    if "OK" not in resp:
        print(f"Login failed: {resp}")
        sock.close()
        sys.exit(1)

    print("Login successful.")
    #Activam modul de comenzi folosind select.poll pentru a astepta atat inputul utilizatorului, cat si raspunsurile serverului, fara blocare
    poller = select.poll()
    poller.register(sys.stdin.fileno(), select.POLLIN)
    poller.register(sock_file.fileno(),  select.POLLIN)

    running = True
    while running:
        print("\n> ", end="", flush=True)

        events = poller.poll()  

        for fd, event in events:
            #── Raspuns server ──
            if fd == sock_file.fileno():
                data = sock.recv(4096, socket.MSG_PEEK)
                if not data:
                    print("\n[!] Connection closed by the server.")
                    running = False
                    break
                msg = data.decode(errors="ignore").strip()

                if msg.startswith("SIZE"):
                    header = ""
                    while '\n' not in header:
                        chunk = sock.recv(1).decode(errors='ignore')
                        if not chunk:
                            print("Connection closed while reading header", file=sys.stderr)
                            break
                        header += chunk
                    
                    header = header.strip()
                    
                    if not header.startswith("SIZE "):
                        print(f"Server error: {header}")
                        continue
                    
                    try:
                        file_size = int(header.split()[1])
                    except (ValueError, IndexError):
                        print(f"Invalid SIZE header: {header}")
                        continue
                    
                    if file_size <= 0:
                        print(f"Invalid file size: {file_size}")
                        continue
                    
                    # Generate random filename
                    random_num = random.randint(1000, 99999)
                    local_file = f"downloaded_result_{random_num}.txt"
                
                    with open(local_file, 'wb') as f:
                        # Receive file data
                        received = 0
                        while received < file_size:
                            chunk_size = min(4096, file_size - received)
                            chunk = sock.recv(chunk_size)
                            if not chunk:
                                print("\nDownload failed - connection closed")
                                os.unlink(local_file)
                                break
                            f.write(chunk)
                            received += len(chunk)
                        else:
                            print(f"\nDownload completed: {local_file} ({file_size} bytes)")
                        
                else:
                    data = sock.recv(4096)
                    print(f"\n[server] {msg}")
                    
                if "you have been kicked" in msg.lower() or \
                   "server_shutdown"      in msg.lower():
                    running = False
                break  

            # ── Input utilizator ──
            if fd == sys.stdin.fileno():
                try:
                    cmd = input().strip().lower()
                except EOFError:
                    running = False
                    break

                if not cmd:
                    break

                # ── exit ──
                if cmd == "exit":
                    sock.sendall(b"LOGOUT\n")
                    running = False

                

                # ── download ──
               
                elif cmd == "download":
                    filename = input("File: ").strip()
                    sock.sendall(f"DOWNLOAD {filename}\n".encode())

                    header = poll_readline(sock_file)
                    if not header:
                        break
                    if not header.startswith("SIZE"):
                        print(f"[!] {header}")
                        break

                    try:
                        size = int(header.split()[1])
                    except (ValueError, IndexError) as e:
                        print(f"[!] Header Error: {e}")
                        break

                    data = poll_recv_bytes(sock_file, size)
                    print()

                    local = f"downloaded_result_{filename}.txt"
                    with open(local, "wb") as f:
                        f.write(data)

                    if len(data) >= size:
                        print(f"Download Complete: {local}")
                    else:
                        print(f"[!] Download Incomplete: {len(data)}/{size}")

                # ── stats ──
                elif cmd == "stats":
                    filename = input("File: ").strip()
                    sock.sendall(f"STATS {filename}\n".encode())
                    print(poll_readline(sock_file))

                elif cmd == "backup":
                    filename = input("Backup time: ").strip()
                    sock.sendall(f"BACKUP {filename}\n".encode())
                    print(poll_readline(sock_file))
                elif cmd == "cleanup":
                    filename = input("Cleanup time(files older than, will be deleted): ").strip()
                    sock.sendall(f"CLEANUP {filename}\n".encode())
                    print(poll_readline(sock_file))
                elif cmd == "size":
                    filename = input("Size format (B, KB, MB): ").strip()
                    sock.sendall(f"SIZE {filename}\n".encode())
                    print(poll_readline(sock_file))

                # ── scan ──
                elif cmd == "scan":
                    filepath = input("Local file: ").strip()
                    if not os.path.exists(filepath):
                        print(f"[!] '{filepath}' doesn't exist.")
                        break

                    filename = os.path.basename(filepath)
                    size     = os.path.getsize(filepath)
                    sock.sendall(f"SCAN {filename} {size}\n".encode())

                    sent = 0
                    with open(filepath, "rb") as f:
                        while sent < size:
                            chunk = f.read(BUFFER_SIZE)
                            if not chunk:
                                break
                            sock.sendall(chunk)
                            sent += len(chunk)
                            pct = sent * 100 // size if size else 100
                            print(f"\rUpload: {sent}/{size} bytes ({pct}%)",
                                  end="", flush=True)
                    print()

                    resp_line = poll_readline(sock_file)
                    print(resp_line)

                # ── list ──
                elif cmd == "list":
                    sock.sendall(b"LIST\n")
                    lines = []
                    while True:
                        line = poll_readline(sock_file)
                        if not line or "END_OF_LIST" in line:
                            break
                        lines.append(line)
                    print("\n".join(lines))

                else:
                    print(f"Unknown command: '{cmd}'")

                break  

    try:
        sock_file.close()
        sock.close()
    except Exception:
        pass
    print("Disconnected.")


if __name__ == "__main__":
    main()