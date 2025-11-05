#!/usr/bin/env python3
"""
TLS + Authentication file server
Supports: AUTH, LIST, DOWNLOAD <filename>, UPLOAD <filename>, QUIT
"""

import socket
import ssl
import os

HOST = '0.0.0.0'
PORT = 9999
SHARED_DIR = 'shared_files'
RECV_DIR = 'received_uploads'
USERS_FILE = 'users.txt'
CERTFILE = 'server_cert.pem'
KEYFILE = 'server_key.pem'
CHUNK_SIZE = 4096

def load_users(path=USERS_FILE):
    users = {}
    if not os.path.isfile(path):
        return users
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
            username, pwd = line.split(':', 1)
            users[username] = pwd
    return users

def recv_exact(conn, nbytes):
    received = bytearray()
    while len(received) < nbytes:
        chunk = conn.recv(min(CHUNK_SIZE, nbytes - len(received)))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)

def send_all(conn, data: bytes):
    total = 0
    while total < len(data):
        sent = conn.send(data[total:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total += sent

def handle_authenticated(conn, addr):
    """After authentication -> same commands as before."""
    print(f"[+] Secured session for {addr}")
    try:
        while True:
            data = conn.recv(2048)
            if not data:
                print("[-] Client disconnected")
                break
            text = data.decode(errors='ignore').strip()
            print("Command:", text)

            if text.upper() == "LIST":
                try:
                    files = os.listdir(SHARED_DIR)
                except FileNotFoundError:
                    files = []
                response = "|".join(files)
                send_all(conn, response.encode())

            elif text.upper().startswith("DOWNLOAD "):
                _, filename = text.split(" ", 1)
                path = os.path.join(SHARED_DIR, filename)
                if not os.path.isfile(path):
                    send_all(conn, b"NOTFOUND")
                    continue
                filesize = os.path.getsize(path)
                send_all(conn, f"SIZE {filesize}".encode())
                ack = conn.recv(1024).decode().strip()
                if ack != "READY":
                    print("Client not ready (download), got:", ack)
                    continue
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        send_all(conn, chunk)
                print(f"[+] Sent file {filename}")

            elif text.upper().startswith("UPLOAD "):
                # this expects header possibly split; be tolerant
                lines = text.splitlines()
                _, filename = lines[0].split(" ", 1)
                filesize = None
                if len(lines) > 1 and lines[1].upper().startswith("SIZE "):
                    filesize = int(lines[1].split(" ",1)[1])
                else:
                    hdr = conn.recv(1024).decode().strip()
                    if not hdr.upper().startswith("SIZE "):
                        send_all(conn, b"ERR")
                        continue
                    filesize = int(hdr.split(" ",1)[1])

                send_all(conn, b"READY")
                file_bytes = recv_exact(conn, filesize)
                if len(file_bytes) != filesize:
                    print("[-] Upload incomplete")
                    send_all(conn, b"ERR")
                    continue
                os.makedirs(RECV_DIR, exist_ok=True)
                outpath = os.path.join(RECV_DIR, os.path.basename(filename))
                with open(outpath, 'wb') as f:
                    f.write(file_bytes)
                print(f"[+] Received upload: {outpath} ({filesize} bytes)")
                send_all(conn, b"DONE")

            elif text.upper() == "QUIT":
                send_all(conn, b"BYE")
                break

            else:
                send_all(conn, b"UNKNOWN_COMMAND")

    except Exception as e:
        print("Exception in authenticated handler:", e)
    finally:
        conn.close()
        print("[-] Secured connection closed for", addr)

def handle_client(conn_raw, addr, users):
    """
    First stage: perform a simple AUTH handshake over the secured socket.
    Expected from client: 'AUTH username password'
    """
    try:
        # Read first line for AUTH
        data = conn_raw.recv(2048)
        if not data:
            print("No data on auth; closing")
            conn_raw.close()
            return
        text = data.decode(errors='ignore').strip()
        print("Auth recv raw:", repr(text[:200]))
        parts = text.split()
        if len(parts) >= 3 and parts[0].upper() == "AUTH":
            username = parts[1]
            password = " ".join(parts[2:])  # allow spaces in password if any
            # check credentials
            if users.get(username) == password:
                # Let client know auth ok
                send_all(conn_raw, b"AUTH_OK")
                # If extra payload after AUTH line, it will be ignored; proceed to normal loop
                handle_authenticated(conn_raw, addr)
            else:
                send_all(conn_raw, b"AUTH_FAIL")
                conn_raw.close()
                print("Auth failed for", username)
        else:
            send_all(conn_raw, b"AUTH_REQUIRED")
            conn_raw.close()
            print("Bad auth format from", addr)
    except Exception as e:
        print("Exception in handle_client auth:", e)
        try:
            conn_raw.close()
        except:
            pass

def start_server():
    users = load_users()
    if not users:
        print("[!] Warning: no users found in users.txt. Add users before starting.")
    os.makedirs(SHARED_DIR, exist_ok=True)
    os.makedirs(RECV_DIR, exist_ok=True)

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"TLS server listening on {HOST}:{PORT}")
        while True:
            client_sock, addr = sock.accept()
            # Wrap socket in TLS
            try:
                conn = context.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as e:
                print("SSL error during handshake:", e)
                client_sock.close()
                continue
            print("[+] New TLS connection from", addr)
            handle_client(conn, addr, users)

if __name__ == "__main__":
    start_server()
