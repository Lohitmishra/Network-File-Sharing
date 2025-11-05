#!/usr/bin/env python3
"""
TLS + Authentication client for file sharing
"""

import socket
import ssl
import os
import time
import getpass

SERVER = '127.0.0.1'
PORT = 9999
DOWNLOAD_DIR = 'downloads'
TO_UPLOAD_DIR = 'to_upload'
CHUNK_SIZE = 4096
SERVER_CERT = 'server_cert.pem'   # we'll trust this self-signed cert for verification

def recv_exact(sock, nbytes):
    received = bytearray()
    while len(received) < nbytes:
        chunk = sock.recv(min(CHUNK_SIZE, nbytes - len(received)))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)

def list_files(sock):
    sock.send(b"LIST")
    data = sock.recv(4096).decode()
    files = data.split("|") if data else []
    return [f for f in files if f]

def download_file(sock, filename):
    sock.send(f"DOWNLOAD {filename}".encode())
    header = sock.recv(1024).decode().strip()
    if header == "NOTFOUND":
        print("Server: File not found.")
        return
    if not header.startswith("SIZE "):
        print("Unexpected response:", header)
        return
    filesize = int(header.split(" ",1)[1])
    print(f"Downloading {filename} ({filesize} bytes)...")
    sock.send(b"READY")
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    outpath = os.path.join(DOWNLOAD_DIR, os.path.basename(filename))
    received = 0
    start = time.time()
    with open(outpath, 'wb') as f:
        while received < filesize:
            chunk = sock.recv(min(CHUNK_SIZE, filesize - received))
            if not chunk:
                break
            f.write(chunk)
            received += len(chunk)
            print(f"\r{received}/{filesize} bytes", end='', flush=True)
    print()
    if received == filesize:
        print("Download complete:", outpath)
    else:
        print("Download incomplete")

def upload_file(sock, filename):
    path = os.path.join(TO_UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        print("Local file not found:", path)
        return
    filesize = os.path.getsize(path)
    header = f"UPLOAD {filename}\nSIZE {filesize}\n"
    sock.send(header.encode())
    ack = sock.recv(1024).decode().strip()
    if ack != "READY":
        print("Server didn't send READY; got:", ack)
        return
    sent = 0
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sock.sendall(chunk)
            sent += len(chunk)
            print(f"\rSent {sent}/{filesize} bytes", end='', flush=True)
    print()
    resp = sock.recv(1024).decode().strip()
    if resp == "DONE":
        print("Upload finished.")
    else:
        print("Upload failed, server said:", resp)

def authenticate_over_tls(sock):
    """
    Send AUTH username password and expect AUTH_OK or AUTH_FAIL
    """
    username = input("Username: ").strip()
    # Use getpass so password isn't echoed
    password = getpass.getpass("Password: ")
    auth_line = f"AUTH {username} {password}\n"
    sock.send(auth_line.encode())
    resp = sock.recv(1024).decode().strip()
    if resp == "AUTH_OK":
        print("Authenticated successfully.")
        return True
    else:
        print("Authentication failed:", resp)
        return False

def main():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(TO_UPLOAD_DIR, exist_ok=True)

    # Create TLS context and verify server cert
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Trust the local server cert (self-signed)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=SERVER_CERT)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped = context.wrap_socket(raw_sock, server_hostname="localhost")
    wrapped.connect((SERVER, PORT))
    print("Connected to server over TLS.")

    # Perform authentication
    ok = authenticate_over_tls(wrapped)
    if not ok:
        wrapped.close()
        return

    try:
        while True:
            print("\nMenu: (1) LIST  (2) DOWNLOAD  (3) UPLOAD  (4) QUIT")
            choice = input("Choose option: ").strip()
            if choice == "1":
                files = list_files(wrapped)
                if not files:
                    print("No files on server.")
                else:
                    print("Files on server:")
                    for i,f in enumerate(files,1):
                        print(f" {i}. {f}")

            elif choice == "2":
                files = list_files(wrapped)
                if not files:
                    print("No files.")
                    continue
                print("Files on server:")
                for i,f in enumerate(files,1):
                    print(f" {i}. {f}")
                fname = input("Type filename to DOWNLOAD: ").strip()
                if fname:
                    download_file(wrapped, fname)

            elif choice == "3":
                local = os.listdir(TO_UPLOAD_DIR)
                local = [f for f in local if os.path.isfile(os.path.join(TO_UPLOAD_DIR,f))]
                if not local:
                    print("No files to upload in", TO_UPLOAD_DIR)
                    continue
                print("Local files to upload:")
                for i,f in enumerate(local,1):
                    print(f" {i}. {f}")
                fname = input("Type local filename to UPLOAD: ").strip()
                if fname:
                    upload_file(wrapped, fname)

            elif choice == "4":
                wrapped.send(b"QUIT")
                bye = wrapped.recv(1024).decode().strip()
                print("Server:", bye)
                break

            else:
                print("Invalid choice.")

    finally:
        wrapped.close()

if __name__ == "__main__":
    main()
