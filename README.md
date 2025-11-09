 Network File Sharing System(LSP Capstone Project)


  Developed by: Lohit Kumar Mishra
 
  Course: Linux System Programming (LSP)
 
  Institution: SOA - ITER

Project Overview


This project implements a Network File Sharing System using Client-Server architecture over sockets.  
It allows users to list, download, upload, and securely transfer files between the client and the server.  
Security is enhanced with *authentication* and *encryption* features using SSL (Secure Sockets Layer).

🎯 Objective


To design a secure and reliable file sharing system that enables data transfer between multiple systems using
*socket programming in Python* on a *Linux-based environment (WSL2/Ubuntu)*.


 
 🗓️ Day-Wise Progress

 🧩 *Day 1:* Server-Client Socket Setup
- Configured server and client communication using Python sockets.  
- Verified basic message transfer between both ends.

 📂 *Day 2:* File Listing & Selection
- Implemented listing of available files from the server directory.  
- Enabled the client to select files for download.

 🔄 *Day 3:* File Download Functionality
- Client can download any selected file from the server.  
- Verified successful transfer and file integrity.

 ⬆️ *Day 4:* File Upload Functionality
- Added upload feature for client → server transfer.  
- Ensured confirmation messages and proper file placement.

🔐 *Day 5:* Security Integration
- Implemented user authentication (username/password).  
- Secured communication using *SSL encryption* (OpenSSL certificates).  
- Verified encrypted file transfer with authentication success message.



 ⚙️ Technologies Used
| Component | Technology |
|------------|-------------|
| Language | Python 3 |
| OS | Ubuntu (WSL2 on Windows) |
| Networking | TCP Sockets |
| Security | SSL (OpenSSL Certificates) |
| Tools | nano, openssl, python3 |



 🧠 Key Learning Outcomes
- Hands-on experience with Linux socket programming.  
- Implementation of client-server communication.  
- Understanding file transfer protocols* and *secure sockets (SSL).  
- Gained practical exposure to *authentication and encryption concepts*.

 
🧾 How to Run

   🖥️ On the Server Terminal:
          cd network-file-sharing
          python3 server.py

          
   💻 On the Client Terminal:
           cd network-file-sharing
           python3 client.py


✅ When prompted:
    Enter username: admin
    Enter password: password
    You’ll see: Authentication successful


Then use options: 
                 1️⃣ List files
                 2️⃣ Download
                 3️⃣ Upload
                 4️⃣ Quit

🧾 Example terminal flows

Client (download)

      Connected to server over TLS.
      Username: student
      Password: **
      Authenticated successfully.
      Menu: (1) LIST (2) DOWNLOAD (3) UPLOAD (4) QUIT
      Choice: 2
      Files on server:
      1. fileA.txt
      Type filename to DOWNLOAD: fileA.txt
      Server says file size = 15 bytes.
      Downloading: 15/15 bytes (100.0%)
      Download complete: downloads/fileA.txt (15 bytes)
      Server: BYE

Server (upload received)

      [+] New TLS connection from ('127.0.0.1', 52344)
      Auth recv raw: 'AUTH student password123\n'
      [+] Secured session for ('127.0.0.1', 52344)
      Command: UPLOAD test_upload.txt
      [+] Received upload: received_uploads/test_upload.txt (24 bytes)


🧩 Implementation Notes 

The server uses a simple textual protocol:

LIST → server returns file1|file2|... DOWNLOAD <filename> → server sends SIZE N then the bytes UPLOAD <filename> → client sends SIZE N then the bytes QUIT → close politely AUTH <username> <password> → initial auth handshake

The implementation handles *TCP stream edge cases* — headers and data may coalesce, and the server parses combined headers robustly.

Transfers use *chunked reads* (CHUNK_SIZE = 4096), which supports large files efficiently.


 🧪 Testing Checklist

Before submitting, verify the following ✅

- [ ] server.py runs without traceback.  
- [ ] client.py connects and authenticates successfully.  
- [ ] Download a file and verify its content appears correctly in downloads/.  
- [ ] Upload a file and confirm it appears in received_uploads/.  
- [ ] Ensure server_key.pem is *not committed* to the repository.  

        
## 🏁 Final Notes

This project successfully demonstrates the implementation of a secure and efficient *Network File Sharing System* using socket programming in Python.  
It simulates real-world client–server communication, handling file uploads, downloads, and authentication over TCP with proper data integrity and protocol handling.  

Through this project, we learned key concepts of:
- Linux-based networking,
- Socket programming (LSP),
- Client–server architecture, and
- Secure file transfer mechanisms.

This capstone strengthened My practical understanding of *Linux System Programming* and teamwork in software development.




