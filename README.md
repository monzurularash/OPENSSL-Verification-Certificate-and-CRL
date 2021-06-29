# OPENSSL-based-security

The repository source code for a server app, a client app, and CRL server. When the client sends a connection request to a server, the server sends back its own certificate. Now the client verifies if the received certificate is indeed a valid certificate. The client also downloads a copy of the revocation list (CRL) from a CRL server to local cache. The client performs a lookup on the CRL to find out if the certificate is revoked or not.

## How to Build (on Linux OS)
##### server app: gcc -o server server.c -L/usr/lib -lcrypto -lssl  
##### client app: g++ -o client crl_client.cpp -L/usr/lib -lcrypto -lssl    

## How to Run 
On different terminal:
For openssl based client app: 
##### ./client server_ip server_port . Example: ./client 127.0.0.1 6000  
For openssl based server app: 
##### sudo ./server server_port. Example: sudo ./server 6000  
Fot CRL server: 
##### node index.js  

If everything goes right, you will have a secure full duplex server-client chat system running.
