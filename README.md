#Secure File Transfer

Implemented a secure file upload application from a client to a secure file server. By secure, we mean three fulfilled requirements:

   1. First, before you do your upload as the client, you should authenticate the identity of the file server so you won’t leak your data to random entities including criminals.
   2. Secondly, you also want to ensure that you’re talking to a live server too.
   3. Thirdly, while carrying out the upload you should be able to protect the confidentiality of the data against eavesdropping by any curious adversaries.


##How to Run

Run python3 Server and Client python file in two terminal windows:

1. ServerWithoutSecurity.py, ClientWithoutSecurity.py is insecure file transfer between client and server
2. ServerWithSecurityAP.py, ClientWithSecurityAP.py authenticates the identity using a CA and checks if its talking to live server using a nonce
3. ServerWithSecurityCP1.py, ClientWithSecurityCP1.py protects confidentiality using public key cryptography 
4. ServerWithSecurityCP2.py, ClientWithSecurityCP2.py protects confidentiality using symmetric key cryptography 

