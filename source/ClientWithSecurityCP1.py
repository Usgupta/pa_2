import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")
def encrypt_with_publicKey(xbytes,len,public_key):
     """
     To encrypt data 
     """
     if (len<117):
        return (public_key.encrypt(xbytes, padding.PKCS1v15()),128)
     else:
        encrypted_data = public_key.encrypt(xbytes[0:117], padding.PKCS1v15())
        number_of_blocks = 0
        if (len%117 == 0):
            number_of_blocks = len//117
        else: 
             number_of_blocks = (len//117 )+ 1
        
        m = 117
       
        for i in range(1,(len//117)):
            encrypted_data += public_key.encrypt(xbytes[m:m+117], padding.PKCS1v15())
            m = m+117
        encrypted_data += public_key.encrypt(xbytes[m:], padding.PKCS1v15())

        return (encrypted_data,number_of_blocks*128)     
        


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    #Extracting Public Keys from the Certificate:
    f = open("auth/cacsertificate.crt", "rb")
    ca_cert_raw = f.read()
    ca_cert = x509.load_pem_x509_certificate( data=ca_cert_raw, backend=default_backend())
    ca_public_key = ca_cert.public_key()


    # try:
    print("Establishing connection to server...")
    # Connect to server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")


        #Send the authentication message
        s.sendall(convert_int_to_bytes(3))
        authmsg_bytes = bytes('./source/files/file.txt', encoding="utf8")
        s.sendall(convert_int_to_bytes(len(authmsg_bytes)))
        s.sendall(authmsg_bytes)

        #Receive authentication message:
        signed_message_len = s.recv(8);
        signed_message = s.recv(convert_bytes_to_int(signed_message_len ));
    

        #Receive signed certificate from server
        server_cert_len = s.recv(8);
        server_cert_raw= s.recv(convert_bytes_to_int( server_cert_len ));
        
        #Verify Certificate 
        server_cert = x509.load_pem_x509_certificate(data=server_cert_raw, backend=default_backend())
        ca_public_key.verify(signature=server_cert.signature, # signature bytes to  verify
         data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
         padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
         algorithm=server_cert.signature_hash_algorithm,
         )
        

        server_public_key = server_cert.public_key()
       
        server_public_key.verify(
            signed_message,
            authmsg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
                 ),
                  hashes.SHA256(),
                  )
                  
        if (server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after):

            while True:
                filename = input("Enter a filename to send (enter -1 to exit):")

                while filename != "-1" and (not pathlib.Path(filename).is_file()):
                    filename = input("Invalid filename. Please try again:")

                if filename == "-1":
                    s.sendall(convert_int_to_bytes(2))
                    break

                filename_bytes = bytes(filename, encoding="utf8")

                # Send the filename
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)
                

                # Send the file
                with open(filename, mode="rb") as fp:
                    data = fp.read()
                    enc_data,size = encrypt_with_publicKey(data,len(data),server_public_key)
                    print(size)
                    print(len(enc_data))
                    filename_enc = "enc_" + filename.split("/")[-1]
                     # Write the file with 'recv_' prefix
                    with open(f"send_files_enc/{filename_enc}", mode="wb" ) as fp:
                        fp.write(enc_data)
                    
                    s.sendall(convert_int_to_bytes(1))
                    s.sendall(convert_int_to_bytes(size))
                    s.sendall(enc_data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
