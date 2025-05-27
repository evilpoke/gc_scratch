

import socket
import ssl
import pprint

hostname = '127.0.0.1'
#context = ssl.create_default_context()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("example.crt")

#context.load_cert_chain('/path/to/certchain.pem', '/path/to/private.key')

# The evaluator is the client


with socket.create_connection((hostname, 8443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())
        
        #ssock.connect((hostname, 8443))
        ssock.sendall(b"message one from evaluatore\r\n\r\n") # 1
        
        data = ssock.recv(1024)    #2
        pprint.pprint(data.split(b"\r\n"))
        
        print("recieved first message")
        
        ssock.sendall(b"message two from evaluatroe\r\n\r\n")   #3
        #ssock.sendall(b"testtest something something\r\n\r\n")
        
        data = ssock.recv(1024)   #4
        pprint.pprint(data.split(b"\r\n"))
        
        print("recieved second message")
        
        ssock.close()
    
    
    #context.wrap_socket(socket.socket(socket.AF_INET),
    #                       server_hostname=hostname)
#conn.connect()
#cert = conn.getpeercert()


#conn.sendall(b"testtest something something\r\n")

#pprint.pprint(conn.recv(1024).split(b"\r\n"))
