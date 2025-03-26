

import socket
import ssl
import pprint

hostname = '127.0.0.1'
#context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_verify_locations("example.crt")

context.load_cert_chain(certfile="example.crt", keyfile="example.key")



def deal_with_client(connstream):
    print("dealing")
    data = connstream.recv(1024)
    pprint.pprint(data.split(b"\r\n"))   # 1
    
    print("recieved first message")
    # empty data means the client is finished with us
    while data:
        
        #if not do_something(connstream, data):
        #    # we'll assume do_something returns False
        #    # when we're finished with client
        #    break
        
        connstream.sendall(b"message one from garblerer\r\n\r\n")   # 2
        
        data = connstream.recv(1024)   #3
        pprint.pprint(data.split(b"\r\n"))
        
        
        print("recieved second message")
        
        connstream.sendall(b"message two from garblerer\r\n\r\n")   #4
        
        
        
        
        
    # finished with client


print("start")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((hostname, 8443))
    sock.listen(5)
    print("listening for accept")
    while True:
        print("entered the while loop")
        newsocket, fromaddr = sock.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        try:
            deal_with_client(connstream)
        finally:
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()


"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")
wrappedSocket.connect(('127.0.0.1', 8443))
wrappedSocket.recv(1024)

wrappedSocket.send(b"asdfsaf\r\n")
"""