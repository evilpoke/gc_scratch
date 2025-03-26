

import socket
import ssl
import pprint



class IOWrapperClient:
    
    
    def __init__(self):
        
        self.hostname = '127.0.0.1'
        #context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations("example.crt")
        self.ssock = None

    def deal_with_client(self, connstream):
        print("dealing")
        data = connstream.recv(1024)
        pprint.pprint(data.split(b"\r\n"))
        # empty data means the client is finished with us
        while data:
            
            #if not do_something(connstream, data):
            #    # we'll assume do_something returns False
            #    # when we're finished with client
            #    break
            data = connstream.recv(1024)
            pprint.pprint(data.split(b"\r\n"))
        # finished with client


    def startup(self):
        
        print("start")
        self.sock =  socket.create_connection((self.hostname, 8443))
        self.ssock = self.context.wrap_socket(self.sock, server_hostname=self.hostname)
        
    def send(self, msg):
        self.ssock.sendall(msg)
    
    def receive(self):
        data = self.ssock.recv(1024)
        return data




io = IOWrapperClient()
io.startup()
io.send(b"ssfdsfkadsflksajfksalfsajlfjlksajflka\r\n\r\n")

v = io.receive()
pprint.pprint(v.split(b"\r\n"))

io.ssock.shutdown(socket.SHUT_RDWR)
io.ssock.close()
io.sock.close()


"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")
wrappedSocket.connect(('127.0.0.1', 8443))
wrappedSocket.recv(1024)

wrappedSocket.send(b"asdfsaf\r\n")
"""