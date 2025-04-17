
import socket
import ssl
import pprint
from time import (
    process_time,
    perf_counter,
    sleep,
)

class IOWrapperServer:
    
    
    def __init__(self):
        
        self.hostname = '127.0.0.1'
        #context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_verify_locations("example.crt")

        self.context.load_cert_chain(certfile="example.crt", keyfile="example.key")
        self.sock = None
        self.connstream = None
        
        self.totaltimesend = 0
        self.totaltimereceive = 0
        
        self.codesend = "_"
        self.codereceive = "_"
        
        self.lock = None
        

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
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        
        self.sock.bind((self.hostname, 5443))
        self.sock.listen(5)
        print("listening for accept")
        newsocket, fromaddr = self.sock.accept()
        self.connstream = self.context.wrap_socket(newsocket, server_side=True)
        
    def send(self, msg):
        a = perf_counter()
        
        if self.codesend != "_":
            # sending with additional context

            
            
        else:
           # sending with additional context 
            self.connstream.sendall(msg)
        
        
        
        b = perf_counter()
        self.totaltimesend = self.totaltimesend + (b - a)
    
    def receive(self):
        a = perf_counter()
        data = self.connstream.recv(5192)
        b = perf_counter()
        self.totaltimereceive = self.totaltimereceive + (b - a)
        return data
    
    # TODO: this 'announce'-thing is an incredibly inefficient and stupid way to do this
    # I did it because i do not particularly like myself. This will be replaced by a proper library of some sorts
    
    def announcesend(self, code):
        
        send the announcesendcode. do nothing else. Following the announcesend there will be a send. 
        This send will go through as soon as the announcerecieve of the other party has cleared 
        
        self.codesend = code
    
    def announcereceive(self, code):
        
        while True:
            time.sleep(1)
            ..scan for code in codequeue..
                -> solve
            
            recieve an announcesend, put it in codequeue
        


"""
io = IOWrapperServer()
io.startup()
v = io.receive()
pprint.pprint(v.split(b"\r\n"))
io.send(b"asdfasfdasfd\r\n\r\n")

io.connstream.shutdown(socket.SHUT_RDWR)
io.sock.shutdown(socket.SHUT_RDWR)
io.sock.close()
io.connstream.close()
io.sock.close()
"""


#io.sock.close()

"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")
wrappedSocket.connect(('127.0.0.1', 8443))
wrappedSocket.recv(1024)

wrappedSocket.send(b"asdfsaf\r\n")
"""