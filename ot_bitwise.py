
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from cryptography.hazmat.primitives.asymmetric import padding
from random import SystemRandom
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from tqdm import tqdm
from ot import selectionofferer, selectionselector
from multiprocessing import Process

class selectionofferer_bitwise:
    def __init__(self, io, askedid):
        self.b0 = None # byte array 
        self.b1 = None # byte array
        self.io = io
        self.sms = SysCmdStrings()
        
        self.pbar = tqdm(total=256)
        
        self.askedid = askedid 
        
        self.backend_selection_offerers = []
        for i in range(32*8):
            self.backend_selection_offerers.append(selectionofferer(io, askedid))
        
    
    def set_first_optionbit(self,setop):
        assert isinstance(setop, bytes), "Wrong input type for setting a offer byte arry" 
        
        
        for i in range(32):
            for p in range(8):
                offerer = self.backend_selection_offerers[p+8*i]
                tobeinsertedbool = (setop[i] >> p) & 1 == 1 #b'\x01'
                offerer.set_first_optionbit(tobeinsertedbool)

        self.b0 = setop
        
    
    def set_second_optionbit(self,setop):
        assert isinstance(setop, bytes), "Wrong input type for setting a offer byte arry"
        
        for i in range(32):
            for p in range(8):
                offerer = self.backend_selection_offerers[p+8*i]
                
                tobeinsertedbool = (setop[i] >> p) & 1 == 1 #b'\x01'
                offerer.set_second_optionbit(tobeinsertedbool)

        self.b1 = setop
    
    def do_protocol(self):
        assert not (self.b0 is None or  self.b1 is None), "Initialize first!"
        
        for ww in self.backend_selection_offerers:
            ww.do_protocol()
            self.pbar.update()
        
        self.pbar.close()


class selectionselector_bitwise:
    
    def __init__(self, io, wireid):
        self.sigma = None
        self.bsel = None # will result in bitarray here
        self.io = io
        self.sms = SysCmdStrings()
        
        self.announced = False
        self.backend_selection_selectors = []
        self.wireid = wireid
        for i in range(32*8):
            self.backend_selection_selectors.append(selectionselector(io, wireid))
        self.pbar = tqdm(total=256)
        
    def announce_selection(self):
        c = Command.performing_ot_ask
        otann = OT_ANNOUNCE.ot_wire_id
        cmddict = self.sms.makecommand(cmd=c, otann=otann, payloadcontext=self.wireid, payload=self.wireid)
        
        self.io.send(cmddict)
        
        self.announced = True
        
    def set_sigma(self, setop):
        assert isinstance(setop, bool), "Wrong input type for setting a select bit" 

        self.sigma = setop
        
        for i in range(32*8):
            self.backend_selection_selectors[i].sigma = setop
    
    def do_protocol(self):
        """
        This method blocks while the underlying methods block
        """
        assert not (self.sigma is None), "Initialize first!"
        i = 0
        for ww in self.backend_selection_selectors:
            #print("ot: "+str(i))
            ww.do_protocol()
            i = i + 1
            self.pbar.update()
        self.pbar.close()
        
        
        self.bsel = bytearray(bytes(32))
        
        
        for i in range(32):
            
            for p in range(8):
            
                modibyte = self.bsel[i]
                
                # creating a byte 0000 0001
                
                insertbyte = 1 # b'\x01'
                
                # left shifting to position
                
                insertbyte = insertbyte << p
                
                # inverting => e.g. 0000 0100 to 1111 1011
                
                insertbyte = insertbyte ^ 255
                
                # AND-ing modibyte => yyyy y0yy
                
                modibyte = modibyte & insertbyte
                
                # creating a byte 0000000[x]
                
                ww = self.backend_selection_selectors[i*8 + p]
                if ww.bsel == True:
                    inin = b'\x01'
                else:
                    inin = b'\x00'
                
                # shifting to appropriate place
                
                inin = ord(inin) << p
                
                # OR-ing with new modibyte
                
                modibyte = modibyte | inin
                
                self.bsel[i] = modibyte
                
#class 

#def call_protocol_on_entry() # TODO multiprocessign

    
class IOhandler:
    pass