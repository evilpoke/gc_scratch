
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
from ot import FunctionF, FunctionI, FunctionInvF, FunctionS, selectionofferer, selectionselector
from multiprocessing import Process


def hash5(in_input):
    #if isinstance(in_input, bytes):
    #    pass
    #else:
    in_input = in_input.to_bytes(4096, byteorder='big')
        
    digest = hashes.Hash(hashes.SHA256())
    
    digest.update(b"schaal")
    digest.update(bytes(in_input))
    
    return digest.finalize()

def xorarray(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

class selectionofferer_hashins:
    
    def __init__(self, io, askedid):
        self.b0 = None
        self.b1 = None
        self.io = io
        self.sms = SysCmdStrings()
        
        self.askedid = askedid 
    
    
    def set_first_optionbit(self,setop):
        assert isinstance(setop, bytes), "Wrong input type for setting a offer byte arry" 

        self.b0 = setop
        
    
    def set_second_optionbit(self,setop):
        assert isinstance(setop, bytes), "Wrong input type for setting a offer byte arry"
        

        self.b1 = setop
        

    def do_protocol(self):
        assert not (self.b0 is None or     self.b1 is None), "Initialize first!"
        
        
        iin = FunctionI()
        
        (pupkey, privkey) = iin.generate(self)
        alpha = iin.alpha
        
        backward = FunctionInvF(privkey)
        
        #hcpred = FunctionHardCoreB(alpha)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        alphac = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="alpha", payload=alpha)
        self.io.send(alphac)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        sendpupkey = list(pupkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        pupkey = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="pupkey", payload=sendpupkey) # to byte array
        self.io.send(pupkey)
        
        
        ## Recieving  ------------------------
        y0 = self.io.receive()
        
        command = self.sms.load_byte_to_object(y0)
        assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "y0", "Wrong OT seq command, expect alpha"
        y0 = bytes(command["payload"])
        
        ## Recieving  ------------------------
        y1 = self.io.receive()
        
        command = self.sms.load_byte_to_object(y1)
        assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "y1", "Wrong OT seq command, expect alpha"
        y1 = bytes(command["payload"])
        
        
        x0 = backward.fun_invF(alpha, y0)
        x1 = backward.fun_invF(alpha, y1)
        
        #beta0 = hcpred.fun_B(int.from_bytes(x0, 'big')) ^ self.b0   # < do hash instead
        #beta1 = hcpred.fun_B(int.from_bytes(x1, 'big')) ^ self.b1
        
        beta0 = xorarray(hash5( int.from_bytes(x0, 'big') ) , self.b0 )
        beta1 = xorarray(hash5( int.from_bytes(x1, 'big') ) , self.b1 )
        
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        beta0 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta0", payload=list(beta0))
        self.io.send(beta0)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        beta1 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta1", payload=list(beta1))
        self.io.send(beta1)



class selectorselector_hashins:
    
    def __init__(self, io, wireid):
        self.sigma = None
        self.bsel = None
        self.io = io
        self.sms = SysCmdStrings()
        self.wireid = wireid
    
    
    def announce_selection(self):
        c = Command.performing_ot_ask
        otann = OT_ANNOUNCE.ot_wire_id
        cmddict = self.sms.makecommand(cmd=c, otann=otann, payloadcontext=self.wireid, payload=self.wireid)
        
        self.io.send(cmddict)
    
    
    def set_sigma(self, setop):
        assert isinstance(setop, bool), "Wrong input type for setting a select bit" 

        self.sigma = setop
    

    def do_protocol(self):
        """
        This method blocks while the underlying methods block
        """
        assert not (self.sigma is None), "Initialize first!"
        
        ## Recieving  ------------------------
        alpha = self.io.receive()
        command = self.sms.load_byte_to_object(alpha)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "alpha", "Wrong OT seq command, expect alpha"
        alpha = command["payload"]
        
        ## Recieving  ------------------------
        pupkey = self.io.receive()
        
        command = self.sms.load_byte_to_object(pupkey)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "pupkey", "Wrong OT seq command, expect alpha"
        pupkey = bytes(command["payload"])
        pupkey = serialization.load_pem_public_key(pupkey)
        
        fS = FunctionS()
        
        forward = FunctionF(pupkey)
        
        #hcfunc = FunctionHardCoreB(alpha)
        
        fS.modulus_n = pupkey.public_numbers().n
        fS.pubkey = pupkey
        
        if self.sigma == False:
            x_0 = fS.select_from_S()
            hcbit = hash5(x_0) #hcfunc.fun_B(x_0)
            y_1 = fS.select_from_S_dummy(pupkey, alpha)
            y_0 = forward.fun_F(alpha, x_0)
        else: # sigma = 1
            x_1 = fS.select_from_S()
            hcbit = hash5(x_1) # hcfunc.fun_B(x_1)
            y_0 = fS.select_from_S_dummy(pupkey, alpha)
            y_1 = forward.fun_F(alpha, x_1)
        
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_ask
        otan = OT_ANNOUNCE.ot_seq
        y_0 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="y0", payload=list(y_0))
        self.io.send(y_0)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_ask
        otan = OT_ANNOUNCE.ot_seq
        y_1 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="y1", payload=list(y_1))
        self.io.send(y_1)
        
        
        beta0 = self.io.receive()
        command = self.sms.load_byte_to_object(beta0)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "beta0", "Wrong OT seq command, expect alpha"
        beta0 = bytes(command["payload"])
        
        beta1 = self.io.receive()
        command = self.sms.load_byte_to_object(beta1)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "beta1", "Wrong OT seq command, expect alpha"
        beta1 = bytes(command["payload"])
        
        if self.sigma == False:
            bsel = xorarray(hcbit , beta0 )
        else:
            bsel = xorarray(hcbit , beta1 )
        
        self.bsel = bsel
        #try:
        #    self.io.send(b'EOF')
        #except Exception as e:
        #    print("exited connection")
        