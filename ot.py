
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings

class FunctionS:
    """
    S is a selector on a group Z*n where n is a number of 4096 bit. 
    
    S chooses from 1..n
    
    """
    
    def __init__(self):
        self.modulus_n = None
    
    
    def set_n(self,n):
        self.modulus_n = n
    
    def select_from_S(self):
        #        from random import SystemRandom
        #>>> cryptogen = SystemRandom()
        #>>> [cryptogen.randrange(3) for i in range(20)] # random ints in range(3)
        #[2, 2, 2, 2, 1, 2, 1, 2, 1, 0, 0, 1, 1, 0, 0, 2, 0, 0, 0, 0]
        #>>> [cryptogen.random() for i in range(3)]  # random floats in [0., 1.)
        #[0.2710009745425236, 0.016722063038868695, 0.8207742461236148]
        
        rand = ...  # no need for padding?
    
    def select_from_S_dummy(self, pupkey, alpha):
        
        dummy_S = self.select_from_S()
        
        pred_value = hash(alpha)
        pred2_value = hash2(alpha)
        
        pred_value_comp = pred_value mod pubkey.N
        
        y_sigma = self.pubkey.encrypt(    dummy_S, # TODO << as with the other function 
                                padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=pred2_value  # None
                                )
                            )

        return y_sigma
        
        
    
class FunctionI:
    """
    Generates I(1^n) material. 
    For our case, the enhanced trapdoor collection is just usual 4096-RSA material
      
    """
    def __init__(self):
        self.modulus = None
        self.exp = None
        self.pubkey = None
        
        
        self.alpha = rnd 
            #        from random import SystemRandom
        #>>> cryptogen = SystemRandom()
        #>>> [cryptogen.randrange(3) for i in range(20)] # random ints in range(3)
        #[2, 2, 2, 2, 1, 2, 1, 2, 1, 0, 0, 1, 1, 0, 0, 2, 0, 0, 0, 0]
        #>>> [cryptogen.random() for i in range(3)]  # random floats in [0., 1.)
        #[0.2710009745425236, 0.016722063038868695, 0.8207742461236148

    def generate(self, party):
        """
        Generates a key pair
        
        returns: RSAPublicKey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey 
        """
        assert isinstance(party,selectionofferer), "The party selecting one of the choices can not generate the trapdoor"
        
        return ..
    
    def pull_pub_material(self):
        return (self.pubkey, self.alpha)

class FunctionF:
    
    def __init__(self, publickey):
        self.pubkey = publickey
    
    
    def fun_F(self, alpha, x):
        
        pred_value = hash(alpha)
        pred2_value = hash2(alpha)
        
        pred_value_comp = pred_value mod pubkey.N
        
        y_sigma = self.pubkey.encrypt(    x,   #  *pred_value_comp,  << TODO include back. currently to risky 
                                padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=pred2_value  # None
                                )
                            )

        return y_sigma
    
    
class FunctionInvF:
    def __init__(self, privkey):
        self.privkey = privkey
    
    def fun_invF(self, alpha, y):
        
        pred_value = hash(alpha)
        pred2_value = hash2(alpha)
        
        x = self.privkey.decrypt(
                y,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=pred2_value
                )
        )
        
        
        return x


class FunctionHardCoreB:
    
    def __init__(self, alpha):
        self.alpha = alpha
        self.hashed_alpha = hash3(alpha) 
        
    
    def fun_B(self, x):
        iv = hash4(x)
        cipher = Cipher(algorithms.AES(self.hashed_alpha), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(x)
        
        return ct[0]


class selectionofferer:
    def __init__(self, io, askedid):
        self.b0 = None
        self.b1 = None
        self.io = io
        
        
        self.askedid = askedid 
        
    
    def set_first_optionbit(self,setop):
        assert isinstance(setop, bool), "Wrong input type for setting a offer bit" 
        self.b0 = setop
    
    def set_second_optionbit(self,setop):
        assert isinstance(setop, bool), "Wrong input type for setting a offer bit" 
        self.b1 = setop
    
    
    def do_protocol(self):
        assert not (self.b0 is None or     self.b1 is None), "Initialize first!"
        
        
        iin = FunctionI()
        
        (pupkey, privkey) = iin.generate(self)
        alpha = iin.alpha
        
        backward = FunctionInvF(privkey)
        
        hcpred = FunctionHardCoreB(alpha)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        alpha = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="alpha", payload=alpha)
        self.io.send(alpha)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        pupkey = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="pupkey", payload=pupkey)
        self.io.send(pupkey)
        
        
        ## Recieving  ------------------------
        y0 = self.io.recieve()
        
        command = json.loads(y0)
        assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "y0", "Wrong OT seq command, expect alpha"
        y0 = command["payload"]
        
        ## Recieving  ------------------------
        y1 = self.io.recieve()
        
        command = json.loads(y1)
        assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "y1", "Wrong OT seq command, expect alpha"
        y1 = command["payload"]
        
        
        x0 = backward.fun_invF(alpha, y0)
        x1 = backward.fun_invF(alpha, y1)
        
        beta0 = hcpred.fun_B(x0) ^ self.b0
        beta1 = hcpred.fun_B(x1) ^ self.b1
        
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        beta0 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta0", payload=beta0)
        self.io.send(beta0)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_give
        otan = OT_ANNOUNCE.ot_seq
        beta1 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta1", payload=beta1)
        self.io.send(beta1)


class selectionselector:
    
    def __init__(self, io, wireid):
        self.sigma = None
        self.bsel = None
        self.io = io
        self.sms = SysCmdStrings()
        
        
        c = Command.performing_ot_ask
        otann = OT_ANNOUNCE.ot_wire_id
        cmddict = self.sms.makecommand(cmd=c, otann=otann, payloadcontext=wireid, payload=wireid)
        
        io.send(cmddict)
            
    
    def set_sigma(self, setop):
        assert isinstance(setop, bool), "Wrong input type for setting a select bit" 

        self.sigma = setop
    
    def do_protocol(self):
        """
        This method blocks while the underlying methods block
        """
        assert not (self.sigma is None), "Initialize first!"
        
        ## Recieving  ------------------------
        alpha = self.io.recieve()
        
        command = json.loads(alpha)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "alpha", "Wrong OT seq command, expect alpha"
        alpha = command["payload"]
        
        ## Recieving  ------------------------
        pupkey = self.io.recieve()
        
        command = json.loads(pupkey)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "pubkey", "Wrong OT seq command, expect alpha"
        pupkey = command["payload"]
        
        
        fS = FunctionS()
        
        forward = FunctionF(pupkey)
        
        hcfunc = FunctionHardCoreB(alpha)
        
        fS.modulus_n = pupkey.public_numbers().n
        
        
        if self.sigma == False:
            x_0 = fS.select_from_S()
            hcbit = hcfunc.fun_B(x_0)
            y_1 = fS.select_from_S_dummy(pupkey)
            y_0 = forward.fun_F(alpha, x_0)
        else: # sigma = 1
            x_1 = fS.select_from_S()
            hcbit = hcfunc.fun_B(x_0)
            y_0 = fS.select_from_S_dummy(pupkey)
            y_1 = forward.fun_F(alpha, x_1)
        
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_ask
        otan = OT_ANNOUNCE.ot_seq
        y_0 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="y_0", payload=y_0)
        self.io.send(y_0)
        
        ## Sending  ------------------------
        cmd = Command.performing_ot_ask
        otan = OT_ANNOUNCE.ot_seq
        y_1 = self.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="y_0", payload=y_1)
        self.io.send(y_1)
        
        
        beta0 = self.io.recieve()
        command = json.loads(beta0)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "beta0", "Wrong OT seq command, expect alpha"
        beta0 = command["payload"]
        
        beta1 = self.io.recieve()
        command = json.loads(beta0)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "beta1", "Wrong OT seq command, expect alpha"
        beta1 = command["payload"]
        
        if self.sigma == False:
            bsel = hcbit ^ beta0
        else:
            bsel = hcbit ^ beta1
        
        self.bsel = bsel
        

        
    
class IOhandler:
    pass