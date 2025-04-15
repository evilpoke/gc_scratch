
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

def hash(in_input):
    in_input = in_input.to_bytes(4096, byteorder='big')
    digest = hashes.Hash(hashes.SHA256())
    
    digest.update(b"abc")
    digest.update(in_input)
    
    return digest.finalize()

def hash2(in_input):
    in_input = in_input.to_bytes(4096, byteorder='big')
    digest = hashes.Hash(hashes.SHA256())
    
    digest.update(b"cba")
    digest.update(in_input)
    
    return digest.finalize()

def hash3(in_input):
    
    in_input = in_input.to_bytes(4096, byteorder='big')
    digest = hashes.Hash(hashes.SHA256())
    
    digest.update(b"entgegengegangen")
    digest.update(in_input)
    
    return digest.finalize()

def hash4(in_input):
    in_input = in_input.to_bytes(4096, byteorder='big')
    digest = hashes.Hash(hashes.SHA256())
    
    digest.update(b"flugangst")
    digest.update(in_input)
    
    return digest.finalize()


class FunctionS:
    """
    S is a selector on a group Z*n where n is a number of 4096 bit. 
    
    S chooses from 1..n
    
    """
    
    def __init__(self):
        self.pubkey = None
    
    
    def select_from_S(self):
        """
        Securely selects randomly from the multi-add group 
        """
        
        cryptogen = SystemRandom()
        
        ultirange = 125 << 511
        rnd = cryptogen.randrange(  ultirange  )
        
        rnd = rnd % self.pubkey.public_numbers().n
        
        invrnd = rsa._modinv(self.pubkey.public_numbers().e, rnd)
        
        invrnd = invrnd % self.pubkey.public_numbers().n
        
        return invrnd
    
    
    def select_from_S_dummy(self, pupkey, alpha):
        
        dummy_S = self.select_from_S()
        
        pred_value = hash(alpha)
        pred2_value = hash2(alpha)
        
        rr = int(dummy_S.bit_length() // 8) + 1 if (dummy_S.bit_length() % 8 != 0) else int(dummy_S.bit_length() / 8)  
        
        y_sigma = pupkey.encrypt(    dummy_S.to_bytes(rr,'big'), # TODO << as with the other function 
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
        self.exp = 65537
        self.pubkey = None
        

    def generate(self, party):
        """
        Generates a key pair
        
        returns: RSAPublicKey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey 
        """
        assert isinstance(party,selectionofferer), "The party selecting one of the choices can not generate the trapdoor"
        
        # key generation
        rSAprivatekey =  generate_private_key(self.exp, 4096)
        rsapublickey = rSAprivatekey.public_key()
        self.pubkey = rsapublickey
        
        # generating alpha
        cryptogen = SystemRandom()
        ultirange = 125 << 511  # 4096
        rnd = cryptogen.randrange(  ultirange  )
        rnd = rnd % self.pubkey.public_numbers().n
        self.alpha = rsa._modinv(self.pubkey.public_numbers().e, rnd)
        
        return rsapublickey, rSAprivatekey
    
    def pull_pub_material(self):
        return (self.pubkey, self.alpha)

class FunctionF:
    
    def __init__(self, publickey):
        self.pubkey = publickey
    
    
    def fun_F(self, alpha, x):
        
        pred2_value = hash2(alpha)
        
        rr = int(x.bit_length() // 8) + 1 if (x.bit_length() % 8 != 0) else int(x.bit_length() / 8)  
        
        y_sigma = self.pubkey.encrypt(    x.to_bytes(rr,'big'),   #  *pred_value_comp,  << TODO include back. currently to risky 
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
        cipher = Cipher(algorithms.AES(self.hashed_alpha), modes.CTR(iv[0:16]))
        encryptor = cipher.encryptor()
        ct = encryptor.update(x.to_bytes(4096, 'big'))
        
        #return ct[0] # will return a byte (not a bit)
        return ct[0] <= 127

class selectionofferer:
    def __init__(self, io, askedid):
        self.b0 = None
        self.b1 = None
        self.io = io
        self.sms = SysCmdStrings()
        
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
        
        beta0 = hcpred.fun_B(int.from_bytes(x0, 'big')) ^ self.b0
        beta1 = hcpred.fun_B(int.from_bytes(x1, 'big')) ^ self.b1
        
        
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
        
        hcfunc = FunctionHardCoreB(alpha)
        
        fS.modulus_n = pupkey.public_numbers().n
        fS.pubkey = pupkey
        
        if self.sigma == False:
            x_0 = fS.select_from_S()
            hcbit = hcfunc.fun_B(x_0)
            y_1 = fS.select_from_S_dummy(pupkey, alpha)
            y_0 = forward.fun_F(alpha, x_0)
        else: # sigma = 1
            x_1 = fS.select_from_S()
            hcbit = hcfunc.fun_B(x_1)
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
        beta0 = command["payload"]
        
        beta1 = self.io.receive()
        command = self.sms.load_byte_to_object(beta1)
        assert command["cmd"] == Command.performing_ot_give, "Wrong OT seq command"
        assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
        assert command["payloadcontext"] == "beta1", "Wrong OT seq command, expect alpha"
        beta1 = command["payload"]
        
        if self.sigma == False:
            bsel = hcbit ^ beta0
        else:
            bsel = hcbit ^ beta1
        
        self.bsel = bsel
        #try:
        #    self.io.send(b'EOF')
        #except Exception as e:
        #    print("exited connection")
        
    
class IOhandler:
    pass