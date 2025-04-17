

from multiprocessing import Process, Lock

from commandstrings import OT_ANNOUNCE, Command
from ot import FunctionHardCoreB, FunctionI, FunctionInvF
from cryptography.hazmat.primitives import serialization


def perform_ot_selectofferer(seloff_obj, lock):
    

    basecmdstr = str(seloff_obj.askedid) + "ASK:"+str(seloff_obj.otid)+":"
    
    assert not (seloff_obj.b0 is None or  seloff_obj.b1 is None), "Initialize first!"
        
    iin = FunctionI()
    
    (pupkey, privkey) = iin.generate(seloff_obj)
    alpha = iin.alpha
    
    backward = FunctionInvF(privkey)
    
    hcpred = FunctionHardCoreB(alpha)
    
    ## Sending  ------------------------
    cmd = Command.performing_ot_give
    otan = OT_ANNOUNCE.ot_seq
    alphac = seloff_obj.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="alpha", payload=alpha)
    
    lock.a
    io.announcesend(basecmdstr + "alpha")
    seloff_obj.io.send(alphac)
    lock.r
    
    ## Sending  ------------------------
    cmd = Command.performing_ot_give
    otan = OT_ANNOUNCE.ot_seq
    sendpupkey = list(pupkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    pupkey = seloff_obj.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="pupkey", payload=sendpupkey) # to byte array
    
    lock.a
    io.announcesend(basecmdstr + "pupkey")
    seloff_obj.io.send(pupkey)
    lock.r
    
    
    ## Recieving  ------------------------
    
    lock.a
    io.announcereceive(basecmdstr + "y0")
    y0 = seloff_obj.io.receive()
    lock.r
    
    command = seloff_obj.sms.load_byte_to_object(y0)
    assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
    assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
    assert command["payloadcontext"] == "y0", "Wrong OT seq command, expect alpha"
    y0 = bytes(command["payload"])
    
    ## Recieving  ------------------------
    lock.a
    io.announcereceive(basecmdstr + "y1")
    y1 = seloff_obj.io.receive()
    lock.r
    
    command = seloff_obj.sms.load_byte_to_object(y1)
    assert command["cmd"] == Command.performing_ot_ask, "Wrong OT seq command"
    assert command["otann"] == OT_ANNOUNCE.ot_seq, "Wrong OT seq command"
    assert command["payloadcontext"] == "y1", "Wrong OT seq command, expect alpha"
    y1 = bytes(command["payload"])
    
    
    x0 = backward.fun_invF(alpha, y0)
    x1 = backward.fun_invF(alpha, y1)
    
    beta0 = hcpred.fun_B(int.from_bytes(x0, 'big')) ^ seloff_obj.b0
    beta1 = hcpred.fun_B(int.from_bytes(x1, 'big')) ^ seloff_obj.b1
    
    
    ## Sending  ------------------------
    cmd = Command.performing_ot_give
    otan = OT_ANNOUNCE.ot_seq
    beta0 = seloff_obj.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta0", payload=beta0)
    
    lock.a
    io.announcesend(basecmdstr + "beta0")
    seloff_obj.io.send(beta0)
    lock.r
    
    ## Sending  ------------------------
    
    cmd = Command.performing_ot_give
    otan = OT_ANNOUNCE.ot_seq
    beta1 = seloff_obj.sms.makecommand(cmd=cmd, otann=otan,payloadcontext="beta1", payload=beta1)
    
    lock.a
    io.announcesend(basecmdstr + "beta1")
    seloff_obj.io.send(beta1)
    lock.r

    
    