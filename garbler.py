import copy
import json
from typing import List, Tuple
import numpy as np
import random
import os
from tqdm import tqdm
from cryptography.hazmat.primitives import hashes

from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from garblerpartyclass import IOWrapperServer
from gates import AndGate, Gate, InputWire, InterWire, OperatorGate, OrGate, XORGate, countWires, fill_nonce_material
from ot import selectionofferer
from ot_bitwise import selectionofferer_bitwise
from utils import maketokeybytes
from Crypto.Cipher import AES
from multiprocessing import Process, Lock



def permutegate(gate: Gate):
    """
    Removes the possibilty that the evaluator can deduce to which input pair a successfully decrypted row belongs to
    
    """
    random.shuffle(gate.rows)
    

def remove_plaintext_encoding(wire):
    """
    After the gate has been permuted, we have to remove any trace linking the label to their semantic input.
    Input: wire.
    This will recursively remove all labels 
    """
    
    if isinstance(wire, InterWire):
        gate = wire.gateref
        for input_gate in gate.input_gates:
            remove_plaintext_encoding(input_gate)
        
        wire.possiblelables = None
        if len(gate.table) == 4:
            
            gate.rows[0][0] = -1
            gate.rows[0][1] = -1
            gate.rows[1][0] = -1
            gate.rows[1][1] = -1
            gate.rows[2][0] = -1
            gate.rows[2][1] = -1
            gate.rows[3][0] = -1
            gate.rows[3][1] = -1
            
        elif len(gate.table) == 2:
            
            gate.rows[0][0] = -1
            gate.rows[1][0] = -1
            
        else:
            
            raise ValueError("Invalid gate table")
            
    # do not do anything to the input wires


def encrypt(plaintext, labels, nonce):
    
    key_bytes = maketokeybytes(labels)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce)
    fnonce = digest.finalize()
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=fnonce, use_aesni='True')
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return ciphertext, tag
    

def encryptgate(gate: OperatorGate, wirelables):
    """
    gate: Gate to encrypt
    
    wirelables: Array, |wirelables| = 4 | 2
                For |wirelables| = 4
                    wirelables = Wg0 We0 Wg1 We1
                For |wirelables| = 2
                    wirelables = W0 W1
    """
    
    
    if len(gate.table) == 4:
        assert len(wirelables) == 4, "Inadequate number of wire labels given"
        
        #gate.noncematerial[0] = gate.noncematerial[0] ^ 9
        g0, t0 = encrypt(gate.rows[0][2], (wirelables[0], wirelables[1]),gate.noncematerial )
        #gate.noncematerial[1] = gate.noncematerial[1] ^ 11
        g1, t1 = encrypt(gate.rows[1][2], (wirelables[0], wirelables[3]),gate.noncematerial )
        #gate.noncematerial[2] = gate.noncematerial[2] ^ 111
        g2, t2 = encrypt(gate.rows[2][2], (wirelables[2], wirelables[1]),gate.noncematerial )
        #gate.noncematerial[3] = gate.noncematerial[3] ^ 50
        g3, t3 = encrypt(gate.rows[3][2], (wirelables[2], wirelables[3]),gate.noncematerial )
        
        gate.rows[0][2] = g0
        gate.rows[1][2] = g1
        gate.rows[2][2] = g2
        gate.rows[3][2] = g3
        
        gate.rows[0][3] = t0
        gate.rows[1][3] = t1
        gate.rows[2][3] = t2
        gate.rows[3][3] = t3
        
    elif len(gate.table) == 2:
        assert len(wirelables) == 2, "Inadequate number of wire labels given"
        
        gate.noncematerial[3] = gate.noncematerial[3] ^ b'z'
        g0, t0 = encrypt(gate.rows[0][1], (wirelables[0]),gate.noncematerial )
        gate.noncematerial[2] = gate.noncematerial[2] ^ b'v'
        g1, t1 = encrypt(gate.rows[1][1], (wirelables[1]),gate.noncematerial )
        
        gate.rows[0][1] = g0
        gate.rows[1][1] = g1
        
        gate.rows[0][2] = t0
        gate.rows[1][2] = t1
        
    else:
        raise ValueError("Tried to encrypt incompatible gate")
    

def maskOutputGateWithLabel(gate, resultlables):
    """
    resultlables = [wV0, wV1]
    
    wVi is the label for the result wire having value i
    
    """    

    if gate.rows == []:
        
        gate.rows = copy.deepcopy(gate.table)
        
        for row in gate.rows:
            row.append(bytes(1)) # for later encryption tag
            tableresultvalue = row[-2] # the one before the last
            
            if tableresultvalue == 1:
                row[-2] = resultlables[1]
            else:
                row[-2] = resultlables[0]
        
        
        
def encryptsourcegate(gate):
    
    if len(gate.table) == 4:
        salt = os.urandom(32)
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"wg0ZEROBASE")
        digest.update(salt)
        Wg0 = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"we0ZEROANOTHER")
        digest.update(salt)
        We0 = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"wg1ZEROFIRST")
        digest.update(salt)
        Wg1 = digest.finalize()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"wg1ONEANOTHER")
        digest.update(salt)
        We1 = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoOneOne")
        digest.update(salt)
        wV1 = digest.finalize()
        
        maskOutputGateWithLabel(gate, [wV0, wV1])
        
        encryptgate(gate, [ Wg0 ,We0, Wg1, We1])
        
        return [wV0, wV1]
    
    
def garblewire(finalwire, pbar):
    """
    
    Garbles the gate and all precessor gates associated with the Interwire finalwire
    
    """
    
    
    if isinstance(finalwire, InputWire):
        if finalwire.possiblelables == None:
            
            salt = os.urandom(32)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(salt)
            digest.update(b"VALUEtargeoZEroZero")
            digest.update(salt)
            wV0 = digest.finalize()
            
            digest = hashes.Hash(hashes.SHA256())
            digest.update(salt)
            digest.update(b"VALUEtargeoOneOne")
            digest.update(salt)
            wV1 = digest.finalize()
            
            finalwire.possiblelables = [wV0, wV1]
            pbar.update()
            return finalwire.possiblelables
        else:
            return finalwire.possiblelables
    
    #
    # finalwire is InterWire !
    #
    
    gate = finalwire.gateref
    
    if gate.isgarbled == True:
        assert not(finalwire.possiblelables is None), "A gate has been garbled, but the plaintext labels are missing"
        return finalwire.possiblelables
    else:
        
        allwirelables = []
        
        if len(gate.input_gates) == 2:
            inputwireA, inputwireB = gate.input_gates
            
            [wV0_A, wV1_A] = garblewire(inputwireA,pbar)  # if input wire, then A is Garbler
            [wV0_B, wV1_B] = garblewire(inputwireB,pbar)  # if input wire, then B is Evaluator
            
            allwirelables = [wV0_A,wV0_B,wV1_A,wV1_B]
        elif len(gate.input_gates) == 1:
            inputwireA = gate.input_gates[0]
            
            [wV0_A, wV1_A] = garblewire(inputwireA,pbar)  # if input wire, then A is Garbler
            allwirelables = [wV0_A,wV1_A]
            
        
        salt = os.urandom(32)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoOneOne")
        digest.update(salt)
        wV1 = digest.finalize()
        
        finalwire.possiblelables = [wV0, wV1]
        
        maskOutputGateWithLabel(gate, [wV0, wV1])
        
        encryptgate(gate, allwirelables)
        
        gate.isgarbled = True
        pbar.update()
        
        return [wV0, wV1]


def parallel_OT_processor(initmsg, io,allInputWiresOfParty2,pbar ):
    
    askedid = initmsg["payloadcontext"]
    
    print("Resolving the wire id " + str(askedid))
    
    so = selectionofferer_bitwise(io, askedid) # grabbing the requested wire id
    
    askedid = so.askedid
    
    assert askedid in [w.id for w in allInputWiresOfParty2], "Violation in the protocol"
    
    inputwire = [w for w in allInputWiresOfParty2 if w.id == askedid][0]
    [l0, l1] = inputwire.possiblelables
    
    so.set_first_optionbit(l0) # actually do maybe with a full 256bit 
    so.set_second_optionbit(l1)
    
    so.do_protocol()
    
    pbar.update()


def parallel_OT_start(initmsg, io,allInputWiresOfParty2,pbar ):
    
    #p = Process( # TODO
    #        target=parallel_OT_processor, 
    #        args=(initmsg, io,allInputWiresOfParty2,pbar)
    #        )
    
    parallel_OT_processor(initmsg, io,allInputWiresOfParty2,pbar )
    
    #p.start()
    
        
def resolvingAllObliviousTransfers(io, inputwires, party1, party2):
    """
    Resolving the OTs

    Args:
        io (_type_): _description_
        inputwires (_type_): _description_
        party1 : the garbler (us)
        party2 : the evaluator (them)
    """
    
    print("Resolving the wire fetching...")
    
    sms = SysCmdStrings()

    allInputWiresOfParty1 = [w for w in inputwires if w.party == party1]
    allInputWiresOfParty2 = [w for w in inputwires if w.party == party2]  # < belong to evaluator: 
    
    numberofOTs = len(allInputWiresOfParty2)
    pbar = tqdm(total=numberofOTs)
    
    
    for i in range(len(allInputWiresOfParty2) + len(allInputWiresOfParty1)):    
        # all input wires are resolved now
        
        initmsg = io.receive()
        initmsg = sms.load_byte_to_object(initmsg)
        
        if initmsg["cmd"] == Command.performing_ot_ask and initmsg["otann"] == OT_ANNOUNCE.ot_wire_id:
            
            # OT
            
            parallel_OT_start(initmsg, io,allInputWiresOfParty2,pbar )
        
        elif initmsg["cmd"] == Command.performing_ot_ask and initmsg["otann"] == OT_ANNOUNCE.simple_ask:
            
            # Evaluator is asking for the wire label
            
            wireid = initmsg["payloadcontext"]
            
            assert wireid in [w.id for w in allInputWiresOfParty1], "Violation in the protocol"
            
            inputwire = [w for w in allInputWiresOfParty1 if w.id == wireid][0]
            [l0, l1] = inputwire.possiblelables
            
            assert not(inputwire.value is None), "Although this wire belongs to the garbler, we do not have a value stored for it"
            
            if inputwire.value == False:
                payload = l0
            elif inputwire.value == True:
                payload = l1
            else:
                raise ValueError("Invalid value in wire")  
            
            sms = SysCmdStrings()
            cmd = Command.performing_ot_give
            otan = OT_ANNOUNCE.simple_ask
            command = sms.makecommand(cmd=cmd, otann=otan, payloadcontext=wireid, payload=list(payload))
            io.send(command)
        else:
            raise ValueError("Violation in protocol")  

    
    pbar.close()
        
def establish(io, f):
    # io 
    # f is a wire
    
    
    if isinstance(f, InputWire):
        return
    
    sms = SysCmdStrings()
    c = Command.sending_circuit_rows
    currentwire = f
    
    currentgate = currentwire.gateref
    
    rows = currentgate.rows
    
    
    # convert rows consisting of arrays of arrays of bytes to arrays of arrays of lists 
    if len(currentgate.input_gates) == 2:
        newrows = [[bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)]]
        for i in range(4):
            for j in range(4):
                newrows[i][j] = list(bytes(rows[i][j]))
    else:
        newrows = [[bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1)]
                ]
        for i in range(2):
            for j in range(3):
                newrows[i][j] = list(bytes(rows[i][j]))
        
    command = sms.makecommand(cmd=c, otann=None, payloadcontext=None, payload=newrows)
    
    io.send(command)
    
    inputwires = currentgate.input_gates
    
    for wire in inputwires:
        establish(io,wire)
    
        
def main():
    
    """
    
         {-------------------------------.
      P1 {-----------.                   |               
                     |                   |
      P2 {----------AND---[b]----.       |                          1
         {-----------------.     |       |
                           |     |       |
                           |----OR-[c]--XOR---[d]---.|              2 3
                           |         |               |
                           |         |               |
                           |.-------AND-----[e]------OR-----[f]     4 5
    """
    
    # 
    #
    #
    #
    
    party1 = "garbler"
    party2 = "evaluator"
    
    p1a = InputWire(party1, 'first', True) #  gate3
    p1b = InputWire(party1, 'second',True) #  gate1
    
    p2a = InputWire(party2, 'third') #  gate1
    p2b = InputWire(party2, 'forth') #  gate2, gate4
    
    b = AndGate()(p1b, p2a)
    c = OrGate()(b, p2b)
    d = XORGate()(c, p1a)
    e = AndGate()(c, p2b)
    f = OrGate()(d, e)
    
    nonce = os.urandom(12)
    copynonce = copy.copy(nonce)
    fill_nonce_material(f, nonce)
    
    count = countWires(f)
    print("garbling in total "+str(count)+ " wires")
    
    pbar = tqdm(total=count)
    garblewire(f, pbar)
    pbar.close()
    
    io = IOWrapperServer()
    sms = SysCmdStrings()
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(generatecircuitstructure(f, ""), 'utf-8'))
    summaryhash = list(digest.finalize())
    
    summaryyaml = {}
    summaryyaml["summary"] = summaryhash  # TODO: add commitment scheme
    summaryyaml["nonce"] = list(copynonce)
    
    summarypackage = sms.makecommand(Command.checkcircuit, OT_ANNOUNCE.ot_seq, "", summaryyaml)
    

    io.startup()
    io.send(summarypackage)
    
    # waiting until the client is ready to receive the rows
    beginrequesting = io.receive()
    beginrequesting = sms.load_byte_to_object(beginrequesting)
    assert beginrequesting["cmd"] == Command.ready_to_receive_circuit_rows, "No receiving the circuitry"
    
    establish(io, f) # blocks, transmitts garbled, permuted rows only

    resolvingAllObliviousTransfers(io, [p1a,p1b,p2a,p2b], party1, party2)
    
    
    print("The output wires are")
    print("'1' \t - \t "+str(f.possiblelables[1]))
    print("'0' \t - \t "+str(f.possiblelables[0]))
    

main()

