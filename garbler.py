import copy
import json
from typing import List, Tuple
import numpy as np
import random
import os
from tqdm import tqdm
from cryptography.hazmat.primitives import hashes

from circblocks import addingblock
from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from garblerpartyclass import IOWrapperServer
from gates import AndGate, DFGate, Gate, InputWire, InterWire, NotGate, OperatorGate, OrGate, XORGate, countWires, enumerateAllGates, enumerateAllGates_nonrec, fill_nonce_material, getallinputwires
from ot import selectionofferer
from ot_bitwise import selectionofferer_bitwise
from ot_hashinstHB import selectionofferer_hashins
from utils import deterministic_joining, maketokeybytes
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

        g0, t0 = encrypt(gate.rows[0][1], (wirelables[0]),gate.noncematerial )

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
        
            # kill the input labels
            row[-3] = 0
            row[0] = 0
        
        
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


def make_to_previous_gates(gates):
    pass

def make_to_following_gates(gates):
    pass

def garblewire_nonrec(finalwire):
    
    if isinstance(finalwire, InputWire):
        raise ValueError("The finalwire should not be a input wire")
    
    inputwires = getallinputwires(finalwire)
    
    for iwire in inputwires:
        
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
        
        iwire.possiblelables = [wV0, wV1]
    
    
    gates2garble = []
    for iw in inputwires:
        deterministic_joining(gates2garble, iw.coupled_target_gates)
    
     
    newgates2garble = gates2garble
    
    # gates2garble.append(inputwires)
    
    while True:
        
        did_a_garbling = False
        gates2garble = newgates2garble
        newgates2garble = []
        
        if gates2garble == []:
            # garbled all gates
            pass
        else:
            for gate in gates2garble:
                
                #gate = wire.gateref 
                if gate.isgarbled == True:
                    assert not(gate.output_wire.possiblelables is None) and not(gate.output_wire.possiblelables == []), "A gate has been garbled, but the plaintext labels are missing"
                else:
                    did_a_garbling = True
                    
                    # trying to garble gate
                    inputgates = gate.input_gates
                    notpossible = False
                    for ig in inputgates:
                        if ig.possiblelables == [] or (ig.possiblelables is None):
                            notpossible = True
                            
                    if notpossible == True:
                        # We can not garble the gate. We have to wait for a new round
                        
                        newgates2garble.append( gate )
                        
                    else:
                        # We can garble the gate

                        # 1. We generate output wires
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
                        
                        gate.output_wire.possiblelables = [wV0, wV1]
            
                        maskOutputGateWithLabel(gate, [wV0, wV1])
                        
                        if len(gate.input_gates) == 2:
                            
                            wV0_A = gate.input_gates[0].possiblelables[0]
                            wV1_A = gate.input_gates[0].possiblelables[1]
                            wV0_B = gate.input_gates[1].possiblelables[0]
                            wV1_B = gate.input_gates[1].possiblelables[1]
                            
                            allwirelables = [wV0_A,wV0_B,wV1_A,wV1_B]

                        else:
                            
                            assert len(gate.input_gates) == 1, "Unknown gate used"
                            
                            wV0_A = gate.input_gates[0].possiblelables[0]
                            wV1_A = gate.input_gates[0].possiblelables[1]
                            
                            allwirelables = [wV0_A,wV1_A]
                        
                        encryptgate(gate, allwirelables)
                        permutegate(gate)
                        
                        gate.isgarbled = True
                        
                        if gate.output_wire.coupled_target_gates == []:
                            pass
                            # this is one of the final wires
                        else:
                            newgates2garble = newgates2garble +  gate.output_wire.coupled_target_gates
    
        if did_a_garbling == False:
            break
        
def garblewire(finalwire):
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
            
            return finalwire.possiblelables
        else:
            return finalwire.possiblelables
    
    #
    # finalwire is InterWire !
    #
    
    gate = finalwire.gateref
    
    if gate.isgarbled == True:
        assert not(finalwire.possiblelables == []), "A gate has been garbled, but the plaintext labels are missing"
        return finalwire.possiblelables
    else:
        
        allwirelables = []
        
        if len(gate.input_gates) == 2:
            inputwireA, inputwireB = gate.input_gates
            
            [wV0_A, wV1_A] = garblewire(inputwireA)  # if input wire, then A is Garbler
            [wV0_B, wV1_B] = garblewire(inputwireB)  # if input wire, then B is Evaluator
            
            allwirelables = [wV0_A,wV0_B,wV1_A,wV1_B]  
        elif len(gate.input_gates) == 1:
            inputwireA = gate.input_gates[0]
            
            [wV0_A, wV1_A] = garblewire(inputwireA)  # if input wire, then A is Garbler
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
        
        
        return [wV0, wV1]
        
        
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
            
            askedid = initmsg["payloadcontext"]
            
            #print("Resolving the wire id " + str(askedid))
            
            so = selectionofferer_hashins(io, askedid) #selectionofferer_bitwise(io, askedid) # grabbing the requested wire id
            
            askedid = so.askedid
            
            assert askedid in [w.id for w in allInputWiresOfParty2], "Violation in the protocol"
            
            inputwire = [w for w in allInputWiresOfParty2 if w.id == askedid][0]
            [l0, l1] = inputwire.possiblelables
            
            so.set_first_optionbit(l0) # actually do maybe with a full 256bit 
            so.set_second_optionbit(l1)
            
            so.do_protocol()
            
            pbar.update()
        
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
        

def establish_nonrec(io, f):
    """
    Establish the encrypted wire rows

    """
    sms = SysCmdStrings()
    c = Command.sending_circuit_rows
    
    ins = getallinputwires(f)
    
    allgates = enumerateAllGates_nonrec(ins)
    
    for gate in allgates:
        rows = gate.rows 
        if len(gate.input_gates) == 2:
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
        
    possiblevalueenc = [ list(bytes(f.possiblelables[0])), list(bytes(f.possiblelables[1])) ]
    command = sms.makecommand(cmd=c, otann=None, payloadcontext=None, payload=possiblevalueenc)
    io.send(command)
    

def establish(io, f):
    # io 
    # f is a wire
    
    
    sms = SysCmdStrings()
    allgates = enumerateAllGates(f)
    
    c = Command.sending_circuit_rows
    
    
    for gate in allgates:
        
        rows = gate.rows
        # convert rows consisting of arrays of arrays of bytes to arrays of arrays of lists 
        if len(gate.input_gates) == 2:
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
    

def simple_circ(party1, party2):
    
    p1s = []
    p2s = []
    
    linestrength = 10
    for i in range(linestrength):
        vv = random.choice([True,False])
        p1s.append(InputWire(party1, 'plGAR'+str(i), vv))
    
    for i in range(linestrength):
        p2s.append(InputWire(party2, 'plEVA'+str(i)))

    firstands = []
    for i in range(linestrength):
        firstands.append(AndGate()(p1s[i], p2s[i]))
        
    xorinline = []
    xorinline.append(XORGate()(firstands[0], firstands[1]))
    for i in range(2,linestrength):
        xorinline.append(XORGate()(xorinline[-1], firstands[i]))
        
    f = xorinline[-1]
    return f
        

def create_circ(party1, party2):
    
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
                           
                           
        P1 { - 300b    ---------------------------NOT--------XOR------
                            AND           |                         |
        P2 { - 300b    ------ |  ---------.-[0,2]AND-----------     |
                              |                               |     |
                              |____ XOR ___                   |     |
                              |             |                 |     |
                              |             |                 |     |
                              |             |_______________ AND___AND___
                              |                         |                  |  
                              |_[10,30]-NOT-.           |                  |
                              |            XOR---NOT---OR---NOT----------OR --- [f]
                              |__[9,29]---- ^
                           
    """
    
    
    p1s = []
    p2s = []
    
    linestrength = 50
    for i in range(linestrength):
        vv = random.choice([True,False])
        p1s.append(InputWire(party1, 'plGAR'+str(i), vv))
    
    for i in range(linestrength):    
        p2s.append(InputWire(party2, 'plEVA'+str(i)))
    
    
    startxor = []
    for i in range(len(p1s)):
        startxor.append(XORGate()(p1s[i], p2s[i]) ) 
    
    newxor = addingblock(startxor)
    
    newxor = addingblock(newxor)
    
    return newxor[2]
    
    
def main():
    

    
    party1 = "garbler"
    party2 = "evaluator"
    
    #f = simple_circ(party1, party2)  #create_circ(party1, party2)
    f = create_circ(party1, party2)
    
    # 
    #
    #
    #
    

    cut_n_choose_lambda = 50
    stored_circuits = []
    stored_nonces = []
    
    
    io = IOWrapperServer()
    sms = SysCmdStrings()
    
    
    # checking public circuit 
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(generatecircuitstructure(f, ""), 'utf-8'))
    summaryhash = list(digest.finalize())
    summaryyaml = {}
    summaryyaml["summary"] = summaryhash  # TODO: add commitment scheme
    #summaryyaml["nonce"] = list(copynonce)
    summarypackage = sms.makecommand(Command.checkcircuit, OT_ANNOUNCE.ot_seq, "", summaryyaml)
    io.startup()
    io.send(summarypackage)
    
    print("garbling circuits...")
    for newc in tqdm(range(cut_n_choose_lambda)):
        
        #circuitclone = simple_circ(party1, party2)  #create_circ(party1, party2)
        circuitclone = create_circ(party1, party2)
        
        nonce = os.urandom(12)
        #copynonce = copy.copy(nonce)
        fill_nonce_material(circuitclone, nonce)
        
        #count = countWires(circuitclone)
        #print("garbling in total "+str(count)+ " wires")

        #pbar = tqdm(total=count)
        garblewire_nonrec(circuitclone)
        #garblewire(circuitclone)
        #pbar.close()

        stored_circuits.append(circuitclone)
        stored_nonces.append(nonce)
        
    print("Establishing client contact...")
    # waiting until the client is ready to receive the rows
    beginrequesting = io.receive()
    beginrequesting = sms.load_byte_to_object(beginrequesting)
    assert beginrequesting["cmd"] == Command.ready_to_receive_circuit_rows, "No receiving the circuitry"   
    
    
    print("Sending rows...")
    
    for newc in range(cut_n_choose_lambda):
        
        noncei = stored_nonces[newc]
        noncesend = sms.makecommand(cmd = Command.sending_circuit_nonce, otann=None, payloadcontext="", payload=list(noncei))
        io.send(noncesend)
        
        establish_nonrec(io, stored_circuits[newc])
        #establish(io, stored_circuits[newc])
    
    
    requestingcuntnchooseopening = io.receive()
    requestingcuntnchooseopening = sms.load_byte_to_object(requestingcuntnchooseopening)
    assert requestingcuntnchooseopening["cmd"] == Command.askforcutnchoosever, "Why not performing cut&choose?"  
    listofcircuitstoopen = requestingcuntnchooseopening["payloadcontext"]["listofcircuitstoopen"]
    circuitweuse = requestingcuntnchooseopening["payloadcontext"]["circuitweuse"]
    
    for op in listofcircuitstoopen:
        
        circ_to_be_opened = stored_circuits[op]
        
        allinputwires = getallinputwires(circ_to_be_opened, [])
        
        for inputwire in allinputwires:
            
            wirelabels = inputwire.possiblelables
            
            contextdicts = {'circuitid': op,
                            'circuitwires': inputwire.id}
            
            payload = [list(wirelabels[0]), list(wirelabels[1])]
            
            pay = sms.makecommand(cmd = Command.giveacutnchoose, otann= None, payloadcontext=contextdicts, payload=payload)
            io.send(pay)
        
    circ_to_be_used = stored_circuits[circuitweuse]
    
    
    cutnchoosecompleted = io.receive()
    cutnchoosecompleted = sms.load_byte_to_object(cutnchoosecompleted)
    assert cutnchoosecompleted["cmd"] == Command.cutnchoosecompleted, "Garbler has failed to provide security"  
    
    
    #copynonce = copy.copy(nonce)
    #fill_nonce_material(f, nonce)
    
    #count = countWires(f)
    #print("garbling in total "+str(count)+ " wires")
    
    #pbar = tqdm(total=count)
    #garblewire(f, pbar)
    #pbar.close()
    
    #establish(io, f) # blocks, transmitts garbled, permuted rows only

    inputwires = getallinputwires(circ_to_be_used, [])
    
    
    resolvingAllObliviousTransfers(io, inputwires, party1, party2)
    
    
    print("The output wires are")
    print("'1' \t - \t "+str(circ_to_be_used.possiblelables[1]))
    print("'0' \t - \t "+str(circ_to_be_used.possiblelables[0]))
    

main()

