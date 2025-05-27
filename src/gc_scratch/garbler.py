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
from garblertools.garblegates import garblethegate
from gates import AndGate, DFGate, Gate, InputWire, InterWire, NotGate, OperatorGate, OrGate, XORGate, enumerateAllGates_nonrec, fill_nonce_material, gate_can_be_evaluated, getallinputwires
from ot import selectionofferer
from ot_bitwise import selectionofferer_bitwise
from ot_hashinstHB import selectionofferer_hashins
from utils import deterministic_joining, maketokeybytes, xoring_bytearray
from Crypto.Cipher import AES
from multiprocessing import Process, Lock

from wireiterator import iter_wires


    

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

    



def make_to_previous_gates(gates):
    pass

def make_to_following_gates(gates):
    pass

def garblewire_nonrec(finalwire, DeltaKey):
    
    if isinstance(finalwire, InputWire):
        raise ValueError("The finalwire should not be a input wire")
    
    inputwires = getallinputwires(finalwire)
    
    
    """
    
    W^1_wireA = W^0_wireA + R
    W^1_wireB = W^0_wireB + R
    
    W^0_result = W^0_wireA + W^0_wireB
    
    implicitly:
    W^1_result = W^0_result + R
    
    """
    

    for iwire in inputwires:
        
        salt = os.urandom(32)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        
        wV1 = xoring_bytearray(wV0 , DeltaKey)
        
        iwire.possiblelables = [wV0, wV1]
    
    
    def check_if_wire_done(wire):
        return not (wire.possiblelables == [])
    
    for wires in iter_wires(inputwires,check_if_wire_done ):
        
        # obtain all gates of the wires
        
        resolvinggates = []
        for w in wires:
            deterministic_joining(resolvinggates, w.coupled_target_gates)
        
        # resolve the gates
        
        for gate in resolvinggates:
            
            if gate.isgarbled == True:
                assert not(gate.output_wire.possiblelables is None) and not(gate.output_wire.possiblelables == []), "A gate has been garbled, but the plaintext labels are missing"
            else:
                
                # trying to garble gate
                
                if not gate_can_be_evaluated(gate):
                    continue
                
                garblethegate(gate, DeltaKey)
                
                
                
    for gate in enumerateAllGates_nonrec(inputwires):
        if not isinstance(gate, XORGate):
            assert gate.isgarbled == True, "Missed garbling a gate"
    
        
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
        if not isinstance(gate, XORGate):
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
    
    

def simple_circ(party1, party2):
    
    p1s = []
    p2s = []
    

    p1s.append(InputWire(party1, 'inputparty1a', True))
    p1s.append(InputWire(party1, 'inputparty1b', True))
    
    p2s.append(InputWire(party2, 'inputparty2a'))
    p2s.append(InputWire(party2, 'inputparty2b'))

    a = AndGate("a gate")(p1s[1], p2s[1])
    b = NotGate("b gate")(a)
    c = XORGate("c gate")(b, a)
    d = XORGate("d gate")(p2s[0], c)

    v = AndGate()(
            NotGate()(OrGate()(
                AndGate()(
                        NotGate()(a),
                        b,
                ),
                c
            ))
            ,
            OrGate()(
                AndGate()(
                        NotGate()(c),
                        d,
                ),
                d
            )
            )

    e = AndGate()(
            NotGate()(OrGate()(
                AndGate()(
                        NotGate()(a),
                        v,
                ),
                c
            ))
            ,
            OrGate()(
                AndGate()(
                        NotGate()(c),
                        d,
                ),
                d
            )
            )


    t = XORGate()(v, e)

    return t
        

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

    newxor = addingblock(newxor)
    
    newxor = addingblock(newxor)
    
    finalarr = [newxor[0]]
    for i in range(1,len(newxor)):
        finalarr.append(XORGate()(finalarr[-1], newxor[i]))
    
    return finalarr[-1]
    
    
def main():
    

    
    party1 = "garbler"
    party2 = "evaluator"
    
    print("Generating initial circuit...")
    f = create_circ(party1, party2)  #create_circ(party1, party2)
    #f = create_circ(party1, party2)
    
    # 
    #
    #
    #
    

    cut_n_choose_lambda = 10
    stored_circuits = []
    stored_nonces = []
    stored_circuits_delta = []
    
    io = None
    sms = None
    io = IOWrapperServer()
    sms = SysCmdStrings()
    
    
    # checking public circuit 
    print("Hashing circuit...")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(generatecircuitstructure(f, ""), 'utf-8'))
    print("Circuit hashed")
    summaryhash = list(digest.finalize())
    summaryyaml = {}
    summaryyaml["summary"] = summaryhash  # TODO: add commitment scheme
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
        
        srcrnd = os.urandom(32)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(srcrnd)
        digest.update(b"VALUEtargeoZEroZero")
        digest.update(srcrnd)
        DeltaKey = digest.finalize()  # global delta key
        
        #count = countWires(circuitclone)
        #print("garbling in total "+str(count)+ " wires")

        #pbar = tqdm(total=count)
        
        
        garblewire_nonrec(circuitclone, DeltaKey)
        #garblewire(circuitclone)
        #pbar.close()

        stored_circuits.append(circuitclone)
        stored_nonces.append(nonce)
        stored_circuits_delta.append(DeltaKey)
    
    
    print("Waiting for client to be ready...")
    # waiting until the client is ready to receive the rows
    beginrequesting = io.receive()
    beginrequesting = sms.load_byte_to_object(beginrequesting)
    assert beginrequesting["cmd"] == Command.ready_to_receive_circuit_rows, "No receiving the circuitry"   
    
    print("Client is ready: Sending rows...")
    
    for newc in tqdm(range(cut_n_choose_lambda)):
        
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
    
    print("Sending openings of requested circuits..")
    
    for op in tqdm(listofcircuitstoopen):
        
        payload = list(stored_circuits_delta[op])
        pay = sms.makecommand(cmd = Command.giveacutnchoose, otann=None, payloadcontext="Delta", payload=payload)
        io.send(pay)
        
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
    
    print("Evaluator has confirmed trust in me.")
    
    #copynonce = copy.copy(nonce)
    #fill_nonce_material(f, nonce)
    
    #count = countWires(f)
    #print("garbling in total "+str(count)+ " wires")
    
    #pbar = tqdm(total=count)
    #garblewire(f, pbar)
    #pbar.close()
    
    #establish(io, f) # blocks, transmitts garbled, permuted rows only

    inputwires = getallinputwires(circ_to_be_used, [])
    
    print("Resolving OTs..")
    resolvingAllObliviousTransfers(io, inputwires, party1, party2)
    
    
    
    print("The output wires are")
    print("'1' \t - \t "+str(circ_to_be_used.possiblelables[1]))
    print("'0' \t - \t "+str(circ_to_be_used.possiblelables[0]))
    
main()
