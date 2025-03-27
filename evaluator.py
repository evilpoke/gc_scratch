
import json
from typing import List, Tuple
import numpy as np
import json
from Crypto.Cipher import AES
from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from evaluatorpartyclass import IOWrapperClient
from gates import AccessRejectedGate, AndGate, InputWire, InterWire, OrGate, XORGate
from ot import selectionselector

    

def maketokeybytes(t):
    # tuple t of size 2 or 1
    pass

def decrypt(row, t , nonce, tag):

    key_bytes = maketokeybytes(t)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce, use_aesni='True')
    plaintext_as_bytes = cipher.decrypt(row)
    try:
        cipher.verify(tag)
    except ValueError:
        return False
    
    return plaintext_as_bytes


def decryptrow(gate, labels, i, nonce):
    """
    gate: Gate to encrypt
    
    labels: Array of lables required to access the gate

    i:  row to decrypt
    
    returns: Decrypted bit/label or Exception
    """
    
    if len(labels) == 2:
        assert gate.rows == 4, "Wrong number of gate / labels"
        
        # We have a 2 bit gate on our hand
        
        
        g0 = decrypt(gate.rows[i][2], (labels[0], labels[1]) , nonce, gate.rows[i][3])
        if g0 == False:
            raise AccessRejectedGate("R: "+str(i))
        else:
            return g0
        
    elif len(labels) == 1:
        assert gate.rows == 2, "Wrong number of gate / labels"
        
        g0 = decrypt(gate.rows[i][1], (labels[0], labels[1]) , nonce, gate.rows[i][2])
        
    else:
        raise ValueError("Invalid gate")
    
    
def obliviously_select_label(wireid, io, plain_value):
    """
        This method is called from the perspective of the evaluator.
        
        This method blocks until the underlying OT (which blocks) is completed
    
    """
    
    # setup the oblivious transfer
    

    
    selsel = selectionselector(io, wireid)
    selsel.set_sigma(plain_value)
    
    selsel.do_protocol()
    return selsel.w_bsel


def request_gate_label_from_garbler(wireid, io):
    
    sms = SysCmdStrings
    cmd = Command.performing_ot_ask
    otan = OT_ANNOUNCE.simple_ask
    command = sms.makecommand(cmd=cmd, otann=otan, payloadcontext=wireid, payload=None)
    io.send(command)
    
    wirelabel = io.recieve()
    wirelabel = json.load(wirelabel)
    wirelabel = wirelabel["payload"]
    
    
    return wirelabel


def solve(wire: InterWire, evalparty, io):
    """
    Calling this method will lead to the 'value'-attribute in the InterWire object to be filled
    
    :param wire: InterWire object
    :param evalparty: The party evaluating the circuit. The evaluation party needs to be the evaluator. Otherwise this code does simply not work
    
    """
    
    nonce = None # TODO <<
    
    if isinstance(wire, InputWire):
        
        if wire.party != evalparty:
            # wire stems from the garbler
            
            # wirevalue is the label from the garbler
            wireid = wire.id
            wirevalue = request_gate_label_from_garbler(wireid,io)
            wire.value = wirevalue
            
        else:
            
            plain_sigma = wire.value
            assert not (plain_sigma is None), "The input wire comes from the evaluator, but "
            
            # wire stems from the evaluator (us).
            # We have to obliviously select the wire label
            wireid = wire.id
            wirevalue = obliviously_select_label(wireid,io, plain_sigma)
            wire.value = wirevalue
    
        assert not(wire.value is None), "Input wire label " +str(wire) + " could not be constructed"
    
    else:
        
        assert isinstance(wire, InterWire), "Non-input wires have to be intermediate wires"
    
        
        gate = wire.gateref
        inputwires = gate.input_gates
        for w in inputwires:
            solve(w)
        
        # extracting labels
        labels = []
        for w in inputwires:
            labels.append(w.value)
        
        print("Solving gate "+str(gate)+"...")
        
        returnlabel = None
        
        # primitive brute-force gate evaluator
        for rowi in range(len(gate.rows)):
            try:
                returnlabel = decryptrow(gate,labels,rowi,nonce)
            except AccessRejectedGate as ae:
                continue
            except Exception as e:
                print(str(e))
                raise e

        assert not (returnlabel is None), "Failed to solve wire after gate " + str(gate)
        
        wire.value = returnlabel
        assert not(wire.value is None), "Intermediate wire label " +str(wire) + " could not be constructed"
        
            
def readRows(io, f):
    
    if isinstance(f, InputWire):
        return
    
    currentwire = f
    currentgate = currentwire.gateref
    
    command = io.recieve()
    currentgate.rows = command["payload"]
    
    
    inputwires = currentgate.input_gates
    
    for wire in inputwires:
        readRows(io,wire)
    
    
def main():
    
    
    """
    
         {-------------------------------.
      P1 {-----------.                   |               
                     |                   |
      P2 {----------AND----------.       |                          1
         {-----------------.     |       |
                           |     |       |
                           |----OR---.--XOR---------.|              2 3
                           |         |               |
                           |         |               |
                           |.-------AND--------------OR------ ()    4 5
    """
    
    party1 = "garbler"
    party2 = "evaluator"
    
    p1a = InputWire(party1, 'first') #  gate3
    p1b = InputWire(party1, 'second') #  gate1
    
    p2a = InputWire(party2, 'third', 0) #  gate1
    p2b = InputWire(party2, 'forth', 1) #  gate2, gate4
    
    b = AndGate()(p1b, p2a)
    c = OrGate()(b, p2b)
    d = XORGate()(c, p1a)
    e = AndGate()(c, p2b)
    f = OrGate()(d, e)
    
    
    io = IOWrapperClient()
    
    calculatedsummary = generatecircuitstructure(f, "")
    
    summary = io.receive()
    summary = json.loads(summary)
    
    assert summary == calculatedsummary, "Different circuits used"
    
    sms = SysCmdStrings()
    c = Command.ready_to_receive_circuit_rows
    command = sms.makecommand(cmd = c, otann=None, payloadcontext=None, payload=None)
    io.send(command)
    
    readRows(io, f) # blocks, reads into the garbled, permuted rows into the circuit
    # All the possiblelables attributes on all wires are set to None 
    
    solve(f, party2, io)


main()

