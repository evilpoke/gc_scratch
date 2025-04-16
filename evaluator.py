

from typing import List, Tuple
import numpy as np
from tqdm import tqdm
from Crypto.Cipher import AES
from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from evaluatorpartyclass import IOWrapperClient
from gates import AccessRejectedGate, AndGate, InputWire, InterWire, OrGate, XORGate, countWires, fill_nonce_material
from ot import selectionselector
from ot_bitwise import selectionselector_bitwise
from utils import maketokeybytes
from cryptography.hazmat.primitives import hashes

def decrypt(row, t , nonce, tag):

    key_bytes = maketokeybytes(t)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce)
    fnonce = digest.finalize()
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=fnonce, use_aesni='True')
    plaintext_as_bytes = cipher.decrypt(row)
    try:
        cipher.verify(tag)
    except ValueError:
        return False
    
    return plaintext_as_bytes


def decryptrow(gate, labels, i):
    """
    gate: Gate to encrypt
    
    labels: Array of lables required to access the gate

    i:  row to decrypt
    
    returns: Decrypted bit/label or Exception
    """
    
    nonce = gate.noncematerial
    
    if len(labels) == 2:
        assert len(gate.rows) == 4, "Wrong number of gate / labels"
        
        # We have a 2 bit gate on our hand
        
        
        g0 = decrypt(gate.rows[i][2], (labels[0], labels[1]) , nonce, gate.rows[i][3])
        if g0 == False:
            raise AccessRejectedGate("R: "+str(i))
        else:
            return g0
        
    elif len(labels) == 1:
        assert len(gate.rows) == 2, "Wrong number of gate / labels"
        
        g0 = decrypt(gate.rows[i][1], (labels[0], labels[1]) , nonce, gate.rows[i][2])
        
    else:
        raise ValueError("Invalid gate")
    
    
def obliviously_select_label(wireid, io, plain_value):
    """
        This method is called from the perspective of the evaluator.
        
        This method blocks until the underlying OT (which blocks) is completed
    
    """
    
    # setup the oblivious transfer
    
    selsel = selectionselector_bitwise(io, wireid)
    selsel.announce_selection()
    
    selsel.set_sigma(plain_value)
    
    selsel.do_protocol()
    return bytes(selsel.bsel)


def request_gate_label_from_garbler(wireid, io):
    
    sms = SysCmdStrings()
    cmd = Command.performing_ot_ask
    otan = OT_ANNOUNCE.simple_ask
    command = sms.makecommand(cmd=cmd, otann=otan, payloadcontext=wireid, payload=wireid)
    io.send(command)
    
    wirelabel = io.receive()
    wirelabel = sms.load_byte_to_object(wirelabel)
    wirelabel = bytes(wirelabel["payload"])
    
    
    return wirelabel


def solve(wire: InterWire, evalparty, io, pbar):
    """
    Calling this method will lead to the 'value'-attribute in the InterWire object to be filled
    
    :param wire: InterWire object
    :param evalparty: The party evaluating the circuit. The evaluation party needs to be the evaluator. Otherwise this code does simply not work
    
    """
    
    
    if isinstance(wire, InputWire):
        
        #if wire.value is None:
        if wire.party != evalparty:
            # wire stems from the garbler
            if wire.value is None:
                wireid = wire.id
                print("Simple Requesting id "+ str(wireid))
                # wirevalue is the label from the garbler
                
                wirevalue = request_gate_label_from_garbler(wireid,io)
                wire.value = wirevalue
                pbar.update()
            else: 
                print("Garbler wire has already been fetched")
                
        else:
            # wire stems from the evaluator
            # we need to convert the bool value to a wire label
            if isinstance(wire.value, bool):
                wireid = wire.id
                print("OT Requesting id "+ str(wireid))
                plain_sigma = wire.value
                assert not (plain_sigma is None), "The input wire comes from the evaluator, but "
                
                # wire stems from the evaluator (us).
                # We have to obliviously select the wire label
                
                wirevalue = obliviously_select_label(wireid,io, plain_sigma)
                wire.value = wirevalue
                pbar.update()
                
            else:
                print("We already converted the eval wire to a label value")

            
        assert not(wire.value is None), "Input wire label " +str(wire) + " could not be constructed"
    
    else:
        
        assert isinstance(wire, InterWire), "Non-input wires have to be intermediate wires"
    
        
        gate = wire.gateref
        inputwires = gate.input_gates
        for w in inputwires:
            solve(w, evalparty,io,pbar)
        
        # extracting labels
        labels = []
        for w in inputwires:
            labels.append(w.value)
        
        print("Solving gate "+str(gate)+"...")
        
        returnlabel = None
        
        # primitive brute-force gate evaluator
        for rowi in range(len(gate.rows)):
            try:
                returnlabel = decryptrow(gate,labels,rowi)
            except AccessRejectedGate as ae:
                continue
            except Exception as e:
                print(str(e))
                raise e

        assert not (returnlabel is None), "Failed to solve wire after gate " + str(gate)
        
        wire.value = returnlabel
        pbar.update()
        assert not(wire.value is None), "Intermediate wire label " +str(wire) + " could not be constructed"
        
            
def readRows(io, f):
    
    if isinstance(f, InputWire):
        return
    
    currentwire = f
    currentgate = currentwire.gateref
    sms = SysCmdStrings()
    
    command = io.receive()
    command = sms.load_byte_to_object(command)
    listrows = command["payload"]
    
    if len(currentgate.input_gates) == 2:
        
        newrows = [[bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1),bytes(1)]]
        
        for i in range(4):
            for j in range(4):
                newrows[i][j] = bytes(listrows[i][j])
                
    else:
        newrows = [[bytes(1),bytes(1),bytes(1)],
                [bytes(1),bytes(1),bytes(1)]
                ]
        
        for i in range(2):
            for j in range(3):
                newrows[i][j] = bytes(listrows[i][j])
    
    currentgate.rows = newrows
    
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
    
    p2a = InputWire(party2, 'third', False) #  gate1
    p2b = InputWire(party2, 'forth', True) #  gate2, gate4
    
    b = AndGate()(p1b, p2a)
    c = OrGate()(b, p2b)
    d = XORGate()(c, p1a)
    e = AndGate()(c, p2b)
    f = OrGate()(d, e)
    
    io = IOWrapperClient()
    sms = SysCmdStrings()
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(generatecircuitstructure(f, ""), 'utf-8'))
    calculatedsummary = digest.finalize()
    
    
    io.startup()
    summary = io.receive()
    recievedsummary = sms.load_byte_to_object(summary)
    recievedsummary = recievedsummary["payload"]
    summarytxt = bytes(recievedsummary["summary"])
    initnonce = bytes(recievedsummary["nonce"])
    
    fill_nonce_material(f, initnonce)
    
    assert summarytxt == calculatedsummary, "Different circuits used"
    
    
    c = Command.ready_to_receive_circuit_rows
    command = sms.makecommand(cmd = c, otann=None, payloadcontext=None, payload=None)
    io.send(command)
    
    readRows(io, f) # blocks, reads into the garbled, permuted rows into the circuit
    # All the possiblelables attributes on all wires are set to None 
    
    
    inputwires = [p1a,p1b,p2a,p2b]
    allInputWiresOfParty2 = [w for w in inputwires if w.party == party2] 
    
    numberofOTs = len(allInputWiresOfParty2)
    count = countWires(f)
    pbar = tqdm(total=count)
    solve(f, party2, io, pbar)
    pbar.close()
    
    print(str(f.value))


main()

