

import copy
import random
from typing import List, Tuple
import numpy as np
from tqdm import tqdm
from Crypto.Cipher import AES
from circblocks import addingblock
from commandstrings import OT_ANNOUNCE, Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from cut_n_choose_naive import verify_functional_equality
from decryptiongate import decryptrow
from evaluatorpartyclass import IOWrapperClient
from gates import AccessRejectedGate, AndGate, DFGate, InputWire, InterWire, NotGate, OrGate, XORGate, checkGateIsQualified, countGates, countWires, enumerateAllGates, enumerateAllGates_nonrec, fill_nonce_material, getallinputwires
from ot import selectionselector
from ot_bitwise import selectionselector_bitwise
from ot_hashinstHB import selectorselector_hashins
from utils import maketokeybytes
from cryptography.hazmat.primitives import hashes

from wireiterator import iter_wires
    
    
def obliviously_select_label(wireid, io, plain_value):
    """
        This method is called from the perspective of the evaluator.
        
        This method blocks until the underlying OT (which blocks) is completed
    
    """
    
    # setup the oblivious transfer
    
    selsel = selectorselector_hashins(io, wireid) #selectionselector_bitwise(io, wireid)
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

def selectingAllObliviousTransfers(f, evalparty, io):
    
    ins = getallinputwires(f)
    
    for wire in ins:
        
        if isinstance(wire, InputWire):
            
            #if wire.value is None:
            if wire.party != evalparty:
                # wire stems from the garbler
                if wire.value is None:
                    wireid = wire.id
                    #print("Simple Requesting id "+ str(wireid))
                    # wirevalue is the label from the garbler
                    
                    wirevalue = request_gate_label_from_garbler(wireid,io)
                    wire.value = wirevalue
                    #pbar.update()
                else: 
                    print("Garbler wire has already been fetched")
                    
            else:
                # wire stems from the evaluator
                # we need to convert the bool value to a wire label
                if isinstance(wire.value, bool):
                    wireid = wire.id
                    #print("OT Requesting id "+ str(wireid))
                    plain_sigma = wire.value
                    assert not (plain_sigma is None), "The input wire comes from the evaluator, but "
                    
                    # wire stems from the evaluator (us).
                    # We have to obliviously select the wire label
                    
                    wirevalue = obliviously_select_label(wireid,io, plain_sigma)
                    wire.value = wirevalue
                    #pbar.update()
                    
                else:
                    pass
                    #print("We already converted the eval wire to a label value")

                
            assert not(wire.value is None), "Input wire label " +str(wire) + " could not be constructed"
        

def propagate_solver(wires, cG):
    """
    
    """
    
    pbar = tqdm(total=cG)
    
    newwires = []
    following_gates = []
    inputwires = wires
    
    def check_if_wire_done(wire):
        return not (wire.value is None)
    
    for wires in iter_wires(inputwires, check_if_wire_done):
        
        for w in wires:
            
            # evaluating all target gates of wire w
            targetgates = w.coupled_target_gates
            for t in targetgates:
                
                # target gate already evaluated
                if not(t.output_wire.value is None):
                    continue
                
                # checking if we can evaluate this gate
                ins = t.input_gates
                insvalues = [i.value for i in ins]
                if None in insvalues:
                    newwires.append(w)
                    continue
                
                # the gate t we can evaluate
                gate = t
                
                returnlabel = None
            
                # primitive brute-force gate evaluator
                for rowi in range(len(gate.rows)):
                    try:
                        returnlabel = decryptrow(gate,insvalues,rowi)
                        pbar.update()
                    except AccessRejectedGate as ae:
                        continue
                    except Exception as e:
                        print(str(e))
                        raise e

                assert not (returnlabel is None), "Failed to solve wire after gate " + str(gate)
            
                gate.output_wire.value = returnlabel
    
    
    
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
        

def readRows_nonrec(io, f):
    
    sms = SysCmdStrings()
    
    inputwires = getallinputwires(f)
    allgates = enumerateAllGates_nonrec(inputwires)
    
    for gate in allgates:
        
        command = io.receive()
        command = sms.load_byte_to_object(command)
        listrows = command["payload"]
        
        if len(gate.input_gates) == 2:
            
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

        gate.rows = newrows
    
    command = io.receive()
    command = sms.load_byte_to_object(command)
    possiblevaluesenc = command["payload"]
    
    f.possiblelables = [ bytes(possiblevaluesenc[0]), bytes(possiblevaluesenc[1]) ]

        
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
    
    

def simple_circ(party1, party2):
    
    p1s = []
    p2s = []
    
    p1s.append(InputWire(party1, 'inputparty1a'))
    p1s.append(InputWire(party1, 'inputparty1b'))
    
    p2s.append(InputWire(party2, 'inputparty2a', False))
    p2s.append(InputWire(party2, 'inputparty2b', False))

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
        
        p1s.append(InputWire(party1, 'plGAR'+str(i)))
    
    for i in range(linestrength):
        vv = random.choice([True,False])
        p2s.append(InputWire(party2, 'plEVA'+str(i), vv))
    
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
    
    cut_n_choose_lambda = 10
    stored_circuits = []
    
    #f = simple_circ(party1, party2)  # create_circ(party1, party2)
    f = create_circ(party1, party2)
    
    """
    p1a = InputWire(party1, 'first') #  gate3
    p1b = InputWire(party1, 'second') #  gate1
    
    p2a = InputWire(party2, 'third', False) #  gate1
    p2b = InputWire(party2, 'forth', True) #  gate2, gate4
    
    b = AndGate()(p1b, p2a)
    c = OrGate()(b, p2b)
    d = XORGate()(c, p1a)
    e = AndGate()(c, p2b)
    f = OrGate()(d, e)
    """
    
    
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
    
    assert summarytxt == calculatedsummary, "Different circuits used"
    
    for i in range(cut_n_choose_lambda):
        #ff = simple_circ(party1, party2) # create_circ(party1, party2)
        ff = create_circ(party1, party2)
        stored_circuits.append(ff)
    
    c = Command.ready_to_receive_circuit_rows
    command = sms.makecommand(cmd = c, otann=None, payloadcontext=None, payload=None)
    io.send(command)
    
    print("Receiving all circuits")
    for newc in tqdm(range(cut_n_choose_lambda)):
        
        selcirc = stored_circuits[newc]
        
        nonceraw = io.receive()
        noncepay = sms.load_byte_to_object(nonceraw)
        assert noncepay["cmd"] == Command.sending_circuit_nonce, "Not recieved a nonce"
        nonce = noncepay["payload"]
        nonce = bytes(nonce)
        fill_nonce_material(selcirc, nonce)
        
        readRows_nonrec(io, selcirc)
        #readRows(io, selcirc) # blocks, reads into the garbled, permuted rows into the circuit
        # All the possiblelables attributes on all wires are set to None 
    
    tobeverifiedcircuits = random.sample([a for a in range(cut_n_choose_lambda)], int(cut_n_choose_lambda/2))
    
    remainingcircuits = set([a for a in range(cut_n_choose_lambda)]) - set(tobeverifiedcircuits)
    circuitweuse = random.choice(list(remainingcircuits))
    
    askcontext = {
        'listofcircuitstoopen': list(tobeverifiedcircuits),
        'circuitweuse': circuitweuse
    }
    
    askforcuntnchoose = sms.makecommand(cmd=Command.askforcutnchoosever, otann=None, payloadcontext=askcontext, payload=None)
    io.send(askforcuntnchoose)
    
    print("Receiving openings of selected circuits...")
    for op in tqdm(tobeverifiedcircuits):
        circ_to_be_opened = stored_circuits[op]
        
        tobefilledinputwires = getallinputwires(circ_to_be_opened, [])
        
        for _ in range(len(tobefilledinputwires)):
            pay = io.receive()
            pay = sms.load_byte_to_object(pay)
            payloadcontext = pay["payloadcontext"]
            payload = pay["payload"]
            
            circid = payloadcontext["circuitid"]
            wireid = payloadcontext["circuitwires"]
            
            possiblelables = payload

            assert circid == op, "Provided the cut and choose circuits out of order"
            selectedwire = [w for w in tobefilledinputwires if w.id == wireid][0]
            
            selectedwire.possiblelables = [bytes(possiblelables[0]), bytes(possiblelables[1])]
            #print("obtained labels" + str(selectedwire.possiblelables))
            
    
    #pbar = tqdm(total=cut_n_choose_lambda)
    print("Verifying circuits....")
    for op in tqdm(tobeverifiedcircuits):
        
        circ_to_be_opened = stored_circuits[op]
        
        verify_functional_equality(circ_to_be_opened)
        
        #print("VERIF")
    
    print("Verification complete!")
    
    cutnchoosecomplete = sms.makecommand(cmd = Command.cutnchoosecompleted, otann= None,payloadcontext= None, payload=None)
    io.send(cutnchoosecomplete)
    
    f = stored_circuits[circuitweuse]
    
    #inputwires = [p1a,p1b,p2a,p2b]
    #allInputWiresOfParty2 = [w for w in inputwires if w.party == party2] 
    
    #numberofOTs = len(allInputWiresOfParty2)
    #count = countWires(f)
    cG = countGates(f)
    
    
    print("Resolving input wires...")
    selectingAllObliviousTransfers(f, party2, io)
    
    print("Solving circuit...")
    ins = getallinputwires(f) 
    
    propagate_solver(ins, cG)
    print("obtained value label: " + str(f.value))
    
    
    
    # breaking the pipe
    askforcuntnchoose = sms.makecommand(cmd=Command.askforcutnchoosever, otann=None, payloadcontext=askcontext, payload=None)
    io.send(askforcuntnchoose)


main()

