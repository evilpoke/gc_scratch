import copy
import json
from typing import List, Tuple
import numpy as np

import os

from cryptography.hazmat.primitives import hashes

from commandstrings import Command, SysCmdStrings
from comparativecircuitry import generatecircuitstructure
from garblerpartyclass import IOWrapperServer
from ot import selectionofferer

class Gate:
    
    def __init__(self, table):
        self.table = table  # table[0] table[1] table[2] table[3]
                            # where table[i] is [a b c] with a,b,c \in {0,1}
        self.follower = None
        

class InputWire:
    def __init__(self, party, id, value=None):
        self.party = party
        self.id = id
        self.possiblelables = None
        self.value = value # is assigned if the value is known

class InterWire:
    def __init__(self, gateref):
        self.value = None
        self.gateref = gateref
        self.possiblelables = None


class OperatorGate:
    
    def __init__(self):
        self.output_wire = None
        self.input_gates = None 
        self.table = None
        self.rows = []
        self.isgarbled = False
        self.ispermuted = False
        
        

class AndGate(OperatorGate):
    def __init__(self):
        self.output_wire = None
        self.input_gates = None 
        
        self.table = np.array([
                                [0,0,0],
                                [0,1,0],
                                [1,0,0],
                                [1,1,1]
                            ])
        self.rows = []
   
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        self.output_wire = InterWire(self)
        return self.output_wire
             
    
class OrGate(OperatorGate):
    def __init__(self):
        self.output_wire = None
        self.input_gates = None 
        self.table = np.array([
                                [0,0,0],
                                [0,1,1],
                                [1,0,1],
                                [1,1,1]
                            ])
        self.rows = []
        
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        self.output_wire = InterWire(self)
        return self.output_wire
             
    
class NotGate(OperatorGate):
    def __init__(self):
        self.output_wire = None
        self.input_gates = None 
        self.table = np.array([
                                [0,1],
                                [1,0]
                            ])
        self.rows = []
        
    def __call__(self, in0):
        self.input_gates = [in0] 
        self.output_wire = InterWire(self)
        return self.output_wire
    
    
class XORGate(OperatorGate):
    def __init__(self):
        self.output_wire = None
        self.input_gates = None  
        self.table = np.array([
                            [0,0,0],
                            [0,1,1],
                            [1,0,1],
                            [1,1,0]
                        ])
        self.rows = []
        
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        self.output_wire = InterWire(self)
        return self.output_wire

    

class Circuit:
    
    def __init__(self, inputwires):
        self.startingwires = inputwires
        


def permutegate(gate: Gate) -> List[Gate, Tuple]:
    
    permute the gate.rows entries
    pass


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
    
    # do not do anything to the input wires


def encryptgate(gate: Gate, wirelables):
    """
    gate: Gate to encrypt
    
    wirelables: Array, |wirelables| = 4 | 2
                For |wirelables| = 4
                    wirelables = Wg0 We0 Wg1 We1
                For |wirelables| = 2
                    wirelables = W0 W1
    """
    
    gate.rows = gate.table
    
    if len(wirelables) == 4:
        g0 = encrypt(gate.rows[0][2], (wirelables[0], wirelables[1]) )
        g1 = encrypt(gate.rows[1][2], (wirelables[0], wirelables[3]) )
        g2 = encrypt(gate.rows[2][2], (wirelables[2], wirelables[1]) )
        g3 = encrypt(gate.rows[3][2], (wirelables[2], wirelables[3]) )
        
        gate.rows[0][2] = g0
        gate.rows[1][2] = g1
        gate.rows[2][2] = g2
        gate.rows[3][2] = g3
        
        
    elif len(wirelables) == 2:
        # TODO
        pass
    else:
        raise ValueError("ERR 01")

def maskOutputGateWithLabel(gate, resultlables):
    """
    resultlables = [wV0, wV1]
    
    wVi is the label for the result wire having value i
    
    """    

    for r in range(len(gate.rows)):
        
        tableresultvalue = gate.rows[r][2]
        if tableresultvalue == 1:
            gate.rows[r][2] = resultlables[1]
        else:
            gate.rows[r][2] = resultlables[0]
        

def encryptsourcegate(gate):
    
    if len(gate.table) == 4:
        salt = os.urandom(32)
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("wg0ZEROBASE")
        digest.update(salt)
        Wg0 = digest.finalize()
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("we0ZEROANOTHER")
        digest.update(salt)
        We0 = digest.finalize()
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("wg1ZEROFIRST")
        digest.update(salt)
        Wg1 = digest.finalize()

        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("wg1ONEANOTHER")
        digest.update(salt)
        We1 = digest.finalize()
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("VALUEtargeoOneOne")
        digest.update(salt)
        wV1 = digest.finalize()
        
        maskOutputGateWithLabel(gate, [wV0, wV1])
        
        encryptgate(gate, [ Wg0 ,We0, Wg1, We1])
        
        return [wV0, wV1]
    
    
def garblewire(finalwire):
    """
    
    Garbles the gate and all precessor gates associated with the Interwire finalwire
    
    """
    
    
    if isinstance(finalwire, InputWire):
        if finalwire.possiblelables == None:
            
            salt = os.urandom(32)
            digest = hashes.Hash(hashes.BLAKE2b())
            digest.update(salt)
            digest.update("VALUEtargeoZEroZero")
            digest.update(salt)
            wV0 = digest.finalize()
            
            digest = hashes.Hash(hashes.BLAKE2b())
            digest.update(salt)
            digest.update("VALUEtargeoOneOne")
            digest.update(salt)
            wV1 = digest.finalize()
            
            finalwire.possiblelables = [wV0, wV1]
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
        
        # We have to garble the gate, which defines the wire
        # For this, we need the input wires
        
        
        inputwireA, inputwireB = gate.input_gates
        
        [wV0_A, wV1_A] = garblewire(inputwireA)  # if input wire, then A is Garbler
        [wV0_B, wV1_B] = garblewire(inputwireB)  # if input wire, then B is Evaluator
        
        
        salt = os.urandom(32)
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        digest = hashes.Hash(hashes.BLAKE2b())
        digest.update(salt)
        digest.update("VALUEtargeoOneOne")
        digest.update(salt)
        wV1 = digest.finalize()
        
        finalwire.possiblelables = [wV0, wV1]
        
        maskOutputGateWithLabel(gate, [wV0, wV1])
        
        encryptgate(gate, [wV0_A,wV0_B,wV1_A,wV1_B] )
        
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
    
    sms = SysCmdStrings()

    allInputWiresOfParty1 = [w for w in inputwires if w.party == party1]
    allInputWiresOfParty2 = [w for w in inputwires if w.party == party2]  # < belong to evaluator: 
    
    for i in range(allInputWiresOfParty2):    
        # all input wires are resolved now
        
        so = selectionofferer(io) # grabbing the requested wire id
        
        askedid = so.askedid
        
        assert askedid in allInputWiresOfParty2, "Violation in the protocol"
        
        inputwire = [w for w in allInputWiresOfParty2 if w.id == askedid][0]
        [l0, l1] = inputwire.possiblelables
        
        so.set_first_optionbit(l0) # actually do maybe with a full 256bit 
        so.set_second_optionbit(l1)
        
        so.do_protocol()
        
        
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
    
    command = sms.makecommand(cmd=c, otann=None, payloadcontext=None, payload=rows)
    
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
    
    p1a = InputWire(party1, 'first', 1) #  gate3
    p1b = InputWire(party1, 'second',1) #  gate1
    
    p2a = InputWire(party2, 'third') #  gate1
    p2b = InputWire(party2, 'forth') #  gate2, gate4
    
    b = AndGate()(p1b, p2a)
    c = OrGate()(b, p2b)
    d = XORGate()(c, p1a)
    e = AndGate()(c, p2b)
    f = OrGate()(d, e)
    
    
    garblewire(f)
    
    io = IOWrapperServer()
    
    summary = generatecircuitstructure(f, "")  # TODO: add commitment scheme
    io.send(summary)
    
    
    establish(io, f) # blocks, transmitts garbled, permuted rows only
    
    
    
    resolvingAllObliviousTransfers(io, [p1a,p1b,p2a,p2b], party1, party2)
    
    
    
    
    
    
    
    
    
    
    
    




main()

