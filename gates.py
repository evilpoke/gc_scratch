
import numpy as np
from cryptography.hazmat.primitives import hashes

from utils import deterministic_joining


class Gate:
    
    def __init__(self, table):
        self.table = table  # table[0] table[1] table[2] table[3]
                            # where table[i] is [a b c] with a,b,c \in {0,1}
        self.follower = None
        

class InputWire:
    def __init__(self, party, id, value=None):
        self.party = party
        self.id = id
        self.possiblelables = []
        self.value = value # is assigned if the value is known
        self.coupled_target_gates = []

class InterWire:
    def __init__(self, gateref):
        self.value = None
        self.gateref = gateref
        self.possiblelables = []
        self.coupled_target_gates = []


class OperatorGate:
    
    def __init__(self):
        self.output_wire = None
        self.input_gates = None 
        self.table = None
        self.rows = []
        self.isgarbled = False
        self.ispermuted = False
        self.noncematerial = None
        self.checkedattribute = False


class AndGate(OperatorGate):
    def __init__(self, debug=None):
        super().__init__()
        self.debug = debug
        self.output_wire = None
        self.input_gates = None 
        
        self.table = [
                        [0,0,0],
                        [0,1,0],
                        [1,0,0],
                        [1,1,1]
                    ]
        self.rows = []
   
    def __call__(self, in0, in1):
        #super().(in0, in1)
        self.input_gates = [in0, in1] 
        in0.coupled_target_gates.append(self)
        in1.coupled_target_gates.append(self)
        
        self.output_wire = InterWire(self)
        self.output_wire.debug = self.debug
        return self.output_wire

class DFGate(OperatorGate):
    
    def __init__(self, debug=None):
        super().__init__()
        self.debug = debug
        self.output_wire = None
        self.input_gates = None 
        self.table = [
                        [0,0,1],
                        [0,1,0],
                        [1,0,0],
                        [1,1,1]
                        ]
        self.rows = []
        
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        in0.coupled_target_gates.append(self)
        in1.coupled_target_gates.append(self)
        self.output_wire = InterWire(self)
        self.output_wire.debug = self.debug
        return self.output_wire


class OrGate(OperatorGate):
    
    def __init__(self, debug=None):
        super().__init__()
        self.debug = debug
        self.output_wire = None
        self.input_gates = None 
        self.table = [
                        [0,0,0],
                        [0,1,1],
                        [1,0,1],
                        [1,1,1]
                        ]
        self.rows = []
        
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        in0.coupled_target_gates.append(self)
        in1.coupled_target_gates.append(self)
        self.output_wire = InterWire(self)
        self.output_wire.debug = self.debug
        return self.output_wire
             
        
class NotGate(OperatorGate):
    
    def __init__(self, debug=None):
        super().__init__()
        self.debug = debug
        self.output_wire = None
        self.input_gates = None 
        self.table = [
                    [0,1],
                    [1,0]
                            ]
        self.rows = []
        
    def __call__(self, in0):
        self.input_gates = [in0] 
        in0.coupled_target_gates.append(self)
        self.output_wire = InterWire(self)
        self.output_wire.debug = self.debug
        return self.output_wire
    
    
class XORGate(OperatorGate):
    
    def __init__(self, debug=None):
        super().__init__()
        self.debug = debug
        self.output_wire = None
        self.input_gates = None  
        self.table = [
                        [0,0,0],
                        [0,1,1],
                        [1,0,1],
                        [1,1,0]
                        ]
        self.rows = []
        
        
    def __call__(self, in0, in1):
        self.input_gates = [in0, in1] 
        in0.coupled_target_gates.append(self)
        in1.coupled_target_gates.append(self)
        self.output_wire = InterWire(self)
        self.output_wire.debug = self.debug
        return self.output_wire



#def pop_gates(finalwire):
    
def checkGateIsQualified(gate):
    inputs = gate.input_gates
    for i in inputs:
        if i.value is None:
            return False
    return True


def enumerateAllGates_nonrec(ins):
    
    added = []
    front = []  # wires
    newfront = ins   # wires
    
    
    while True:
        havepropagated = False
        front = newfront
        newfront = []
        
        for wire in front:

            targetgates = wire.coupled_target_gates
            deterministic_joining(added, targetgates)
            
            newwires = [t.output_wire for t in targetgates]
            deterministic_joining(newfront, newwires)

        if newfront == []:
            return added
        
    
def enumerateAllGates(finalwire):
    
    ins = getallinputwires(finalwire)

    allgates = enumerateAllGates_nonrec(ins)
    
    return allgates


def fill_nonce_material(finalwire, initnonce): # ez to un-rec
    """If finalwire and initnonce where called by both parties identically, 
    then the completecircuit will receive the same nonce 

    Args:
        finalwire (_type_): _description_
        initnonce bytes
    """
    
    ins = getallinputwires(finalwire)
    
    allgates = enumerateAllGates_nonrec(ins)
    
    for gate in allgates:
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(initnonce + b'ASDFfdsa')
        initnonce = digest.finalize()
        
        gate.noncematerial = initnonce
        

def gate_can_be_evaluated(gate):

    inputwires = gate.input_gates
    for ig in inputwires:
        if ig.possiblelables == [] or (ig.possiblelables is None):
            return False
    
    return True

def countGates(finalwire):
    
    allgates = enumerateAllGates(finalwire)
    
    return len(allgates)

def countWires(finalwire, acc = []): # ez to un-rec
    
    if finalwire in acc:
        return 0
    
    if isinstance(finalwire, InputWire):
        acc.append(finalwire)
        return 1
    
    igs = finalwire.gateref.input_gates
    
    count = 0
    for i in igs:
        count += countWires(i, acc)
    
    acc.append(finalwire)
    count += 1
    return count

    
def getallinputwires(finalwire, acc = []):  ## ez to un-rec
    
    previouses = [finalwire]
    newpreviouses = []
    collectedinputwires = []
    performed_move = False
    while True:
        performed_move = False
        for p in previouses:
            
            if isinstance(p, InputWire):
                if not(p in collectedinputwires):
                    collectedinputwires.append(p)
            else:
                # p is wire
                performed_move = True
                
                inputgates = p.gateref.input_gates
                
                deterministic_joining(newpreviouses, inputgates)
                #newpreviouses = newpreviouses + inputgates
                
                
                #for gates in inputgates:
                #    # gates is a wire
                #    
                #    if not(gates in newpreviouses):
        
        #deterministic_joining(newp)
        #newpreviouses = list(set(newpreviouses))
                 
                        
        if performed_move == False:
            return collectedinputwires #list(set(collectedinputwires))
        
        previouses = newpreviouses
        newpreviouses = []
        
        
class Circuit:
    
    def __init__(self, inputwires):
        self.startingwires = inputwires
        


class AccessRejectedGate(Exception):
    def __init__(self, *args):
        super().__init__(*args)