
import numpy as np
from cryptography.hazmat.primitives import hashes

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
        self.noncematerial = None


class AndGate(OperatorGate):
    def __init__(self):
        super().__init__()
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
        self.input_gates = [in0, in1] 
        self.output_wire = InterWire(self)
        return self.output_wire
             
    
class OrGate(OperatorGate):
    def __init__(self):
        super().__init__()
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
        self.output_wire = InterWire(self)
        return self.output_wire
             
    
class NotGate(OperatorGate):
    def __init__(self):
        super().__init__()
        self.output_wire = None
        self.input_gates = None 
        self.table = [
                    [0,1],
                    [1,0]
                            ]
        self.rows = []
        
    def __call__(self, in0):
        self.input_gates = [in0] 
        self.output_wire = InterWire(self)
        return self.output_wire
    
    
class XORGate(OperatorGate):
    def __init__(self):
        super().__init__()
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
        self.output_wire = InterWire(self)
        return self.output_wire

def fill_nonce_material(finalwire, initnonce):
    """If finalwire and initnonce where called by both parties identically, 
    then the completecircuit will receive the same nonce 

    Args:
        finalwire (_type_): _description_
        initnonce bytes
    """
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(initnonce)
    newhash = digest.finalize()
    
    if isinstance(finalwire, InputWire):
        return
    else:
        gate = finalwire.gateref
        if not(gate.noncematerial is None):
            return
        else:
            
            gate.noncematerial = newhash
                    
            ins = gate.input_gates
            if len(ins) == 2:
                newhash += b'AA'
                fill_nonce_material(ins[0], newhash)    

                newhash += b'BC'
                fill_nonce_material(ins[1], newhash)
            elif len(ins) == 1:
                newhash += b'DD'
                fill_nonce_material(ins[1], newhash)
            else:
                raise ValueError("Invalid gate")

def countWires(finalwire, acc = []):
    
    if finalwire in acc:
        return 0
    
    if isinstance(finalwire, InputWire):
        acc.append(finalwire)
        return 1
    
    igs = finalwire.gateref.input_gates
    
    count = 0
    for i in igs:
        count += countWires(i)
    
    acc.append(finalwire)
    count += 1
    return count
    
    
class Circuit:
    
    def __init__(self, inputwires):
        self.startingwires = inputwires
        


class AccessRejectedGate(Exception):
    def __init__(self, *args):
        super().__init__(*args)