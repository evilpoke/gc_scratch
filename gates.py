
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
        


class AccessRejectedGate(Exception):
    def __init__(self, *args):
        super().__init__(*args)