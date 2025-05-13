

import numpy as np

from gates import AndGate, InputWire, NotGate, OrGate, XORGate, getallinputwires


def generatecircuitstructure(wire, stt):
    """
    

    Args:
        wire (_type_): _description_
        wireprime (_type_): _description_
    """
    
    
    stt = ""
    
    wires = getallinputwires(wire)
    
    newwires = []
    following_gates = []

    while True:
        
        propagated = False
        
        for w in wires:
            targetgates = w.coupled_target_gates
            
            if targetgates == []:
                continue
            
            propagated = True
            
            if isinstance( w , InputWire):
                stt += "input:"+str(w.id)+":"
            else:
                stt += "inter:"
                
            stt += "["
            
            for gate in targetgates:
                if isinstance(gate, AndGate):
                    stt += 'and'
                elif isinstance(gate, OrGate):
                    stt += 'or'
                elif isinstance(gate, NotGate):
                    stt += 'not'
                elif isinstance(gate, XORGate):
                    stt += 'xor'
                
                
                newwires.append(gate.output_wire)
                
            stt += "]"
        
        wires = newwires
        newwires = []
        
        if propagated == False:
            return stt
        
        
            
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    """
    if isinstance( wire , InputWire):
        stt += "input:"+str(wire.party)
        return stt
    else:

        gate = wire.gateref
        stt += str(gate.table)

        stt += '['
        for g in gate.input_gates:
            stt = generatecircuitstructure(g, stt)
            stt += "|"
        stt += ']'
        
        return stt
    """