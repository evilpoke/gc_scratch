

import numpy as np

from gates import InputWire


def generatecircuitstructure(wire, stt):
    """
    

    Args:
        wire (_type_): _description_
        wireprime (_type_): _description_
    """
    
    if isinstance( wire , InputWire):
        stt += "input:"+str(wire.party)
        return stt
    else:

        gate = wire.gateref
        stt += str(gate.table)

        for g in gate.input_gates:
            stt = generatecircuitstructure(g, stt)
        
        return stt