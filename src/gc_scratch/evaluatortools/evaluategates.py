

from decryptiongate import decryptrow
from gates import AccessRejectedGate, XORGate
from utils import xoring_bytearray

def evaluategate(gate, insvalues):
    
    if not isinstance(gate, XORGate):
    
        # primitive brute-force gate evaluator
        for rowi in range(len(gate.rows)):
            try:
                returnlabel = decryptrow(gate,insvalues,rowi)
                return returnlabel
            except AccessRejectedGate as ae:
                continue
            except Exception as e:
                print(str(e))
                raise e
    
    else:
        
        returnlabel = xoring_bytearray(insvalues[0], insvalues[1])
        return returnlabel
    