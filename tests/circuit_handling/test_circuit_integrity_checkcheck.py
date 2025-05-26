



import unittest

from comparativecircuitry import generatecircuitstructure
from gates import InputWire, NotGate, XORGate


class TestMPCLinearisation(unittest.TestCase):

    def test_circuit_integrity_01(self):
        
        party1 = "garbler"
        party2 = "evaluator"
        
        
        i1 = InputWire(party1, 'plGAR01', True)
        i2 = InputWire(party2, 'plGAR02', True)
        
        a = XORGate()(i1, i2)
        v = NotGate()(a)
        
        i1p = InputWire(party1, 'plGAR01', False)
        i2p = InputWire(party2, 'plGAR02', True)
        
        ap = XORGate()(i1p, i2p)
        vp = NotGate()(ap)
        
        firstvalue = generatecircuitstructure(vp, "")
        secondvalue = generatecircuitstructure(v, "")
        
        assert firstvalue == secondvalue, "Circuit generation not deterministic"
    
    def test_circuit_integrity_02(self):
        
        party1 = "garbler"
        party2 = "evaluator"
        
        
        i1 = InputWire(party1, 'plGARr1', True)
        i2 = InputWire(party2, 'plGAR02', True)
        
        a = XORGate()(i1, i2)
        v = NotGate()(a)
        
        i1p = InputWire(party1, 'plGAR01', False)
        i2p = InputWire(party2, 'plGAR02', True)
        
        ap = XORGate()(i1p, i2p)
        vp = NotGate()(ap)
        
        firstvalue = generatecircuitstructure(vp, "")
        secondvalue = generatecircuitstructure(v, "")
        
        assert firstvalue != secondvalue, "Circuit generation not deterministic"
    
        