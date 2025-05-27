


import copy
import os
import random
from gates import Gate, OperatorGate, XORGate
from utils import maketokeybytes, xoring_bytearray
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES

def encrypt(plaintext, labels, nonce):
    
    key_bytes = maketokeybytes(labels)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce)
    fnonce = digest.finalize()
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=fnonce, use_aesni='True')
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return ciphertext, tag
    

def encryptgate(gate: OperatorGate, wirelables):
    """
    gate: Gate to encrypt
    
    wirelables: Array, |wirelables| = 4 | 2
                For |wirelables| = 4
                    wirelables = Wg0 We0 Wg1 We1
                For |wirelables| = 2
                    wirelables = W0 W1
    """
    
    
    if len(gate.table) == 4:
        assert len(wirelables) == 4, "Inadequate number of wire labels given"
        
        #gate.noncematerial[0] = gate.noncematerial[0] ^ 9
        g0, t0 = encrypt(gate.rows[0][2], (wirelables[0], wirelables[1]),gate.noncematerial )
        #gate.noncematerial[1] = gate.noncematerial[1] ^ 11
        g1, t1 = encrypt(gate.rows[1][2], (wirelables[0], wirelables[3]),gate.noncematerial )
        #gate.noncematerial[2] = gate.noncematerial[2] ^ 111
        g2, t2 = encrypt(gate.rows[2][2], (wirelables[2], wirelables[1]),gate.noncematerial )
        #gate.noncematerial[3] = gate.noncematerial[3] ^ 50
        g3, t3 = encrypt(gate.rows[3][2], (wirelables[2], wirelables[3]),gate.noncematerial )
        
        gate.rows[0][2] = g0
        gate.rows[1][2] = g1
        gate.rows[2][2] = g2
        gate.rows[3][2] = g3
        
        gate.rows[0][3] = t0
        gate.rows[1][3] = t1
        gate.rows[2][3] = t2
        gate.rows[3][3] = t3
        
    elif len(gate.table) == 2:
        assert len(wirelables) == 2, "Inadequate number of wire labels given"

        g0, t0 = encrypt(gate.rows[0][1], (wirelables[0]),gate.noncematerial )

        g1, t1 = encrypt(gate.rows[1][1], (wirelables[1]),gate.noncematerial )
        
        gate.rows[0][1] = g0
        gate.rows[1][1] = g1
        
        gate.rows[0][2] = t0
        gate.rows[1][2] = t1
        
    else:
        raise ValueError("Tried to encrypt incompatible gate")




def permutegate(gate: Gate):
    """
    Removes the possibilty that the evaluator can deduce to which input pair a successfully decrypted row belongs to
    
    """
    random.shuffle(gate.rows)

def maskOutputGateWithLabel(gate, resultlables):
    """
    resultlables = [wV0, wV1]
    
    wVi is the label for the result wire having value i
    
    """    

    if gate.rows == []:
        
        gate.rows = copy.deepcopy(gate.table)
        
        for row in gate.rows:
            row.append(bytes(1)) # for later encryption tag
            tableresultvalue = row[-2] # the one before the last
            
            if tableresultvalue == 1:
                row[-2] = resultlables[1]
            else:
                row[-2] = resultlables[0]
        
            # kill the input labels
            row[-3] = 0
            row[0] = 0


def garblethegate(gate, DeltaKey):

    
    if isinstance(gate, XORGate):
        wV0_A = gate.input_gates[0].possiblelables[0]
        wV0_B = gate.input_gates[1].possiblelables[0]
        
        wV0 = xoring_bytearray(wV0_A, wV0_B)
        
        wV1 = xoring_bytearray(wV0, DeltaKey)
        
        gate.output_wire.possiblelables = [wV0, wV1]
    

    else:
    
        
        if len(gate.input_gates) == 2:
            
            wV0_A = gate.input_gates[0].possiblelables[0]
            wV1_A = gate.input_gates[0].possiblelables[1]
            wV0_B = gate.input_gates[1].possiblelables[0]
            wV1_B = gate.input_gates[1].possiblelables[1]
            
            allwirelables = [wV0_A,wV0_B,wV1_A,wV1_B]

        else:
            
            wV0_A = gate.input_gates[0].possiblelables[0]
            wV1_A = gate.input_gates[0].possiblelables[1]
            
            allwirelables = [wV0_A,wV1_A]
        

        # 1. We generate output wires
        salt = os.urandom(32)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(b"VALUEtargeoZEroZero")
        digest.update(salt)
        wV0 = digest.finalize()
        
        
        #digest = hashes.Hash(hashes.SHA256())
        #digest.update(salt)
        #digest.update(b"VALUEtargeoOneOne")
        #digest.update(salt)
        #wV1 = digest.finalize()
        wV1 = xoring_bytearray( wV0 , DeltaKey )
        
        # We can garble the gate
        
        gate.output_wire.possiblelables = [wV0, wV1]

        maskOutputGateWithLabel(gate, [wV0, wV1])
        

        encryptgate(gate, allwirelables)
        permutegate(gate)
        
    
    gate.isgarbled = True
