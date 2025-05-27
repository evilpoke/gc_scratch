
from Crypto.Cipher import AES
from gates import AccessRejectedGate
from utils import maketokeybytes
from cryptography.hazmat.primitives import hashes

def decrypt(row, t , nonce, tag):

    key_bytes = maketokeybytes(t)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce)
    fnonce = digest.finalize()
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=fnonce, use_aesni='True')
    plaintext_as_bytes = cipher.decrypt(row)
    try:
        cipher.verify(tag)
    except ValueError:
        return False
    
    return plaintext_as_bytes


def decryptrow(gate, labels, i):
    """
    gate: Gate to encrypt
    
    labels: Array of lables required to access the gate

    i:  row to decrypt
    
    returns: Decrypted bit/label or Exception
    """
    
    nonce = gate.noncematerial
    
    if len(labels) == 2:
        assert len(gate.rows) == 4, "Wrong number of gate / labels"
        
        # We have a 2 bit gate on our hand
        
        g0 = decrypt(gate.rows[i][2], (labels[0], labels[1]) , nonce, gate.rows[i][3])
        if g0 == False:
            raise AccessRejectedGate("R: "+str(i))
        else:
            return g0
        
    elif len(labels) == 1:
        assert len(gate.rows) == 2, "Wrong number of gate / labels"
        
        g0 = decrypt(gate.rows[i][1], (labels[0]) , nonce, gate.rows[i][2])
        if g0 == False:
            raise AccessRejectedGate("R: "+str(i))
        else:
            return g0
        
    else:
        raise ValueError("Invalid gate")
