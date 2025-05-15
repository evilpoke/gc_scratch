from cryptography.hazmat.primitives import hashes

def maketokeybytes(t):
    # tuple t of size 2 or 1
    
    digest = hashes.Hash(hashes.SHA256())
    
    
    if len(t) == 2:
        # 2 key labels
        digest.update(t[0])
        digest.update(t[1])
        v = digest.finalize()
    else:
        digest.update(t)
        v = digest.finalize()
    
    return v



def deterministic_joining(list1, list2):
    
    for ll in list2:
        if not(ll in list1):
            list1.append(ll)

