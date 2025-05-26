
from gates import AndGate, NotGate, OrGate, XORGate



def addingblock(startxorarr):
    
    if len(startxorarr) % 5 == 0:
        window = 5
    elif len(startxorarr) % 3 == 0:
        window = 3
    elif len(startxorarr) % 2 == 0:
        window = 3
    else:
        window = 1
    
    inter = startxorarr
    resultarr = []
                
    for w in range(len(inter) - window -1):

        v = AndGate()(
        NotGate()(OrGate()(
            AndGate()(
                    NotGate()(inter[w+3]),
                    inter[w + 4],
            ),
            inter[w + 2]
        ))
        ,
        OrGate()(
            AndGate()(
                    NotGate()(inter[w]),
                    inter[w + 1],
            ),
            inter[w + 2]
        )
        )
        
        resultarr.append(v)
    
    
    trueresultarr = []
    
    for r in range(len(resultarr)):
        trueresultarr.append(  
                                XORGate()(
                                    startxorarr[r*5 % len(startxorarr)],
                                    XORGate()( resultarr[r] , resultarr[(r*21 + 21) %  len(resultarr)] ) 
                                    )
                            )
    while len(trueresultarr) < len(startxorarr):
        trueresultarr.append(  trueresultarr[len(trueresultarr) * 23451 % len(trueresultarr)] )
    
    return trueresultarr
    