
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
                
    for w in range(int(len(inter) / window)):
        if len(inter) % 5 == 0:
            v = AndGate()(
            NotGate()(OrGate()(
                AndGate()(
                        NotGate()(inter[w*window+3]),
                        inter[w*window + 4],
                ),
                inter[w*window + 2]
            ))
            ,
            OrGate()(
                AndGate()(
                        NotGate()(inter[w*window]),
                        inter[w*window + 1],
                ),
                inter[w*window + 2]
            )
            )
            
            
        elif len(inter) % 3 == 0:
            
            v = XORGate()(
                    AndGate()(
                            NotGate()(inter[w*window]),
                            inter[w*window + 2],
                    ),
                    inter[w*window + 1]
            )            
            
        elif len(inter) % 2 == 0:
            v = OrGate()(inter[0], inter[1])
        else:
            v = NotGate()(inter[0])
        
        for w in range(window):
            resultarr.append(v)
    
    trueresultarr = []
    
    for r in range(len(resultarr)):
        trueresultarr.append(  
                                XORGate()(
                                    startxorarr[r*5 % len(resultarr)],
                                    XORGate()( resultarr[r] , resultarr[(r*21 + 21) %  len(resultarr)] ) 
                                    )
                            )
    return trueresultarr
    