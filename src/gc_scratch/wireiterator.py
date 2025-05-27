

from utils import deterministic_joining


def iter_wires(inputwires, check_if_wire_done):
    
    """
    
    inputwires: List of input wires
    
    
        We guarantee for every yielded wireset that they have been resolved
        We expect for every yielded wireset that all gates that could be evaluated, ARE evaluated
        
    """
    
    # inputwires are now already in possession of the labels
    
    
    
    assert not False in [check_if_wire_done(n) for n in inputwires], "Wires has not been garbled"
    
    
    gates = []
    for i in inputwires:
            
            # for wire i get all potential gates 
            potential_gates = i.coupled_target_gates
            
            if potential_gates == []:
                continue
            
            # filter for gates which can be evaluated
            evaluatable_gates = [t for t in potential_gates 
                                    if 
                                        not (False in
                                                [check_if_wire_done(wire_of_candidate) for wire_of_candidate in t.input_gates] 
                                            )
                                ]
            deterministic_joining(gates, evaluatable_gates)
    
    # gates now only are gates which can be garbled
    
    # getting all output wires of these gate which will then receive their 'possiblelable'
    newwires = [g.output_wire for g in gates]
    
    # outputting inputwires from which all evaluatable gates are garbled (so newwires should have the possiblelables) 
    yield inputwires
    
    # checking if all all wires from these gates are done
    assert not False in [check_if_wire_done(n) for n in newwires], "Wires has not been garbled"

    
    inputwires = newwires
    
    while True:
        # -------- Getting all gates which will be garbled -----------
        for i in inputwires:
            
            # for wire i get all potential gates 
            potential_gates = i.coupled_target_gates
            
            if potential_gates == []:
                continue
            
            # filter for gates which can be evaluated
            evaluatable_gates = [t for t in potential_gates 
                                    if 
                                        not (False in
                                                [check_if_wire_done(wire_of_candidate) for wire_of_candidate in t.input_gates] 
                                            )
                                ]
            deterministic_joining(gates, evaluatable_gates)

        # gates now only are gates which can be garbled
        
        if gates == []:
            return
        
        # getting all output wires of these gate which will then receive their 'possiblelable'
        newwires = [g.output_wire for g in gates]
        
        # we will yield the current wires
        yield inputwires
        
        assert not False in [check_if_wire_done(n) for n in newwires], "Wires has not been garbled"
        
        
        inputwires = newwires
        newwires = []
        gates = []
    
    