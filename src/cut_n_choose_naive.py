
from decryptiongate import decryptrow
from gates import AccessRejectedGate, InterWire, getallinputwires


class ViolationDetected(Exception):
    def __init__(self, *args):
        super().__init__(*args)

#def compar_check(circ_opened):
    
def openv_nonrec(circ_to_be_opened):
    
    wires = getallinputwires(circ_to_be_opened) 
    
    newwires = []
    following_gates = []
    while True:
        for w in wires:
            targetgates = w.coupled_target_gates
            for t in targetgates:
                
                gate = t
                if gate.checkedattribute == True:
                    continue
                
                ins = gate.input_gates
                insvalues = [i.possiblelables for i in ins]
                if [] in insvalues:
                    newwires.append(w)
                    break
                
                # this gate we can validate because its input wires have possiblelables filled out
                
                #print("Solving gate "+str(gate)+"...")
            
                returnlabel = None

                def counts_of_successfull_decrypt(gate, labels):
                    decrypts = 0
                    resultlabel = None
                    for i in range(len(gate.rows)):
                    # trying out input combinations
                        try:
                            resultlabel = decryptrow(gate, 
                                    labels,
                                    i)
                            decrypts = decrypts + 1
                        except AccessRejectedGate as arg:
                            pass
                    
                    return decrypts, resultlabel
                
                supposed_label_result = {1: None, 0: None}
                
                if len(gate.input_gates) == 2:
                    
                    supposed_true_label_of_first = gate.input_gates[0].possiblelables[1]
                    supposed_false_label_of_first = gate.input_gates[0].possiblelables[0]

                    supposed_true_label_of_second = gate.input_gates[1].possiblelables[1]
                    supposed_false_label_of_second = gate.input_gates[1].possiblelables[0]
                    
                    # 0 0
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_false_label_of_first, supposed_false_label_of_second])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[0][2]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()

                    # 0 1
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_false_label_of_first, supposed_true_label_of_second])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[1][2]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()

                    # 1 0
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_true_label_of_first, supposed_false_label_of_second])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[2][2]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()
                    
                    # 1 1
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_true_label_of_first, supposed_true_label_of_second])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[3][2]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()
                else: 
                    # len(gate.input_gates) == 1:
                    supposed_true_label_of_first = gate.input_gates[0].possiblelables[1]
                    supposed_false_label_of_first = gate.input_gates[0].possiblelables[0]
                    
                    # 0 
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_false_label_of_first])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[0][1]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()
                        
                    # 1
                    decrypts, resultlabel = counts_of_successfull_decrypt(gate, [supposed_true_label_of_first])
                    
                    if decrypts != 1:
                        raise ViolationDetected()
                    
                    expected_semantic_value = gate.table[1][1]
                    if supposed_label_result[expected_semantic_value] is None:
                        supposed_label_result[expected_semantic_value] = resultlabel
                    else:
                        if not supposed_label_result[expected_semantic_value] == resultlabel:
                            raise ViolationDetected()
                
                
                assert not (resultlabel is None), "Failed to solve wire after gate " + str(gate)

                if gate.output_wire.possiblelables == []:
                    gate.output_wire.possiblelables = [supposed_label_result[0],supposed_label_result[1]]
                else:
                    if gate.output_wire.possiblelables[0] != supposed_label_result[0]:
                        raise ViolationDetected()
                    if gate.output_wire.possiblelables[1] != supposed_label_result[1]:
                        raise ViolationDetected()
                    
                gate.checkedattribute = True
                
                #pbar.update()
            
                newwires.append(gate.output_wire)
        
        wires = newwires
        newwires = []
        
        if [w.coupled_target_gates for w in wires].count([]) == len(wires):
            # all wires have no coupled gates
            break
    


def verify_functional_equality(circ_to_be_opened):
    
    if not (circ_to_be_opened.possiblelables is None) and not (circ_to_be_opened.possiblelables == []):
        pass
    else:
        raise ViolationDetected()
    
    openv_nonrec(circ_to_be_opened)
    
    #print("Verified")