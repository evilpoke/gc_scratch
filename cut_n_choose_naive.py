
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
    

def openv(circ_to_be_opened):

    if isinstance(circ_to_be_opened, InterWire):
        #if not (circ_to_be_opened.possiblelables is None):
        inputwires = circ_to_be_opened.gateref.input_gates
        for i in inputwires:
            openv(i) 
        
        if circ_to_be_opened.gateref.checkedattribute == False: 
            
            if len(circ_to_be_opened.gateref.input_gates) == 2:
                
                supposed_true_label_of_first = inputwires[0].possiblelables[1]
                supposed_false_label_of_first = inputwires[0].possiblelables[0]

                supposed_true_label_of_second = inputwires[1].possiblelables[1]
                supposed_false_label_of_second = inputwires[1].possiblelables[0]
                
                supposed_true_label_result = None
                supposed_false_label_result = None
                
                success = False
                resultlabel = None
                for i in range(4):
                    # trying out |0 0|
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_false_label_of_first, supposed_false_label_of_second],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[0][2] == 1:
                    supposed_true_label_result = resultlabel
                else:
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
                
                success = False
                for i in range(4):
                    # trying out |0 1|
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_false_label_of_first, supposed_true_label_of_second],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[1][2] == 1:
                    if not(supposed_true_label_result is None) and supposed_true_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_true_label_result = resultlabel
                else:
                    if not(supposed_false_label_result is None) and supposed_false_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
                
                success = False
                for i in range(4):
                    # trying out |1 0|
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_true_label_of_first, supposed_false_label_of_second],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[2][2] == 1:
                    if not(supposed_true_label_result is None) and supposed_true_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_true_label_result = resultlabel
                else:
                    if not(supposed_false_label_result is None) and supposed_false_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
                
                success = False
                for i in range(4):
                    # trying out |1 1|
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_true_label_of_first, supposed_true_label_of_second],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[3][2] == 1:
                    if not(supposed_true_label_result is None) and supposed_true_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_true_label_result = resultlabel
                else:
                    if not(supposed_false_label_result is None) and supposed_false_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
            else:
                assert len(circ_to_be_opened.gateref.input_gates) == 1, "Unknown gate used"
                ####################################################################################################################
                
                supposed_true_label_of_first = inputwires[0].possiblelables[1]
                supposed_false_label_of_first = inputwires[0].possiblelables[0]

                supposed_true_label_result = None
                supposed_false_label_result = None
                
                success = False
                resultlabel = None
                for i in range(2):
                    # trying out |0 |
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_false_label_of_first],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[0][1] == 1:
                    supposed_true_label_result = resultlabel
                else:
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
                
                success = False
                for i in range(2):
                    # trying out |1 |
                    try:
                        resultlabel = decryptrow(circ_to_be_opened.gateref, 
                                [supposed_true_label_of_first],
                                i)
                        if success == True:
                            raise ViolationDetected()
                        success = True
                    except AccessRejectedGate as arg:
                        pass
                    except Exception as e:
                        raise ViolationDetected()
                if circ_to_be_opened.gateref.table[1][1] == 1:
                    if not(supposed_true_label_result is None) and supposed_true_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_true_label_result = resultlabel
                else:
                    if not(supposed_false_label_result is None) and supposed_false_label_result != resultlabel:
                        raise ViolationDetected()
                    supposed_false_label_result = resultlabel
                if success == False:
                    raise ViolationDetected()
                
                
                ####################################################################################################################
                
            
            if circ_to_be_opened.possiblelables is None:
                circ_to_be_opened.possiblelables = [supposed_false_label_result, supposed_true_label_result]
                circ_to_be_opened.checkedattribute = False
            else:
                if supposed_false_label_result == circ_to_be_opened.possiblelables[0] and supposed_true_label_result == circ_to_be_opened.possiblelables[1]:
                    circ_to_be_opened.checkedattribute = False
                else:
                    raise ViolationDetected()
        else:
            return
    else:
        if (not (circ_to_be_opened.possiblelables is None)) or (not (circ_to_be_opened.possiblelables == [])):
            pass
        else:
            raise ViolationDetected()
    


def verify_functional_equality(circ_to_be_opened):
    
    if not (circ_to_be_opened.possiblelables is None) and not (circ_to_be_opened.possiblelables == []):
        pass
    else:
        raise ViolationDetected()
    
    openv_nonrec(circ_to_be_opened)
    
    #print("Verified")