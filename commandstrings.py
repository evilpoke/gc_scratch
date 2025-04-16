
import json
import socket
import ssl
import pprint

from enum import Enum

class Command(Enum):
    checkcircuit = "checkcheck"
    ready_to_receive_circuit_rows = "rtscwr"
    sending_circuit_rows = "sencirrows"
    performing_ot_ask = "com_ot_a"
    performing_ot_give = "com_ot_q"

class OT_ANNOUNCE(Enum):
    ot_wire_id = "a:id"
    ot_seq = "seq:seq"
    simple_ask = "askaskask"
    

class SysCmdStrings:
    
    def __init__(self):
        
        # general commands possible for "cmd"
        
        self.commandstructure = {
            "cmd": None, # Command,
            "otann": None, #OT_ANNOUNCE,
            "payloadcontext": None, # the relevant context
            "payload": None
        }
        

    def makecommand(self, cmd, otann, payloadcontext,payload):
        
        
        self.commandstructure = {
            "cmd": cmd, # Command,
            "otann": None, #OT_ANNOUNCE,
            "payloadcontext": None, # the relevant context
            "payload": None
        }
        
        if cmd == Command.performing_ot_ask:
            if otann == OT_ANNOUNCE.ot_wire_id:
                assert payloadcontext == payload, "Invalid command"
                assert isinstance(payloadcontext, str) 
                self.commandstructure["otann"] = OT_ANNOUNCE.ot_wire_id.value
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = None
            elif otann == OT_ANNOUNCE.ot_seq:
                assert payloadcontext != payload, "Invalid command"
                self.commandstructure["otann"] = OT_ANNOUNCE.ot_seq.value
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = payload
            elif otann == OT_ANNOUNCE.simple_ask:
                assert payloadcontext == payload, "Invalid command"
                assert isinstance(payloadcontext, str) , "Payload context needs to be a str id"
                self.commandstructure["otann"] = OT_ANNOUNCE.simple_ask.value
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = None
            else:
                raise ValueError("Invalid command")
        elif cmd == Command.performing_ot_give:
            if otann == OT_ANNOUNCE.ot_seq:
                self.commandstructure["otann"] = OT_ANNOUNCE.ot_seq.value
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = payload
            elif otann == OT_ANNOUNCE.simple_ask:
                assert isinstance(payloadcontext, str) , "Payload context needs to be an id"
                self.commandstructure["otann"] = OT_ANNOUNCE.simple_ask.value
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = payload
            else:
                raise ValueError("Invalid command")
        elif cmd == Command.ready_to_receive_circuit_rows:
            assert otann == None and payloadcontext == None and payload == None, "Invalid command"
        elif cmd == Command.sending_circuit_rows:
            assert otann == None and payloadcontext == None and not ( payload is None), "Invalid command"
            self.commandstructure["payload"] = payload
        elif cmd == Command.checkcircuit:
            assert not ( payload == None), "Invalid command"
        else:
            raise ValueError("Invalid command")

        self.commandstructure["cmd"] = cmd.value
        self.commandstructure["payloadcontext"] = payloadcontext
        self.commandstructure["payload"] = payload
        
        #if isinstance(self.commandstructure["payload"], bytes):
        #    self.commandstructure["payload"] = list(self.commandstructure["payload"])
        
        self.commandstructure = json.dumps(self.commandstructure)
        
        encoding = self.commandstructure.encode(encoding="utf-8")
        
        return encoding
    
    def convert_byte_to_string(self, bytearr):
        
        return bytearr.decode('utf-8')
    
    def convert_string_to_full_dict(self, strings):
        
        temp = json.loads(strings)
        ####### cmd
        if temp["cmd"] == Command.performing_ot_ask.value:
            temp["cmd"] = Command.performing_ot_ask
        
        if temp["cmd"] == Command.checkcircuit.value:
            temp["cmd"] = Command.checkcircuit
    
        if temp["cmd"] == Command.performing_ot_give.value:
            temp["cmd"] = Command.performing_ot_give
            
        if temp["cmd"] == Command.ready_to_receive_circuit_rows.value:
            temp["cmd"] = Command.ready_to_receive_circuit_rows
            
        if temp["cmd"] == Command.sending_circuit_rows.value:    
            temp["cmd"] = Command.sending_circuit_rows

        if temp["otann"] == OT_ANNOUNCE.ot_seq.value:
            temp["otann"] = OT_ANNOUNCE.ot_seq
        
        if temp["otann"] == OT_ANNOUNCE.simple_ask.value:
            temp["otann"] = OT_ANNOUNCE.simple_ask

        if temp["otann"] == OT_ANNOUNCE.ot_wire_id.value:
            temp["otann"] = OT_ANNOUNCE.ot_wire_id

        return temp

    
    def load_byte_to_object(self, ll):
        
        ss = self.convert_byte_to_string(ll)
        
        st = self.convert_string_to_full_dict(ss)
        
        return st
    
    def loaddump(self, load):
        """
        Converts to object for comparison
        
        
        """
        pass    
        
    