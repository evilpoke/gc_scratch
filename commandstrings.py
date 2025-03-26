
import socket
import ssl
import pprint

from enum import Enum

class Command(Enum):
    ready_to_receive_circuit_rows = "rtscwr"
    sending_circuit_rows = "sencirrows"
    performing_ot_ask = "com_ot_a"
    performing_ot_give = "com_ot_q"

class OT_ANNOUNCE(Enum):
    ot_wire_id = "a:id"
    ot_seq = "seq:seq"
    

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
                assert isinstance(payloadcontext, int) 
                self.commandstructure["otann"] = OT_ANNOUNCE.ot_wire_id
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = None
            elif otann == OT_ANNOUNCE.ot_seq:
                assert payloadcontext != payload, "Invalid command"
                self.commandstructure["otann"] = OT_ANNOUNCE.ot_seq
                self.commandstructure["payloadcontext"] = payloadcontext
                self.commandstructure["payload"] = payload
            else:
                raise ValueError("Invalid command")
        elif cmd == Command.performing_ot_give:
            assert otann == OT_ANNOUNCE.ot_seq, "Invalid command"
            self.commandstructure["otann"] = OT_ANNOUNCE.ot_seq
            self.commandstructure["payloadcontext"] = payloadcontext
            self.commandstructure["payload"] = payload
        elif cmd == Command.ready_to_receive_circuit_rows:
            assert otann == None and payloadcontext == None and payload == None, "Invalid command"
        elif cmd == Command.sending_circuit_rows:
            assert otann == None and payloadcontext == None and not ( payload == None), "Invalid command"
            self.commandstructure["payload"] = payload
        else:
            raise ValueError("Invalid command")

        self.commandstructure["cmd"] = cmd
        
        return self.commandstructure
        