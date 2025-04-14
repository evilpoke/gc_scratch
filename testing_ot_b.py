 
from evaluatorpartyclass import IOWrapperClient
from garblerpartyclass import IOWrapperServer
from ot import selectionofferer, selectionselector

io = IOWrapperClient()

io.startup()

so = selectionselector(io, 1234) # grabbing the requested wire id
so.announce_selection()

sel = True

print("I select the bit " + str(sel))

so.set_sigma(sel)

so.do_protocol()


print("I have now obtained the bit: " + str(so.bsel))


