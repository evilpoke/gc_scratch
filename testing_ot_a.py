

from garblerpartyclass import IOWrapperServer
from ot import selectionofferer

io = IOWrapperServer()

io.startup()

so = selectionofferer(io, 1234) # grabbing the requested wire id

somethingwhatever = io.receive()

askedid = so.askedid

firstbit = False
secondbit = False
print("I set up the bits: First bit, Second bit: " + str(firstbit) + ", " + str(secondbit))

so.set_first_optionbit(firstbit) # actually do maybe with a full 256bit 
so.set_second_optionbit(secondbit)

so.do_protocol()





