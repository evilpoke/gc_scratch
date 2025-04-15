

from garblerpartyclass import IOWrapperServer
from ot import selectionofferer
from ot_bitwise import selectionofferer_bitwise
from time import (
    process_time,
    perf_counter,
    sleep,
)

io = IOWrapperServer()

io.startup()

so = selectionofferer_bitwise(io, 1234) # grabbing the requested wire id

somethingwhatever = io.receive() # announcing selection from b
a = perf_counter()
askedid = so.askedid

firstbit = bytearray(b'\x3f\x5d\x22')
secondbit = bytearray(b'\x12\x34\x56')

print("I set up the bits: First bit, Second bit: " + str(firstbit) + ", " + str(secondbit))

so.set_first_optionbit(bytes(firstbit)) # actually do maybe with a full 256bit 
so.set_second_optionbit(bytes(secondbit))

so.do_protocol()

print("Time:\n   ----------")
b = perf_counter()
totaltimespend = b -a
print("Total:\t"+str(totaltimespend))
print("Send:\t"+ str(io.totaltimesend))
print("Receive:\t"+ str(io.totaltimereceive))





