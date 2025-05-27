 
from evaluatorpartyclass import IOWrapperClient
from garblerpartyclass import IOWrapperServer
from ot_bitwise import selectionselector_bitwise
from time import (
    process_time,
    perf_counter,
    sleep,
)

io = IOWrapperClient()

io.startup()

a = perf_counter()

so = selectionselector_bitwise(io, 1234) # grabbing the requested wire id
so.announce_selection()

sel = True

print("I select the bit " + str(sel))

so.set_sigma(sel)

so.do_protocol()
b = perf_counter()

print("I have now obtained the bytes: " + str(so.bsel))

try:
    io.send(b'EOF')
except Exception as e:
    print("exited connection")

print("Time:\n   ----------")
totaltimespend = b -a
print("Total:\t"+str(totaltimespend))
print("Send:\t"+ str(io.totaltimesend))
print("Receive:\t"+ str(io.totaltimereceive))


