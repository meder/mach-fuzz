Mach Fuzzing Tools
==================

To fuzz Mach services you'll need to things:
*  Mach message samples for the target service
*  Fuzzer to mutate and replay the above samples

both of the above can be found here.

mach_dump.py
============

GDB breakpoint implementation that need two thing to parse and save message samples:
*  address to set breakpoint at, which should have incoming Mach message in one of the registers
*  name of the register that will contain the Mach message

Sample invocation:
```
  (gdb) source mach_dump.py
  (gdb) python mach_dump("*0x00007fff9063173c", "$rsi")
  (gdb) set pagination off
  (gdb) c
```
Messages are saved in `dump/` directory and OOL memory is saved in `ool/`, both of which must be passed to the fuzzer.


mach-fuzzer.cpp
===============
_Not the prettiest piece of code, I know!_

To compile
```
$ c++ -o mach-fuzzer mach-fuzzer.cpp
```

Argument are pretty self-explanatory: 
```
./mach-fuzzer <mach_service> <msgs_dir> <msgs_ool_dir> [seed msgh_id_low msgh_id_hi]
```

For example to fuzz `coreserviced`, assuming `mach_dump.py` was run in `/tmp/mach-fuzz`:
```
./mach-fuzzer com.apple.CoreServices.coreservicesd /tmp/mach-fuzz/dump/ /tmp/mach-fuzz/ool/
```

You can use `launchctl bslist -j` to obtain mach service name and corresponding jobs:
```
# launchctl bslist -j|grep -i coreservicesd
A  com.apple.CoreServices.coreservicesd (com.apple.coreservicesd)
#
```
