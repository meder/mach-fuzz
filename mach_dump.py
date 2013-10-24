"""
This script sets breakpoint and saves Mach messages onto disk.

In the example below breakpoint will be set at 0x00007fff9063173c and each time
the breakpoint will be hit message in $rsi will be parsed and saved onto disk.
Messages are saved under dump/ directory and OOL descriptors into ool/:

  (gdb) source mach_dump.py
  (gdb) python mach_dump("*0x00007fff9063173c", "$rsi")
  (gdb) set pagination off
  (gdb) c

Remember that the default version of gdb bundled with OS X doesn't have Python
support, so you have to compile your own version (and self sign it) in order to
be able to use this script.

If you are getting invalid address errors then you are breakpointing at the
wrong place since message is invalid. You want to breakpoint right after the
target app received the Mach message.
"""
import gdb
from struct import unpack_from, calcsize
from ctypes import *

class mach_dump(gdb.Breakpoint):

    def __init__(self, spec, reg):
      super(mach_dump, self).__init__(
          spec, gdb.BP_BREAKPOINT, internal=False)
      self._reg = reg

    def stop(self):
      mach_msg_ptr = gdb.parse_and_eval(self._reg).cast(
          gdb.lookup_type('void').pointer())
      msg_len = int(gdb.parse_and_eval("*({}+4)".format(self._reg)))
      inferior = gdb.selected_inferior()
      mem = inferior.read_memory(mach_msg_ptr, msg_len)
      parse_data(mem, msg_len, inferior)
      return False

def dump_ptr(addr, size, filename, inferior):
  filename = "ool/%s_0x%016lx" % (filename, addr)
  mem = inferior.read_memory(addr, size)
  with open(filename, 'w+') as f:
    f.write(mem)
  print "Dumped %d bytes from  0x%x to %s\n" % (size, addr, filename)

def parse_data(data, len, inferior):
  parse_data.counter += 1
  mach_msg_fmt = "@IIIIII"
  bits, size, rport, lport, reserved, msg_id = unpack_from(mach_msg_fmt, data)
  print"msg_id: 0x%x\n" % (msg_id)
  print "bits: %s  size: %d msg_id: %s" % (hex(bits), size, hex(msg_id))
  filename = "msg_{}_{}".format(hex(msg_id), parse_data.counter)
  with open("dump/" + filename, 'w+') as f:
    f.write(data)

  offset = calcsize(mach_msg_fmt)
  if bits & 0x80000000:
    body_fmt = "@I"
    body = unpack_from(body_fmt, data, offset)
    desc_count = body[0]
    offset += calcsize(body_fmt);
    print "desc_count: %d  descs offset: %d\n" % (desc_count, offset)
    while desc_count > 0:
      desc_fmt = "@QBBBBI"
      desc_size = calcsize(desc_fmt)
      print "descriptor size: %d\n" % (desc_size)
      addr, dealloc, copy, pad, desc_type, size = unpack_from(desc_fmt,
          data, offset)
      print "addr: %s  dealloc: %d copy: %d type: 0x%x  size: %d(0x%x)" % \
          (hex(addr), dealloc, copy, desc_type, size, size)
      if desc_type == 1 and addr != 0:
        dump_ptr(addr, size, filename, inferior)
      desc_count -= 1
      offset += desc_size

parse_data.counter = 0
