import struct

def read_str(fh):
    """Reads a 4-byte LE length-formatted string from file fh"""
    slen = struct.unpack("<L", fh.read(4))[0]
    s = fh.read(slen)
    return s

def read_str_tab(fh):
    """reads a table of strings from file fh"""
    l = []
    tlen = struct.unpack("<H", fh.read(2))[0]
    for idx in range(tlen):
        slen = struct.unpack("<L", fh.read(4))[0]

        # Sanity
        assert slen < 0x800
        s = fh.read(slen)
        l.append(s)
    return l

