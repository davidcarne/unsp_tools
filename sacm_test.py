import struct

fh = open("SACM_A1800_V41b_Beta02.lib","rb")

def read_str(fh):
    slen = struct.unpack("<L", fh.read(4))[0]
    s = fh.read(slen)
    return s

def read_str_tab(fh):
    l = []
    tlen = struct.unpack("<H", fh.read(2))[0]
    for idx in range(tlen):
        slen = struct.unpack("<L", fh.read(4))[0]
        assert slen < 0x800
        s = fh.read(slen)
        l.append(s)
    return l

def read_sec_table(fh):
    tsize = struct.unpack("<H", fh.read(2))[0]

    for i in range(tsize):
        sname = fh.read(0x40)
        sname = sname.rstrip('\x00')
        tent = fh.read(0x16)
        print "\t\t%-40s %s" % (sname,tent.encode("hex"))



def read_sym_table(fh):
    n = struct.unpack("<H",fh.read(2))[0]
    for x in range(n):
        sym = fh.read(0x21).rstrip("\x00")
        rem = fh.read(0x10)
        addr = struct.unpack("<L",rem[:4])[0]
        rem = rem[4:]
        print "\t\t%04x %-42s %08x %s" %(x, sym, addr, rem.encode("hex"))


def read_0x15_rec(fh):
    pos = fh.tell()
    a,sel = struct.unpack("BB", fh.read(2))

    if sel == 0:
        return False
    elif sel == 2:
        size = struct.unpack("<H", fh.read(2))[0]
        payload = fh.read(0x1 + size)
    elif sel == 3:
        size = struct.unpack("B", fh.read(1))[0]
        if size == 0:
            payload = fh.read(0x3)
        elif size in (0x51, 0x55):
            payload = fh.read(0x2)
        elif size == 1:
            payload = fh.read(0x0E)
        else:
            print "t3 unk flags %d @ %x" % (size, pos)
            assert False
    elif sel == 6:
        payload = fh.read(0x8)
    else: 
        print "Unknown selector %x at %x" % (sel, fh.tell())
        return False

    print "\t\t%08x %02x %02x %s" % (pos, a, sel, payload.encode("hex"))
    return True


def read_subfile_inner(fh):
    hdr = fh.read(0x20)
    assert hdr.rstrip("\x00") == "Sunnorth&SunplusObj"
    vers = fh.read(4)
    assert vers == "1.00"
    unk = fh.read(6)
    print "\tUnk: %s" % unk.encode("hex")
    subfiles = read_str_tab(fh)
    print "\tSubfiles:"
    for i in subfiles:
        print "\t\t%s" % i

    print "\tSections:"
    read_sec_table(fh)

    print "\tImports:"
    read_sym_table(fh)

    print "\tOther1:"
    read_sym_table(fh)

    print "\tOther2:"
    read_sym_table(fh)

    print "\tVLA @ %x"
    while 1:
        if not read_0x15_rec(fh):
            break

    print "%08x"% fh.tell()

def read_subfile(fh):
    bdir = read_str(fh)
    print "\tDIR: %s" % bdir
    
    unk = fh.read(0x6)
    print "\tUNK: %s" % unk.encode("hex")

    # some kind of list of symnames. Exports/imports?
    exports = read_str_tab(fh)
    print "\tExports?:"
    for sf in exports:
        print "\t\t%s" % sf


    size = struct.unpack("<L", fh.read(4))[0]
    pos = fh.tell()

    read_subfile_inner(fh)

    #print "Seek to %08x" % (pos+size)
    fh.seek(pos+size)
    #exit(0)



def read_ar_file(fh):
    spl_header = fh.read(0x10)
    assert spl_header == "SunplusLib\x00\x00\x00\x00\x00\x00"
    vers_str = fh.read(0x4)
    assert vers_str == "1.0\x00"

    n_files = struct.unpack("<L", fh.read(4))[0]

    for fn in range(n_files):
        print "Subfile: %d" % fn
        read_subfile(fh)


fh.seek(0)
read_ar_file(fh)

#fh.seek(0x4C)
#read_str_tab_1(fh)

#fh.seek(0xDA)
#read_str_tab_1(fh)
#fh.seek(0x414)
#read_sec_table(fh)
#fh.seek(0xBD0)
#read_sym_table(fh)
#read_sym_table(fh)
#read_sym_table(fh)
#print("%08x"% fh.tell())
