#!/usr/bin/python2

import struct


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

from collections import namedtuple
Section = namedtuple("Section", ["name", "size"])
def read_sec_table(fh):
    tsize = struct.unpack("<H", fh.read(2))[0]

    secs = {}
    for i in range(tsize):
        sname = fh.read(0x40)
        sname = sname.rstrip('\x00')
        overlap = struct.unpack("<H", fh.read(2))[0]
        if overlap == i:
            ovl_name = ""
        else: ovl_name = " (%s)" % secs[overlap].name
        tent = fh.read(0x14)
        assert tent[4:] == '\x00' * (len(tent) -4)
        u1 = struct.unpack("<L", tent[:4])[0]
        print "\t\t%4x %8x %-40s" % (i, u1, sname + ovl_name)
                                         
        secs[i] = Section(sname, u1)
    return secs



Symbol = namedtuple("Symbol", ["name", "sect", "addr"])

def read_sym_table(fh, sections, is_def=False):
    syms = {}
    n = struct.unpack("<H",fh.read(2))[0]
    for x in range(n):
        sym = fh.read(0x21).rstrip("\x00")
        rem = fh.read(0x10)
        addr = struct.unpack("<L",rem[:4])[0]
        rem = rem[4:]
        
        typ = ord(rem[0])
        tstr = " "
        assert typ <= 1
        if typ == 1:
            tstr = 'V' # Symbol is a literal value, not an address

        rem = rem[1:]
        assert rem[:6] == "\x00" * 6
        sect = struct.unpack("<H", rem[6:8])[0]
        if not is_def:
            assert sect == 0
            sect_name = ""
        else:
            sect_name = sections[sect].name
            sect_size = sections[sect].size

        symb = Symbol(sym, sect, addr)
        syms[x] = symb

        assert rem[8:0xA] == '\x00\x00'
        is_priv = ord(rem[0xA])
        assert is_priv <=1

        pstr = ' '
        if not is_priv:
            pstr = 'P'

        print "\t\t%04x %s%s %-32s %08x %s" %(x, tstr,pstr, sym, addr,
                                            sect_name)
        if typ == 0 and is_def:
            assert addr <= sect_size
    return syms


def read_0x15_rec(fh, imptab, sectab):
    pos = fh.tell()
    dat = fh.read(2)
    if not dat:
        return False
    a,sel = struct.unpack("BB", dat)

    if sel == 0:
        return False
    #elif sel == 2:
    #    size = struct.unpack("<H", fh.read(2))[0]
    #    payload = fh.read(0x1 + size)
    #elif sel == 3:
    #    size = struct.unpack("B", fh.read(1))[0]
    #    if size == 0:
    #        payload = fh.read(0x3)
    #    elif size in (0x51, 0x55):
    #        payload = fh.read(0x2)
    #    elif size == 1:
    #        payload = fh.read(0x0E)
    #   else:
    #       print "t3 unk flags %d @ %x" % (size, pos)
    #        print fh.read(18).encode("hex")
    #        assert False
    elif sel == 6:
        payload = fh.read(0xa)
        p2size = struct.unpack("<L", fh.read(4))[0]
        pay2 = fh.read(p2size)
        p3 = fh.read(0x5)
        assert payload[:3] == '\x00\x00\x00'
        # [3:5] section
        # [5:9] some kind of other data?
        assert payload[4] == '\x00'
        assert payload[-1] == '\x02'
        assert a == 0

        sect,startline = struct.unpack("<HL", payload[3:-1])
        #print "%-40s %08x <= %08x+%08x" % (sectab[sect].name, sectab[sect].size,
                                          #add1, p2size)
        #assert (add1 + p2size) <= sectab[sect].size

        # Seems to always be '\x03'
        assert p3[0] == '\x03'
        p3size = struct.unpack("<L",p3[1:])[0]

        print "%08x\t %04x Line:%d %08x"%(pos, sect, startline, p2size), pay2.encode('hex')

        ts = 0
        for i in range(p3size):
            b = fh.read(0x11)
            fixpoint, reloc_type, offset,base, lineafter = struct.unpack("<LBLHL", b[:15])
            if base & 0x8000:
                obstr = "%s" % (imptab[base&0x7FFF].name,)
            else:
                obstr = "%s" % (sectab[base].name,)
            ts += reloc_type
            print "\t\t\t%08x %02x %32s:%-6x (LineA: %d)" % (
                fixpoint,reloc_type,obstr,offset, lineafter), b[15:].encode("hex")

            # The fixup inside the buffer must be within the size of the data
            assert fixpoint < p2size
            # As its a word arch, fixups are on word boundaries
            assert fixpoint % 2 == 0

            # LMA
            assert lineafter >= startline
            #assert addr_at_reloc <= (add1 + p2size)

            assert reloc_type in (4,7,9)
    else: 
        print "Unknown selector %x at %x" % (sel, fh.tell())
        exit()
        return False

    #print "\t\t%08x %02x %02x %s" % (pos, a, sel, payload.encode("hex"))
    return True


def read_subfile_inner(fh):
    hdr = fh.read(0x20)
    assert hdr.rstrip("\x00") == "Sunnorth&SunplusObj"
    vers = fh.read(4)
    assert vers == "1.00"
    unk = fh.read(6)
    print "\tUnk: %s" % unk.encode("hex")
    subfiles = read_str_tab(fh)
    print "\tSourcefiles:"
    for i in subfiles:
        print "\t\t%s" % i

    print "\tSections:"
    sections = read_sec_table(fh)

    print "\tImported Symbols:"
    imptab = read_sym_table(fh, sections)

    print "\tExported Symbols:"
    read_sym_table(fh, sections, True)

    print "\tPrivate Symbols:"
    read_sym_table(fh, sections, True)

    print "\tVLA @ %x"
    while 1:
        if not read_0x15_rec(fh, imptab, sections):
            break

    #print "%08x"% fh.tell()

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
    print vers_str
    #assert vers_str == "1.0\x00"

    n_files = struct.unpack("<L", fh.read(4))[0]

    for fn in range(n_files):
        print "Subfile: %d" % fn
        read_subfile(fh)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("fh", type=argparse.FileType("rb"))
    ap.add_argument("--is-lib", action="store_true")
    args = ap.parse_args()

    args.fh.seek(0)

    if args.is_lib:
        read_ar_file(args.fh)
    else:
        read_subfile_inner(args.fh)

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
