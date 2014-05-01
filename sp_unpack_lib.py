#!/usr/bin/python2

# (C) 2014 David Carne
# GPLv2-or-later


# Sunplus un'SP .lib unpacker
# Extracts .obj files from the concatenated .lib

# Written for python2.7

import struct
from collections import namedtuple
from sp_util import read_str, read_str_tab
import time
import os

name_idx = 1
def clean_name(name):
    global name_idx
    objname = name.strip().split("\\")[-1].replace("/","_")

    if not objname:
        objname = "%04d" % (name_idx)
        name_idx += 1
    return objname

def get_export_name(name):
    return clean_name(name) + ".obj"

def action_unpack(lib, force=False):
    for subfile in lib.entries:
        expname = get_export_name(subfile.objname)
        if os.path.exists(expname) and not force:
            print("Refusing to overwrite %s; bailing" % expname)
            return
        with open(expname, "wb") as fh:
            fh.write(subfile.data)

    
def action_show(lib):
    print("Version: %s" % lib.version)
    for subfile in lib.entries:
        print("Object: %s" % subfile.objname)
        print("\tName: %s" % clean_name(subfile.objname))
        print("\tBuild Time: %s" % time.ctime(subfile.buildtime))
        print("\tExports:")
        for export in subfile.exports:
            print("\t\t%s" % export)
        print("\tObject Size: %d bytes" % len(subfile.data))

        print("")


LibEntry = namedtuple("LibEntry", 
                      ["objname", "unk", "buildtime", "exports", "data"])
LibFile = namedtuple("LibFile", ["version", "entries"])

def parse_lib_entry(fh):
    objname = read_str(fh)
    unk, buildtime = struct.unpack("<HL",fh.read(0x6))

    # We don't know what this does yet
    # Likely a compiler version of some kind?
    #print unk
    assert unk in [8,9]

    exports = read_str_tab(fh)

    subsize = struct.unpack("<L", fh.read(4))[0]
    data = fh.read(subsize)

    # Make sure the file wasn't truncated
    assert len(data) == subsize

    return LibEntry(objname, unk, buildtime, exports, data)

    
def parse_lib_file(fh):
    fh.seek(0)

    # Check to make sure the file type is what we think it is
    spl_header = fh.read(0x10)
    assert spl_header == "SunplusLib\x00\x00\x00\x00\x00\x00"

    vers_str = fh.read(0x4).rstrip('\x00')

    n_files = struct.unpack("<L", fh.read(4))[0]
   
    entries = []
    for i in range(n_files):
        entries.append(parse_lib_entry(fh))

    return LibFile(vers_str, entries)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)

    # Build command list
    for k, v in globals().items():
        if k.startswith("action_") and callable(v):
            g.add_argument("--%s" % k[7:], dest="action", 
                   action="store_const", const=v)

    ap.add_argument("libfile", type=argparse.FileType("rb"))
    args = ap.parse_args()

    # Execute the commands
    args.action(parse_lib_file(args.libfile))




