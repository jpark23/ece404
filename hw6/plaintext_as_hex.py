from BitVector import *
import sys

def get(ptextFile, outfile):
    FILEOUT = open(outfile, 'w')
    file_bv = BitVector(filename=ptextFile)
    while(file_bv.more_to_read):
        ctext_bv = file_bv.read_bits_from_file(128)
        if (ctext_bv.length() != 128):
            ctext_bv.pad_from_right(128 - ctext_bv.length())
        FILEOUT.write(ctext_bv.get_bitvector_in_hex())

def main():
    get(sys.argv[1], sys.argv[2])

main()