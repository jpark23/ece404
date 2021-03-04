#!/usr/bin/env python 

# Name: Jason Park    
# ECN Login: park1036 
# Due Date: 2/4/2021

# DES_image.py image.ppm key.txt image_enc.ppm

import sys
from BitVector import *
from generate_round_keys import *
from get_encryption_key import *
from illustrate_des_substitution import *
from bitstring import *

p_box = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

def encrypt(infile, _key, outfile):
    # getting key and roundkeys
    key = get_encryption_key(_key)
    round_keys = generate_round_keys(key)

    # opening the file
    FILEIN = open(infile, "rb")

    # skipping and saving the header
    header = [FILEIN.readline(), FILEIN.readline(), FILEIN.readline()]
    
    FILEOUT = open(outfile, "wb")
    FILEOUT.write(header[0])
    FILEOUT.write(header[1])
    FILEOUT.write(header[2])

    while (1):
        # saving the rest of the file
        raw = FILEIN.read(8).hex()
        if (raw == 0):
            break
        # create bitvector
        image_bv = BitVector(hexstring = raw)
        bitvec = image_bv
        if (bitvec.length() > 0):
            if (bitvec.length() % 64 != 0):
                bitvec.pad_from_right(64 - (bitvec.length() % 64)) # padding zeroes    
            [LE, RE] = bitvec.divide_into_two() # splits the original block in half
            for one_rndkey in round_keys:
                saveLeft = RE.deep_copy()
                newRE = RE.permute( expansion_permutation ) # permute/contract the right side (32->48 bits)
                out_xor = newRE.__xor__( one_rndkey ) # "key-mixing" 
                out_sbox = substitute( out_xor ) # substitution (48->32 bits)
                right_half = out_sbox.permute( p_box ) # sbox permutation 
                final_right = right_half.__xor__( LE ) # xoring with the original left
                # at this point, left = RE, right = final_right      <- one round of DES
                LE = saveLeft
                RE = final_right   
        else:
            break
        bit_hex = RE.get_bitvector_in_hex() + LE.get_bitvector_in_hex()
        image_bits = BitVector(hexstring = bit_hex)
        image_bits.write_to_file(FILEOUT)        

def main():
    if (len(sys.argv) != 4):
        print("Needs 3 arguments!")
    else:
        encrypt(sys.argv[1], sys.argv[2], sys.argv[3])

main()