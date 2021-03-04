#!/usr/bin/env python 

# Name: Jason Park    
# ECN Login: park1036 
# Due Date: 2/4/2021

# py des.py -e message.txt key.txt encrypted.txt
# py des.py -d encrypted.txt key.txt decrypted.txt

import sys
from BitVector import *
from generate_round_keys import *
from get_encryption_key import *
from illustrate_des_substitution import *

p_box = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

def encrypt(message, _key, output):
    # generating the keys and roundkeys
    key = get_encryption_key(_key)
    round_keys = generate_round_keys(key)
    
    # opening the file
    plaintext_bv = BitVector(filename = message)

    FILEOUT = open(output, "w")
    # feistel function / des
    while (plaintext_bv.more_to_read):
        bitvec = plaintext_bv.read_bits_from_file(64)
        bitvec.pad_from_right(64-bitvec.length()) # padding zeroes       
        if (bitvec.length() > 0 and bitvec.length() == 64):
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
        elif (len(bitvec) != 64):
            print("UH OH bitvector not 64 bits")
            break    
        encrypted = RE.get_bitvector_in_hex() + LE.get_bitvector_in_hex() # combining into one bitvector
        FILEOUT.write(encrypted) # writing to file

    FILEOUT.close()    

def decrypt(enc_msg, _key, output):
    # generating the keys and roundkeys
    key = get_encryption_key(_key)
    round_keys = generate_round_keys(key)
    
    # opening the file
    FILEIN = open(enc_msg, "r")

    FILEOUT = open(output, "w")
    # feistel function / des
    while (1):
        read = FILEIN.read(16)
        bitvec = BitVector(hexstring = read)
        if (bitvec.length() > 0):
            bitvec.pad_from_right(64-bitvec.length()) # padding zeroes      
            if (bitvec.length() > 0 and bitvec.length() == 64):
                [LE, RE] = bitvec.divide_into_two() # splits the original block in half
                for one_rndkey in reversed(round_keys):
                    saveLeft = RE.deep_copy()
                    newRE = RE.permute( expansion_permutation ) # permute/contract the right side (32->48 bits)
                    out_xor = newRE.__xor__( one_rndkey ) # "key-mixing" 
                    out_sbox = substitute( out_xor ) # substitution (48->32 bits)
                    right_half = out_sbox.permute( p_box ) # sbox permutation 
                    final_right = right_half.__xor__( LE ) # xoring with the original left
                    # at this point, left = RE, right = final_right      <- one round of DES
                    LE = saveLeft
                    RE = final_right
            elif (len(bitvec) != 64):
                print("UH OH bitvector not 64 bits")
                break    
            encrypted = RE.get_bitvector_in_ascii() + LE.get_bitvector_in_ascii() # combining into one bitvector
            FILEOUT.write(encrypted) # writing to file
        else:
            break

    FILEOUT.close()

def main():
    if (len(sys.argv) != 5): 
        print("Needs 4 arguments!")
    else:
        if (sys.argv[1] == '-e'): # encrypt mode
            print("Encrypting...")
            encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
            print("Done!")
        elif (sys.argv[1] == '-d'): # decrypt mdoe
            print("Decrypting...")
            decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
            print("Done!")
        else:
            print ("Incorrect test flag, must use -e or -d")

main()