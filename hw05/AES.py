#!/usr/bin/env python3
# Homework number: 4
# Name: Jason Park
# ECN Login: park1036
# Due Date: 2/23

# py AES.py -e message.txt key.txt encrypted.txt
# py AES.py -d encrypted.txt key.txt decrypted.txt

# Aspects of code modified from: https://github.com/brian-rieder/computer-security/blob/master/AES/aes.py
#        roundkey generation, bitvector to state array
#        Note: I'm not sure if I recalled all the code that could be flagged as from the link above.
#               For that, I apologize.

import sys
from BitVector import *
from gen_key_schedule import *
from gen_tables import *

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

AES_modulus = BitVector(bitstring='100011011')

subBytes = [ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 202, 130, 201, 125,
                 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147,  38,  54,  63, 247, 204,
                  52, 165, 229, 241, 113, 216,  49,  21,   4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226,
                 235,  39, 178, 117,   9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
                  83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207, 208, 239, 170, 251,
                  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,  81, 163,  64, 143, 146, 157,  56, 245,
                 188, 182, 218,  33,  16, 255, 243, 210, 205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61,
                 100,  93,  25, 115,  96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
                 224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 231, 200,  55, 109,
                 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 186, 120,  37,  46,  28, 166, 180, 198,
                 232, 221, 116,  31,  75, 189, 139, 138, 112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185,
                 134, 193,  29, 158, 225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
                 140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22]
invSubBytes = [ 82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251, 124, 227,  57, 130,
                    155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,  84, 123, 148,  50, 166, 194,  35,  61,
                    238,  76, 149,  11,  66, 250, 195,  78,   8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73,
                    109, 139, 209,  37, 114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
                    108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132, 144, 216, 171,   0,
                    140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6, 208,  44,  30, 143, 202,  63,  15,   2,
                    193, 175, 189,   3,   1,  19, 138, 107,  58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206,
                    240, 180, 230, 115, 150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
                     71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27, 252,  86,  62,  75,
                    198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,  31, 221, 168,  51, 136,   7, 199,  49,
                    177,  18,  16,  89,  39, 128, 236,  95,  96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159,
                    147, 201, 156, 239, 160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
                     23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125]

def mix_cols(state):
    # convert state array to hex instead of hexstrings
    hex2 = BitVector(hexstring='02')
    hex3 = BitVector(hexstring='03')
    mixed = [[0 for i in range(4)] for j in range(4)]
    for j in range(4):
        mixed[0][j] = (state[0][j].gf_multiply_modular(hex2, AES_modulus, 8)) ^ (state[1][j].gf_multiply_modular(hex3, AES_modulus, 8)) ^ state[2][j] ^ state[3][j]
        mixed[1][j] = state[0][j] ^ (state[1][j].gf_multiply_modular(hex2, AES_modulus, 8)) ^ (state[2][j].gf_multiply_modular(hex3, AES_modulus, 8)) ^ state[3][j]
        mixed[2][j] = state[0][j] ^ state[1][j] ^ (state[2][j].gf_multiply_modular(hex2, AES_modulus, 8)) ^ (state[3][j].gf_multiply_modular(hex3, AES_modulus, 8))
        mixed[3][j] = (state[0][j].gf_multiply_modular(hex3, AES_modulus, 8)) ^ state[1][j] ^ state[2][j] ^ (state[3][j].gf_multiply_modular(hex2, AES_modulus, 8))
    return mixed 

def inv_mix_cols(state):
    # convert state array to hex instead of hexstrings
    hexE = BitVector(hexstring='0E')
    hexB = BitVector(hexstring='0B')
    hexD = BitVector(hexstring='0D')
    hex9 = BitVector(hexstring='09')
    mixed = [[0 for i in range(4)] for j in range(4)]
    for j in range(4):
        mixed[0][j] = state[0][j].gf_multiply_modular(hexE, AES_modulus, 8) ^ state[1][j].gf_multiply_modular(hexB, AES_modulus, 8) ^ state[2][j].gf_multiply_modular(hexD, AES_modulus, 8) ^ state[3][j].gf_multiply_modular(hex9, AES_modulus, 8)
        mixed[1][j] = state[0][j].gf_multiply_modular(hex9, AES_modulus, 8) ^ state[1][j].gf_multiply_modular(hexE, AES_modulus, 8) ^ state[2][j].gf_multiply_modular(hexB, AES_modulus, 8) ^ state[3][j].gf_multiply_modular(hexD, AES_modulus, 8)
        mixed[2][j] = state[0][j].gf_multiply_modular(hexD, AES_modulus, 8) ^ state[1][j].gf_multiply_modular(hex9, AES_modulus, 8) ^ state[2][j].gf_multiply_modular(hexE, AES_modulus, 8) ^ state[3][j].gf_multiply_modular(hexB, AES_modulus, 8)
        mixed[3][j] = state[0][j].gf_multiply_modular(hexB, AES_modulus, 8) ^ state[1][j].gf_multiply_modular(hexD, AES_modulus, 8) ^ state[2][j].gf_multiply_modular(hex9, AES_modulus, 8) ^ state[3][j].gf_multiply_modular(hexE, AES_modulus, 8)
    return mixed

def array_to_bv(state_arr):
    merged = BitVector(size=0)
    for j in range(4):
        for i in range(4):
            merged += state_arr[i][j]
    return merged

def encrypt(ptext_bv, _key):
    print("Getting Roundkeys")
    # generate key schedule + round keys
    FILEIN = open(_key, 'r')
    key = FILEIN.read().replace('\n','')
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_128(key_bv)
    round_keys = [None for i in range(11)]
    for i in range(11):
        round_keys[i] = key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]

    # empty bitvector
    out_bv = BitVector(size=0)

    # get the sbox for encryption
    print("Getting SubBytes Table")
    #subBytes = genTables('-e')

    # initalize empty array
    state_arr = [[0 for i in range(4)] for j in range(4)]

    print("Starting AES Encryption") # TODO - check if 256-128 means that read 64 bits instead of 128W
    # get 64 bit block from plaintext
    while (ptext_bv.more_to_read):
        part_bv = ptext_bv.read_bits_from_file(64)
        # make sure it's 64 bits long
        part_bv.pad_from_right(64-part_bv.length())
        # xor with the first roundkey 
        part_bv = part_bv ^ round_keys[0]                                 
        # create the state array
        for i in range(4):
            for j in range(4):
                # this is a bitvector -> 4x4 array instruction
                state_arr[j][i] = part_bv[32*i + 8*j:32*i + 8*(j+1)] 
        for rnd in range(1, 11):      
            # each round has 4 steps: (256 bit key size = 14 rounds)
            # 1. Single-byte based substitution 
            for i in range(4):
                for j in range(4):
                    addTo = int(subBytes[int(state_arr[i][j])])
                    state_arr[i][j] = BitVector(intVal=addTo, size=8)                   
            # 2. Row-wise permutation 
            state_arr[1] = state_arr[1][1:] + state_arr[1][:1]
            state_arr[2] = state_arr[2][2:] + state_arr[2][:2]
            state_arr[3] = state_arr[3][3:] + state_arr[3][:3]
            
            # 3. Column-wise mixing
            if (rnd != 11):
                state_arr = mix_cols(state_arr)
                                          
            # 4. Addition of the roundkey
            state_bv = array_to_bv(state_arr)
            state_bv = state_bv ^ round_keys[rnd]

            # Making it a state array again                            
            for i in range(4):
                for j in range(4):
                    # this is a bitvector -> 4x4 array instruction
                    state_arr[j][i] = state_bv[32*i + 8*j:32*i + 8*(j+1)]
        
        # FILEOUT.write(state_bv.get_bitvector_in_hex())
        out_bv += state_bv
    print("\nFinished!")
    return out_bv

def decrypt(c_text_bv, _key): 
    print("Getting Inverse Roundkeys")
    # generate key schedule + round keys
    FILEIN = open(_key, 'r')
    key = FILEIN.read().replace('\n','')
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_128(key_bv)
    round_keys = [None for i in range(11)]
    for i in range(11):
        round_keys[i] = key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]

    # empty_bv
    out_bv = BitVector(size=0)

    # get the sbox for encryption
    print("Getting Inverse SubBytes Table")
    #subBytes = genTables('-e')

    # initalize empty array
    state_arr = [[0 for i in range(4)] for j in range(4)]

    print("Starting AES Decryption")
    # get 32 bit block from plaintext
    while (1):
        c_text_bv
        if (c_text_bv.length() <= 0):
            break
        # make sure it's 32 bits long
        c_text_bv.pad_from_right(32-c_text_bv.length())
        # xor with the first roundkey 
        c_text_bv = c_text_bv ^ round_keys[14]                                 
        # create the state array
        for i in range(4):
            for j in range(4):
                # this is a bitvector -> 4x4 array instruction
                state_arr[j][i] = c_text_bv[32*i + 8*j:32*i + 8*(j+1)] 
        for rnd in range(9, -1, -1):      
            # each round has 4 steps: (128 bit key size = 14 rounds)
            # 1. Inverse Row-wise permutation 
            state_arr[1] = state_arr[1][-1:] + state_arr[1][:-1]
            state_arr[2] = state_arr[2][-2:] + state_arr[2][:-2]
            state_arr[3] = state_arr[3][-3:] + state_arr[3][:-3]
            
            # 2. Inverse Single-byte based substitution 
            for i in range(4):
                for j in range(4):
                    addTo = int(invSubBytes[int(state_arr[i][j])])
                    state_arr[i][j] = BitVector(intVal=addTo, size=8)                   
    
            # 3. Addition of the roundkey
            state_bv = array_to_bv(state_arr)
            state_bv = state_bv ^ round_keys[rnd]
            
            if (rnd != 0):
                # Making it a state array again                            
                for i in range(4):
                    for j in range(4):
                        # this is a bitvector -> 4x4 array instruction
                        state_arr[j][i] = state_bv[32*i + 8*j:32*i + 8*(j+1)]
            
                # 4. Inverse Column-wise mixing
                state_arr = inv_mix_cols(state_arr)
        out_bv += array_to_bv(state_arr)
    print("\nFinished!")
    return out_bv

def main():
    if (len(sys.argv) != 5):
        print("[ERROR] Usage Error")
        sys.exit(0)
    if (sys.argv[1] == '-e'):
        # encrypt mode
        print("Encrypting with AES...")
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    elif (sys.argv[1] == '-d'):
        # decrypt mode
        print("Decrypting with AES...")
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4])

main()