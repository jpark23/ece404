#!/usr/bin/env python3
#import x931
from BitVector import *

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

AES_modulus = BitVector(bitstring='100011011')

subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def genTables(flag):
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256): 
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    if (flag == '-e'):
        return subBytesTable
    elif (flag == '-d'):
        return invSubBytesTable

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def array_to_bv(state_arr):
    merged = BitVector(size=0)
    for j in range(4):
        for i in range(4):
            merged += state_arr[i][j]
    return merged

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

def encrypt(ptext_bv, _key):
    #print("Getting Roundkeys")
    # generate key schedule + round keys
    FILEIN = open(_key, 'r')
    key = FILEIN.read().replace('\n','')
    key_bv = BitVector(textstring=key)
    # key is 256 bits
    key_words = gen_key_schedule_256(key_bv)
    round_keys = [None for i in range(15)]
    for i in range(15):
        round_keys[i] = key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]

    # get the sbox for encryption
    #print("Getting SubBytes Table")
    subBytes = genTables('-e')

    #print("Starting AES Encryption") 
    # get 128 bit block from plaintext
    #[left_bv, right_bv] = ptext_bv.divide_into_two()
    enc_bv = AES(ptext_bv, round_keys, subBytes)
    #right_enc_bv = AES(right_bv, round_keys, subBytes)
    return enc_bv

def AES(part_bv, round_keys, subBytes):
    # empty bitvector
    out_bv = BitVector(size=0)
    # initalize empty array
    state_arr = [[0 for i in range(4)] for j in range(4)]
    # make sure it's 128 bits long
    part_bv.pad_from_right(128-part_bv.length())
    # xor with the first roundkey 
    part_bv = part_bv ^ round_keys[0]                                 
    # create the state array
    for i in range(4):
        for j in range(4):
            # this is a bitvector -> 4x4 array instruction
            state_arr[j][i] = part_bv[32*i + 8*j:32*i + 8*(j+1)] 
    for rnd in range(1, 15):      
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
        if (rnd != 14):
            state_arr = mix_cols(state_arr)
                                          
        # 4. Addition of the roundkey
        state_bv = array_to_bv(state_arr)
        state_bv = state_bv ^ round_keys[rnd]

        # Making it a state array again                            
        for i in range(4):
            for j in range(4):
                # this is a bitvector -> 4x4 array instruction
                state_arr[j][i] = state_bv[32*i + 8*j:32*i + 8*(j+1)]
        
    return state_bv

#Arguments:
# v0: 128-bit BitVector object containing the seed value
# dt: 128-bit BitVector object symbolizing the date and time
# key_file: String of file name containing the encryption key (in ASCII) for AES
# totalNum: integer indicating the total number of random numbers to generate
#Function Description
# Uses the arguments with the X9.31 algorithm to generate totalNum random
#   numbers as BitVector objects
#Returns a list of BitVector objects, with each BitVector object representing a
#   random number generated from X9.31
def x931(v0, dt, totalNum, key_file):
    listX931 = []
    vCurrent = v0
    rnd = 0
    while (rnd < totalNum):
        print("Round", rnd+1)
        # 1. Date and time AES
        dt_enc_bv = encrypt(dt, key_file)
        # 2. XOR ^ with V0
        dt_encLeft_bv = dt_enc_bv ^ vCurrent
        # 3. AES to Rj output
        rj_bv = encrypt(dt_encLeft_bv, key_file)
        listX931.append(rj_bv)
        # 4. take AESout step 1, XOR with AESout step 3
        one_more_aes_bv = rj_bv ^ dt_enc_bv
        # 5. AES above to V(j+1) out
        vCurrent = encrypt(one_more_aes_bv, key_file)
        rnd += 1

    return listX931

def main():
    v0 = BitVector(textstring="computersecurity") #v0 will be  128 bits
    #As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal = 501, size=128)
    #listX931 = x931.x931(v0,dt,3,"keyX931.txt")
    listX931 = x931(v0,dt,3,"keyX931.txt")
    #Check if list is correct
    print("{}\n{}\n{}".format(int(listX931[0]),int(listX931[1]),int(listX931[2])))
