#!/usr/bin/env python3

from BitVector import *
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption
AES_modulus = BitVector(bitstring='100011011')

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

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key_schedule(key):
    key_words = []
    key_bv = BitVector(textstring=key)
    keysize = 128    
    key_words = gen_key_schedule_128(key_bv)
    key_schedule = []
    #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        #if word_index % 4 == 0: #print("\n")
        #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
        key_schedule.append(keyword_in_ints)
    num_rounds = None
    if keysize == 128: num_rounds = 10
    if keysize == 192: num_rounds = 12
    if keysize == 256: num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
    return round_keys

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

def AESctr(ptext_bv, round_keys):
    # initalize empty array
    state_arr = [[0 for i in range(4)] for j in range(4)]
    # make sure it's 128 bits long
    ptext_bv.pad_from_right(128-ptext_bv.length())
    # xor with the first roundkey 
    ptext_bv = ptext_bv ^ round_keys[0]                                 
    # create the state array
    for i in range(4):
        for j in range(4):
            # this is a bitvector -> 4x4 array instruction
            state_arr[j][i] = ptext_bv[32*i + 8*j:32*i + 8*(j+1)] 
    for rnd in range(1, 15):      
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
# iv: 128-bit initialization vector
# image_file: input .ppm image file name
# out_file: encrypted .ppm image file name
# key_file: String of file name containing encryption key (in ASCII)
#Function Descrption:
# Encrypts image_file using CTR mode AES and writes said file to out_file. No
    #required return value.
def ctr_aes_image(iv,image_file='image.ppm',out_file='enc_image.ppm', key_file='key.txt'):
    input_bv = BitVector(filename=image_file)
    FILEOUT = open(out_file, "wb")
    header_bv = input_bv.read_bits_from_file(112)
    header_bv.write_to_file(FILEOUT)

    # precomputing the key schedule and round keys for efficiency
    # also hardcoded subbytes table from previous gen_subbytes function for speed
    FILEINa = open(key_file, 'r')
    key = FILEINa.read().replace('\n','')
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_256(key_bv)
    round_keys = [None for i in range(15)]
    for i in range(15):
        round_keys[i] = key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]

    ivCurr = iv
    block = 1
    while (input_bv.more_to_read):
        print("block " +str(block)+ " of 1483") # keep track of code runtime, 1483 ~ 23k / 128
        ptext_bv = input_bv.read_bits_from_file(128)
        ptext_bv.pad_from_right(128 - ptext_bv.length())
        iv_enc = AESctr(ivCurr, round_keys) # encrypt IV
        ctext_bv = ptext_bv ^ iv_enc # XOR with roundkey and ptext
        ctext_bv.write_to_file(FILEOUT) # write to file
        # increment everything
        ivCurr = BitVector(intVal=(ivCurr.int_val() + 1), size=128)
        block += 1

def main():
    iv = BitVector(textstring='computersecurity') #iv will be 128 bits
    ctr_aes_image(iv,'image.ppm','enc_image.ppm','keyCTR.txt')