#!/usr/bin/env python3

# Name: Jason Park  
# ECN Login: park1036   
# Due Date: 3/19/21

### THIS CODE IS MODIFIED AND BORROWED FROM SHA256.py FROM PROFESSOR KAK'S LECTURE NOTES ###

### For sha-512, block size 512->1024 bits, word size 32->64 bits, message digest size 256->512 bits

def pad_bits(msg_bv):
    length = msg_bv.length()
    bv1 = msg_bv + BitVector(bitstring='1')
    length1 = bv1.length()
    numZeros = (896 - length1) % 1024
    zeroList = [0] * numZeros
    bv2 = bv1 + BitVector(bitlist=zeroList)
    bv3 = BitVector(intVal=length, size=128)
    padded_bv = bv2 + bv3
    return padded_bv

def msg_schedule(words, padded_bv):
    for n in range(0, padded_bv.length(), 1024):
        block = padded_bv[n:n+1024]
    # First 16 words obtained directly from the 1024-bit message block
    words[0:16] = [block[i:i+64] for i in range(0, 1024, 64)]
    # Rest of words are obtained by applying permutation and mixing ops to the sum of the previously generated words
    for i in range(16, 80):                      
        i_minus_2_word = words[i-2]
        i_minus_15_word = words[i-15]
        #  The sigma1 function is applied to the i_minus_2_word and the sigma0 function is applied to 
        #  the i_minus_15_word:
        sigma0 = (i_minus_15_word.deep_copy() >> 7) ^ (i_minus_15_word.deep_copy() >> 18) ^ (i_minus_15_word.deep_copy().shift_right(3))
        sigma1 = (i_minus_2_word.deep_copy() >> 17) ^ (i_minus_2_word.deep_copy() >> 19) ^ (i_minus_2_word.deep_copy().shift_right(10))
        words[i] = BitVector(intVal=(int(words[i-16]) + int(sigma1) + int(words[i-7]) + int(sigma0)) & 0xFFFFFFFFFFFFFFFF, size=64)
    return words

def rnd_processing(words):
    #  The K constants (also referred to as the "round constants") are used in round-based processing 
    #  of each 1024-bit input message block.  There is a 64-bit constant for each of the 80 rounds. 
    #  These are as provided on page 10 (page 14 of the PDF) of the NIST standard.  Note that these 
    #  are ONLY USED in STEP 3 of the hashing algorithm where we take each 1024-bit input message block 
    #  through 80 rounds of processing.
    K = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
         "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
         "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
         "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
         "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
         "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
         "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
         "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
         "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
         "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
         "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
         "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
         "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
         "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
         "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
         "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
         "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
         "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
         "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
         "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]
     
    #  Store the 80 K constants as an array of BitVector objects:
    K_bv = [BitVector(hexstring = k_constant) for k_constant in K]

    h0 = BitVector(hexstring='6a09e667')
    h1 = BitVector(hexstring='bb67ae85')
    h2 = BitVector(hexstring='3c6ef372')
    h3 = BitVector(hexstring='a54ff53a')
    h4 = BitVector(hexstring='510e527f')
    h5 = BitVector(hexstring='9b05688c')
    h6 = BitVector(hexstring='1f83d9ab')
    h7 = BitVector(hexstring='5be0cd19')
    a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

    for i in range(80):
        ch = (e & f) ^ ((~e) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        sum_a = ((a.deep_copy()) >> 2) ^ ((a.deep_copy()) >> 13) ^ ((a.deep_copy()) >> 22)
        sum_e = ((e.deep_copy()) >> 6) ^ ((e.deep_copy()) >> 11) ^ ((e.deep_copy()) >> 25)
        t1 = BitVector(intVal=(int(h) + int(ch) + int(sum_e) + int(words[i]) + int(K_bv[i])) & 0xFFFFFFFFFFFFFFFF, size=64)                                                                     
        t2 = BitVector(intVal=(int(sum_a) + int(maj)) & 0xFFFFFFFFFFFFFFFF, size=64)
        h = g
        g = f
        f = e
        e = BitVector(intVal=(int(d) + int(t1)) & 0xFFFFFFFFFFFFFFFF, size=64)
        d = c
        c = b
        b = a
        a = BitVector(intVal=(int(t1) + int(t2)) & 0xFFFFFFFFFFFFFFFF, size=64)
    return a,b,c,d,e,f,g,h

def update_hash(a,b,c,d,e,f,g,h):
    #  The 8 32-words used for initializing the 512-bit hash buffer before we start scanning the
    #  input message block for its hashing. See page 13 (page 17 of the PDF) of the NIST standard.
    #  Note that the hash buffer consists of 8 32-bit words named h0, h1, h2, h3, h4, h5, h6, and h7.
    h0 = BitVector(hexstring='6a09e667')
    h1 = BitVector(hexstring='bb67ae85')
    h2 = BitVector(hexstring='3c6ef372')
    h3 = BitVector(hexstring='a54ff53a')
    h4 = BitVector(hexstring='510e527f')
    h5 = BitVector(hexstring='9b05688c')
    h6 = BitVector(hexstring='1f83d9ab')
    h7 = BitVector(hexstring='5be0cd19')
    h0 = BitVector( intVal = (int(h0) + int(a)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h1 = BitVector( intVal = (int(h1) + int(b)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h2 = BitVector( intVal = (int(h2) + int(c)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h3 = BitVector( intVal = (int(h3) + int(d)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h4 = BitVector( intVal = (int(h4) + int(e)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h5 = BitVector( intVal = (int(h5) + int(f)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h6 = BitVector( intVal = (int(h6) + int(g)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    h7 = BitVector( intVal = (int(h7) + int(h)) & 0xFFFFFFFFFFFFFFFF, size=64 )
    return h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7

def sha512(inFILE, outFile):
    ## Step 1 ##
    #   Pad the message so that its length is an integral multiple of 1024 bits
    #   Only complication is that the last 128 bits of the last block must contain the message length value
    # INPUT FILE IS A TEXTSTRING   
    FILEIN = open(inFILE, 'r')
    message = FILEIN.read()
    msg_bv = BitVector(textstring=message)
    padded_bv = pad_bits(msg_bv)

    ## Step 2 ##
    # Generate message schedule required for processing a 1024 bit input message
    # Message schedule is 80 64-bit words
    words = [None] * 80
    words = msg_schedule(words, padded_bv)

    ## Step 3 ##
    # Apply round-based processing to each 1024-bit input message block
    # There are 80 rounds to be carried out for each message block
    # In the ith round, we permute the values stored in these eight variables
    #   with two of the variables, we mix in teh message schedule word "words[i]" and a round constant K[i]
    a,b,c,d,e,f,g,h = rnd_processing(words)

    ## Step 4 ##
    # Update the hash values calculated for the previous message block by adding to it the values in the temp variables a-h
    message_hash = update_hash(a,b,c,d,e,f,g,h)

    ## Write to output file ##
    FILEOUT = open(outFile, 'w')
    FILEOUT.write(message_hash.get_bitvector_in_hex())
    FILEIN.close()
    FILEOUT.close()

def main():
    if (len(sys.argv) != 3):
       sys.stderr.write("Usage Error! Need two arguments") 
    sha512(sys.argv[1], sys.argv[2])

# py sha512.py tohash.txt hashed.txt

from BitVector import *
from sys import *
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

main()