#!/usr/bin/env python

## get_encryption_key.py

import sys
from BitVector import *

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

def get_encryption_key(_key):
    FILEIN = open(_key, "r")
    key = FILEIN.read().replace('\n', '')
    key = BitVector(textstring = key)
    key = key.permute(key_permutation_1)
    return key