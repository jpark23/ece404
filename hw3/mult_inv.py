#!/usr/bin/env python

## FindMI.py

import sys

def bit_divide(dividend, divisor):
    # code adapted from: https://www.geeksforgeeks.org/divide-two-integers-without-using-multiplication-division-mod-operator/

    # check for sign, store it, remove the sign
    if (dividend < 0 and divisor > 0):
        sign = -1
    elif (dividend > 0 and divisor < 0):
        sign = -1
    else:
        sign = 1
    dividend = abs(dividend)
    divisor = abs(divisor)

    # init
    quotient = 0
    temp = 0

    # this loop was taken from the above link
    ###########################################
    for i in range(31, -1, -1):
        if (temp + (divisor << i) <= dividend):
            temp += divisor << i 
            quotient |= 1 << i 
    ###########################################

    out = sign * quotient
    return out

def bit_multiply(term1, term2):
    # this code borrowed from https://www.geeksforgeeks.org/multiplication-two-numbers-shift-operator/
    out = 0
    count = 0

    # this loop taken from above link:
    #############################
    while (term2 > 0):
        if (term1 % 2 == 1):
            out += term1 << count
        count += 1
        term2 = int(term2/2)
    #############################

    return out
    

def MI(num, mod):
    # This function uses ordinary integer arithmetic implementation of the
    # Extended Euclid’s Algorithm to find the MI of the first-arg integer
    # vis-a-vis the second-arg integer.
    n = bit_multiply(4,5)
    print(n)
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = bit_divide(num, mod)
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
        if num != 1:
            print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
        else:
            MI = (x_old + MOD) % MOD
            print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))

def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: %s <integer> <modulus>\n" % sys.argv[0])
        sys.exit(1)
    NUM, MOD = int(sys.argv[1]), int(sys.argv[2])
    MI(NUM, MOD)

main()