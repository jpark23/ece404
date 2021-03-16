### Function for computing the Miller-Rabin Test for Primality ###

def step1(n):
    n = int(n) - 1
    print("\nStep 1:")
    print("n-1 = "+str(n)+"\n")
    k = 1
    while (1):
        test = float(n / (2**k))
        print(str(n)+" / 2^"+str(k)+" = "+str(test))
        if (test != int(test)):
            print("m = "+str(test)+" is not an integer!")
            break
        print("m = "+str(test)+" is an integer, so we continue...")
        k += 1
    k -=  1
    m = n / (2**k)
    return k,int(m)

def step2(n):
    n = int(n)
    print("\nStep 2:")
    a = 2
    if (a <= 1 or a >= (n-1)):
        print("Incorrect a value chosen! Stopping...")
        return 0
    else: 
        return a

def step3(_a, _m, _n, _k):
    print("\nStep 3")
    a = int(_a)
    m = int(_m)
    n = int(_n)
    k = int(_k)
    b0 = (a**m) % n
    print("b0 = "+str(a)+" ^ "+str(m)+" mod "+str(n))
    if (b0 == 1 or b0 == -1):
        return 1
    bi = b0
    counter = 0
    while (counter < k-1):
        print("trying bi = "+str(bi)+" ^ 2 mod "+str(n))
        bi = (bi**2) % n
        print("current bi = "+str(bi))
        if (bi == n - 1):
            bi = -1
        if (bi == 1 or bi == -1):
            break
        counter += 1
    if (bi == -1):
        return 1
    return 0

def main():
    ## parse input
    if (len(sys.argv) != 2):
        sys.exit("INCORRECT INPUT: must be py MillerRabin.py _#_")
    n = sys.argv[1]
    print("Number to test = "+n)

    k,m = step1(n)
    print("\nAfter step 1: k="+str(k)+" m="+str(m))

    a = step2(n)
    if (a == 0):
        sys.exit("ERROR, 'a' value doesnt work!")
    print("Choosing a = "+str(a))

    test = step3(a, m, n, k)
    if (test == 1):
        print("\n\n"+n+" is probably prime!")
    else:
        print("\n\n"+n+" is composite!")


import sys
import BitVector
main()