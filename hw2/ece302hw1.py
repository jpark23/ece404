def dup():
    from random import randint
    denom = 1
    numer = 1
    while (denom < 1000):
        # pick 50 students
        days = []
        while (len(days) != 50):
            days.append(randint(1, 365))
        if (len(days) != len(set(days))):
            numer += 1
        denom += 1
    
    #print("iterations with duplicates: " + str(numer))
    #print("iterations: " + str(denom))
    prob = float(numer) / float(denom)
    #print("probability for bday buddies: " + str(prob))
    return prob    

def main():
    # Generate 50 random numbers from 1 - 365
    # Do this 1000 times, and find out how many 
    #   times out of a 1000 birthday buddies were found
    # Repeat this process 50 times to generate a working probability
    #   ^ of course, the more times we do this, the closer we get to ~.97

    from statistics import mean
    probs = []
    counter = 0
    while counter < 100:
        probs.append(dup())
        counter += 1
    print("Probability of birthday buddies: " + str(mean(probs)))

main()