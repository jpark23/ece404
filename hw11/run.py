import os
import time

start = time.time()
os.system("echo Removing Old Files...")
os.system("rm -r Mail/recipe_1")
os.system("rm -r Mail/recipe_2")
os.system("rm -r Mail/recipe_3")
os.system("rm -r Mail/recipe_4")
os.system("echo OG Filesize = 74")

print("Please wait ~ 2 min")
i = 1
while (i < 75):
    os.system("procmail .procmailrc < junkMail/junkMail_"+str(i))
    i += 1

print("\nFiltered mail by recipe:")
os.system("ls Mail/recipe_1/new/ | wc -l")
os.system("ls Mail/recipe_2/new/ | wc -l")
os.system("ls Mail/recipe_3/new/ | wc -l")
os.system("ls Mail/recipe_4/new/ | wc -l")

end = time.time()
print("Finished in "+str(end-start)+" seconds. Speedy!\n")