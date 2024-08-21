# COMP6016
Password Cracker using Dictionary Attack

To use this password cracker, the user will need the following:
1) A word list (e.g. rockyou.txt)
2) A hashed password list - It is a list containing passwords that has been hashed using a certain type of algorithm (e.g. SHA256 / MD5). A raw password list containing direct strings or characters of the passwords will not work.

This password cracker program has been equipped with multiple additional features aside from its primary function. Its features includes:
1) A Timer - Keeps track of the time elapsed for the password cracking to complete.
2) A Random Password Generator - Generates a random password consisting of all kinds of combinations (uppercase, lowercase, numbers, symbols) according to length input by user. 
3) A Hash Converter - Hashes the string or characters into by user into hashed format using either SHA256 or MD5 algorithm
4) Threads - User decides the number of threads or cores to be used according to physical system capabilities.
5) Result Output - Upon completion of password cracking, outputs the successfully cracked password along with hashes to user. 
6) File Export - Upon completion of password cracking, generates a .txt file containing the passwords along with their respective hashes.
7) Output Display - Upon completion of password cracking, displays the first 100 passwords "attempted".

Use Case - Password Cracker
1) Select word list and hashed list to be used
2) Select number of threads to be used (this is optional, if left empty the program will use the default amount according to system capability)
3) Click on "Start Cracking".
4) Outputs generated, .txt file generated and exported, timer elapsed generated and first 100 attempted words generated in new tab.

Use Case - Random Password Generator
1) Input length of password.
2) Click on "Generate Password".
3) Random password generated.

Use Case - Hash Generator
1) Input string password
2) Select algorithm to be used (SHA256 / MD5)
3) Click on "Generate Hash"
4) Hash generated

