# SimpleBlockchain
Simple, functional blockchain program using proof of work algorithm

Command-line compilation:

> javac -cp "gson-2.8.2.jar" Blockchain.java

Running program:

In separate shell windows:

> java -cp ".;gson-2.8.2.jar" Blockchain X

Where X is the process number (0,1,2)

All acceptable commands are displayed on the various consoles.
R XXXXX - Reads in data from a file at the root directory called XXXXX
C - Prints out the number of blocks each process has verified. If a process did not contribute to any verifications, it is not displayed
L - Prints out the entire blockchain line by line (Block num, time created, data)

Defaultly runs on localhost only, so processes must be on the same machine

Files needed to run:

 a. Blockchain.java 
 
 b. BlockInput0.txt (Only one txt file is needed to run and test everything, but multiple can be used)
 
 c. BlockInput1.txt (Only one txt file is needed to run and test everything, but multiple can be used)
 
 d. BlockInput2.txt (Only one txt file is needed to run and test everything, but multiple can be used)
