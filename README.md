Dictionary Attack program done for a information security project.

The program takes an argument of prehashed MD5, SHA-1, or SHA-256 passwords. It will then ask the user if he/she wants to do an extensive check which will give the user more detailed information about how long strong passwords will take to crack compared to weak passwords. In addition, the user has the ability to combine passwords which make for a better detailed report when the program is done running. This can take up to 20 minutes. 

The passwords were hashed using http://www.sha1-online.com/ which provide hashes for many algorithms. 

How does the dictionary attack program work?

The program will have a file of 10,000 commonly used passwords which will be hashed during run-time and compared to the prehashed password file using one of the hashing algorithms. When the user decides not to do an extensive check the 80 prehashed MD5 passwords will fail to be 100% cracked but when the user decides it will do an extensive check all 80 prehashed MD5 passwords will be cracked. 
