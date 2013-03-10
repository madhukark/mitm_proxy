------------------------------------------------------------------------------

CS255 Project 2 - MiTM Attack


Names
-----
Madhukar Krishnarao
Jack Wu


SUNet IDs
---------
mkrishn1
jackwu


Description of design choices
-----------------------------


Sequence of steps which is required to run the system
-----------------------------------------------------


Short answers
-------------
1.
Suppose an attacker controls the network hardware and can intercept or redirect
messages. Show how such an attacker can control the admin server just as well as
a legitimate admin client elsewhere on the network. Give a complete and specific
description of the changes you would make to fix this vulnerability.


2.
Suppose an attacker is trying to gain unauthorized access to your MITM server
by making its own queries to the admin interface.3 Consider the security of your
implementation against an attacker who (a) can read the admin server’s password
file, but cannot write to it; (b) can read and/or write to the password file between
invocations of the admin server. For each threat model, either show that your imple-
mentation is secure, or give an attack. (N.B.: For full credit, your implementation
should at least be secure under (a).) What, if anything, would you need to change
in order to make it secure under (b)? If your answer requires any additional crypto-
graphic tools, you should fully specify them (including the names of any algorithms,
cryptosystems, and/or modes of operation that you would use.)


3.
How would you change a web browser to make it less likely that an end user would be
fooled by a MITM attack like the one you have implemented? (This is an important
question to ask because when dealing with security, we never just build attacks: we
also need to think of ways to prevent them.)


4.
(optional — worth 0 points) How does your MITM implementation behave on dy-
namic web pages, such as Google Maps? Why is this the case? How could you
modify your proxy to be more convincing in these cases?

