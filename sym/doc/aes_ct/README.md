Well, if someone want to understand the math in this PR, it might be helpful if
I disclose some intermediate steps I took to design this constant time algorithm.
I started from the NIST document where the AES algorithm is defined, added
the test vectors from that document and implemented a straight forward constant
time AES, and then I transformed the algorithm towards this end result.
aes.c:
