#!/usr/bin/env python3

import leancrypto

def main():
	status = bytearray(500)
	leancrypto.lc_status(status, len(status))
	print(str(status.decode('utf-8')))

if __name__ == "__main__":
	main()
