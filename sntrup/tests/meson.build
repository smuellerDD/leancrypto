# The CTR DRBG provides the testing DRBG as required for the test vectors
# Static linking necessary as access to the lc_sntrup_*_kem_enc_internal
# symbols needed
if get_option('drbg_ctr').enabled()

	if get_option('sntrup_1277').enabled()
		sntrup_1277_tester = executable(
			'sntrup_1277_tester',
			['sntrup_1277_tester.c', internal_src],
			include_directories : [
				include_dirs,
				include_internal_dirs
			],
			dependencies : leancrypto_static_lib)
		test('SNTRUP 1277', sntrup_1277_tester, suite : regression)
	endif

	if get_option('sntrup_1013').enabled()
		sntrup_1013_tester = executable(
			'sntrup_1013_tester',
			['sntrup_1013_tester.c', internal_src],
			include_directories : [
				include_dirs,
				include_internal_dirs
			],
			dependencies : leancrypto_static_lib)
		test('SNTRUP 1013', sntrup_1013_tester, suite : regression)
	endif

	if get_option('sntrup_953').enabled()
		sntrup_953_tester = executable(
			'sntrup_953_tester',
			['sntrup_953_tester.c', internal_src],
			include_directories : [
				include_dirs,
				include_internal_dirs
			],
			dependencies : leancrypto_static_lib)
		test('SNTRUP 953', sntrup_953_tester, suite : regression)
	endif

	if get_option('sntrup_857').enabled()
		sntrup_857_tester = executable(
			'sntrup_857_tester',
			['sntrup_857_tester.c', internal_src],
			include_directories : [
				include_dirs,
				include_internal_dirs
			],
			dependencies : leancrypto_static_lib)
		test('SNTRUP 857', sntrup_857_tester, suite : regression)
	endif

	if get_option('sntrup_761').enabled()
		sntrup_761_tester = executable(
			'sntrup_761_tester',
			['sntrup_761_tester.c', internal_src],
			include_directories : [
				include_dirs,
				include_internal_dirs
			],
			dependencies : leancrypto_static_lib)
		test('SNTRUP 761', sntrup_761_tester, suite : regression)

	endif
endif

sntrup_tester_perf = executable('sntrup_tester_perf',
			[ 'sntrup_tester_perf.c', internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			], dependencies: leancrypto
			)

if get_option('sntrup_1277').enabled()
	test('SNTRUP 1277 KEM 10000 Common', sntrup_tester_perf,
	     args : [ '1' ], timeout: 2000,
	     is_parallel: false, suite: performance)
	test('SNTRUP 1277 KEM 10000 C', sntrup_tester_perf, args : [ '1', 'c' ],
	     timeout: 2000, is_parallel: false, suite: performance)
endif

if get_option('sntrup_1013').enabled()
	test('SNTRUP 1013 KEM 10000 Common', sntrup_tester_perf,
	     args : [ '2' ], timeout: 2000,
	     is_parallel: false, suite: performance)
	test('SNTRUP 1013 KEM 10000 C', sntrup_tester_perf, args : [ '2', 'c' ],
	     timeout: 2000, is_parallel: false, suite: performance)
endif

if get_option('sntrup_953').enabled()
	test('SNTRUP 953 KEM 10000 Common', sntrup_tester_perf,
	args : [ '3' ], timeout: 2000,
	is_parallel: false, suite: performance)
	test('SNTRUP 953 KEM 10000 C', sntrup_tester_perf, args : [ '3', 'c' ],
	timeout: 2000, is_parallel: false, suite: performance)
endif

if get_option('sntrup_857').enabled()
	test('SNTRUP 857 KEM 10000 Common', sntrup_tester_perf,
	args : [ '4' ], timeout: 2000,
	is_parallel: false, suite: performance)
	test('SNTRUP 857 KEM 10000 C', sntrup_tester_perf, args : [ '4', 'c' ],
	timeout: 2000, is_parallel: false, suite: performance)
endif

if get_option('sntrup_761').enabled()
	test('SNTRUP 761 KEM 10000 Common', sntrup_tester_perf,
	args : [ '5' ], timeout: 2000,
	is_parallel: false, suite: performance)
	test('SNTRUP 761 KEM 10000 C', sntrup_tester_perf, args : [ '5', 'c' ],
	timeout: 2000, is_parallel: false, suite: performance)
endif
