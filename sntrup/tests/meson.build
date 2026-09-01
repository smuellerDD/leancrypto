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
