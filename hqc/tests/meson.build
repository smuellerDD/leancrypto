include_hqc_internal = include_directories([ '../src' ])

hqc_tests_generic = false

if get_option('hqc_256').enabled()
	hqc_tests_generic = true

	hqc_256_tester = executable('hqc_256_tester',
				[ 'hqc_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib
				)
	hqc_256_tester_perf = executable('hqc_256_tester_perf',
				[ 'hqc_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib
				)

	test('HQC 256 KEM Common', hqc_256_tester, suite: regression,
	     timeout: 300)
	# Prevent parallel execution, as test disables acceleration
	test('HQC 256 KEM C', hqc_256_tester, args : [ 'c' ], suite: regression,
	     is_parallel: false, timeout: 300)

	test('HQC 256 KEM 1000 Common', hqc_256_tester_perf, timeout: 2000,
	     is_parallel: false, suite: performance)
	test('HQC 256 KEM 1000 C', hqc_256_tester_perf, args : [ 'c' ], timeout: 2000,
	     is_parallel: false, suite: performance)
endif

if get_option('hqc_192').enabled()
	hqc_tests_generic = true

	hqc_192_tester = executable('hqc_192_tester',
				[ 'hqc_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_HQC_TYPE_192'
				)
	hqc_192_tester_perf = executable('hqc_192_tester_perf',
				[ 'hqc_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_HQC_TYPE_192'
				)

	test('HQC 192 KEM Common', hqc_192_tester, suite: regression)
	test('HQC 192 KEM C', hqc_192_tester, args : [ 'c' ], suite: regression,
	     is_parallel: false, timeout: 300)

	test('HQC 192 KEM 1000 Common', hqc_192_tester_perf, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('HQC 192 KEM 1000 C', hqc_192_tester_perf, args : [ 'c' ], timeout: 1000,
	     is_parallel: false, suite: performance)
endif

if get_option('hqc_128').enabled()
	hqc_tests_generic = true

	hqc_128_tester = executable('hqc_128_tester',
				[ 'hqc_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_HQC_TYPE_128'
				)
	hqc_128_tester_perf = executable('hqc_128_tester_perf',
				[ 'hqc_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_HQC_TYPE_128'
				)

	test('HQC 128 KEM Common', hqc_128_tester, suite: regression)
	test('HQC 128 KEM C', hqc_128_tester, args : [ 'c' ], suite: regression,
	     is_parallel: false, timeout: 300)

	test('HQC 128 KEM 1000 Common', hqc_128_tester_perf, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('HQC 128 KEM 1000 C', hqc_128_tester_perf, args : [ 'c' ], timeout: 1000,
	     is_parallel: false, suite: performance)
endif

if hqc_tests_generic
	hqc_kem_official_tester = executable('hqc_kem_official_tester',
				[ 'hqc_kem_official_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_hqc_internal
				], link_with: leancrypto_lib
				)
	test('HQC official API KEM', hqc_kem_official_tester,
	     suite: regression)
endif
