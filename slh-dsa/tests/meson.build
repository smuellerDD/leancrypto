if get_option('sphincs_shake_256s').enabled()
	include_sphincs_internal = include_directories([ '../src' ])

	sphincs_tester_256s_c = executable('sphincs_tester_256s_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				dependencies: leancrypto
				)
	sphincs_tester_256f_c = executable('sphincs_tester_256f_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_256F',
				dependencies: leancrypto
				)

	test('Sphincs SHAKE 256s C', sphincs_tester_256s_c, suite: regression)
	test('Sphincs SHAKE 256f C', sphincs_tester_256f_c, suite: regression)
endif
