if get_option('sphincs_shake_256s').enabled()
	include_sphincs_internal = include_directories([ '../src' ])

	sphincs_tester_c = executable('sphincs_tester_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				dependencies: leancrypto
				)

	test('Sphincs SHAKE 256s C', sphincs_tester_c, suite: regression)
endif
