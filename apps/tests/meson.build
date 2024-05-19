hasher_test_script = find_program('hasher-test.sh', required: true)

# Apps use POSIX API that is not available on regular Windows
if (host_machine.system() != 'windows') and get_option('apps').enabled()
	if get_option('sha2-256').enabled()
		test('sha256sum', hasher_test_script,
		     args: [ sha256sum.full_path(), '/usr/bin/sha256sum' ])
	endif

	if get_option('sha2-512').enabled()
		test('sha512sum', hasher_test_script,
		     args: [ sha512sum.full_path(), '/usr/bin/sha512sum' ])
	endif

	if get_option('sha3').enabled()
		test('sha3-256sum', hasher_test_script,
		     args: [ sha3_256sum.full_path(), '/usr/bin/sha3-256sum' ])
		test('sha3-384sum', hasher_test_script,
		     args: [ sha3_384sum.full_path(), '/usr/bin/sha3-384sum' ])
		test('sha3-512sum', hasher_test_script,
		     args: [ sha3_512sum.full_path(), '/usr/bin/sha3-512sum' ])
	endif

endif
