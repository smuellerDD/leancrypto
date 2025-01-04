pkcs7_trust_tester = executable('pkcs7_trust_tester',
	[ 'pkcs7_trust_tester.c' ],
	  include_directories: [ include_internal_dirs ],
				 dependencies: leancrypto,
	  link_with: leancrypto_static_lib,
	  pie: false,
	)

objcopy = find_program('objcopy', required: true)
pkcs7_trust_tester_efi = custom_target(
	'pkcs7_trust_tester.efi',
	depends: pkcs7_trust_tester,
	input: pkcs7_trust_tester,
	output: '@BASENAME@.efi',
	command: [
		objcopy,
		'-j', '.text',
		'-j', '.sdata',
		'-j', '.data',
		'-j', '.rodata',
		'-j', '.dynamic',
		'-j', '.dynsym',
		'-j', '.rel',
		'-j', '.rela',
		'-j', '.rel.*',
		'-j', '.rela.*',
		'-j', '.reloc',
		'--target', 'efi-app-x86_64',
		'--subsystem=10',
		'@INPUT@',
		'@OUTPUT@'
		],
	)
