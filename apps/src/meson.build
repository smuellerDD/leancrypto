# Apps use POSIX API that is not available on regular Windows
if (host_machine.system() != 'windows' and
    get_option('efi').disabled() and
    get_option('apps').enabled())
	shasum_files_common = files([ 'hasher_app.c' ])
	shasum_files_common += internal_src

	if get_option('sha2-512').enabled()
		sha512sum_files = shasum_files_common
		sha512sum_files += files([ 'sha512sum.c' ])

		sha512sum = executable('sha512sum',
				[ sha512sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sha384sum_files = shasum_files_common
		sha384sum_files += files([ 'sha384sum.c' ])

		sha384sum = executable('sha384sum',
				[ sha384sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

	if get_option('sha2-256').enabled()
		sha256sum_files = shasum_files_common
		sha256sum_files += files([ 'sha256sum.c' ])

		sha256sum = executable('sha256sum',
				[ sha256sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

	if get_option('sha3').enabled()
		sha3_256sum_files = shasum_files_common
		sha3_256sum_files += files([ 'sha3-256sum.c' ])

		sha3_256sum = executable('sha3-256sum',
				[ sha3_256sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sha3_384sum_files = shasum_files_common
		sha3_384sum_files += files([ 'sha3-384sum.c' ])

		sha3_384sum = executable('sha3-384sum',
				[ sha3_384sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sha3_512sum_files = shasum_files_common
		sha3_512sum_files += files([ 'sha3-512sum.c' ])

		sha3_512sum = executable('sha3-512sum',
				[ sha3_512sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

	if get_option('ascon').enabled()
		ascon256_sum_files = shasum_files_common
		ascon256_sum_files += files([ 'ascon256-sum.c' ])

		ascon256_sum = executable('ascon256-sum',
				[ ascon256_sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

	if get_option('x509_generator').enabled()
		lc_x509_generator_files = internal_src
		lc_x509_generator_files += files([
						'lc_x509_generator.c',
						'lc_x509_generator_checker.c',
						'lc_x509_generator_file_helper.c',
						'lc_x509_generator_print.c',
						])

		lc_x509_generator = executable('lc_x509_generator',
				[ lc_x509_generator_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				)
	endif

	if get_option('pkcs7_generator').enabled()
		lc_pkcs7_generator_files = internal_src
		lc_pkcs7_generator_files += files([
			'lc_pkcs7_generator.c',
			'lc_pkcs7_generator_helper.c',
			'lc_x509_generator_checker.c',
			'lc_x509_generator_file_helper.c',
			'lc_x509_generator_print.c',
			])

		lc_pkcs7_generator = executable('lc_pkcs7_generator',
				[ lc_pkcs7_generator_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				)
	endif

	if get_option('sbsigntools').enabled()
		sbsign_files = internal_src
		sbsign_files += files([
			'authenticode_SpcIndirectDataContent_asn1.c',
			'authenticode_SpcPeImageData_asn1.c',
			'image.c',
			'lc_pkcs7_generator_helper.c',
			'lc_x509_generator_checker.c',
			'lc_x509_generator_file_helper.c',
			'lc_x509_generator_print.c',
			'sbsign.c',
		])

		sbsign = executable('sbsign',
				[ sbsign_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sbverify_files = internal_src
		sbverify_files += files([
			'authenticode_SpcIndirectDataContent_asn1.c',
			'image.c',
			'lc_pkcs7_generator_helper.c',
			'lc_x509_generator_checker.c',
			'lc_x509_generator_file_helper.c',
			'lc_x509_generator_print.c',
			'sbverify.c',
		])

		sbverify = executable('sbverify',
				[ sbverify_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sbvarsign_files = internal_src
		sbvarsign_files += files([
			'lc_pkcs7_generator_helper.c',
			'lc_x509_generator_print.c',
			'lc_x509_generator_file_helper.c',
			'sbvarsign.c',
		])

		sbvarsign = executable('sbvarsign',
				[ sbvarsign_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sbsiglist_files = internal_src
		sbsiglist_files += files([
			'lc_x509_generator_file_helper.c',
			'sbsiglist.c',
		])

		sbsiglist = executable('sbsiglist',
				[ sbsiglist_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sbkeysync_files = internal_src
		sbkeysync_files += files([
			'lc_x509_generator_file_helper.c',
			'sbkeysync.c',
		])

		sbkeysync = executable('sbkeysync',
				[ sbkeysync_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		sbattach_files = internal_src
		sbattach_files += files([
			'image.c',
			'lc_pkcs7_generator_helper.c',
			'lc_x509_generator_file_helper.c',
			'lc_x509_generator_print.c',
			'sbattach.c',
		])

		sbattach = executable('sbattach',
				[ sbattach_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

endif

