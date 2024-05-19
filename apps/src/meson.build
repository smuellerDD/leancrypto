# Apps use POSIX API that is not available on regular Windows
if (host_machine.system() != 'windows') and get_option('apps').enabled()

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
		ascon128_sum_files = shasum_files_common
		ascon128_sum_files += files([ 'ascon128-sum.c' ])

		ascon128_sum = executable('ascon128-sum',
				[ ascon128_sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)

		ascon128a_sum_files = shasum_files_common
		ascon128a_sum_files += files([ 'ascon128a-sum.c' ])
		ascon128a_sum = executable('ascon128a-sum',
				[ ascon128a_sum_files ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto,
				install: true,
				install_dir: get_option('libexecdir') / meson.project_name()
				)
	endif

endif

