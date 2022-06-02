if get_option('hkdf').enabled()
	hkdf_tester = executable('hkdf_tester',
				 [ 'hkdf_tester.c', internal_src ],
				 include_directories: [ include_internal_dirs ],
				 dependencies: leancrypto
				)
	test('HKDF', hkdf_tester)
endif

if get_option('kdf_ctr').enabled()
	kdf_ctr_tester = executable('kdf_ctr_tester',
				    [ 'kdf_ctr_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('KDF Counter', kdf_ctr_tester)
endif

if get_option('kdf_fb').enabled()
	kdf_fb_tester = executable('kdf_fb_tester',
				   [ 'kdf_fb_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				  )
	test('KDF Feedback', kdf_fb_tester)
endif

if get_option('kdf_dpi').enabled()
	kdf_dpi_tester = executable('kdf_dpi_tester',
				    [ 'kdf_dpi_tester.c', internal_src ],
				    include_directories: [ include_internal_dirs ],
				    dependencies: leancrypto
				   )
	test('KDF Double Pipeline', kdf_dpi_tester)
endif

if get_option('pbkdf2').enabled()
	pbkdf2_tester = executable('pbkdf2_tester',
				   [ 'pbkdf2_tester.c', internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	test('PBKDF2', pbkdf2_tester)
endif
