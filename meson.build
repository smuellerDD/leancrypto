################################################################################
# Version Change Definition
################################################################################
# Major Version: API / ABI incompatible changes, functional changes that require
#		 consumer to be updated (as long as this number is zero, the API
#		 is not considered stable and can change without a bump of the
#		  major version).
# Minor Version: API compatible, ABI may change, functional enhancements only,
#		 consumer can be left unchanged if enhancements are not
#		 considered. Yet, consumer must be recompiled.
# Patchlevel Version: API / ABI compatible, no functional changes, no
#		      enhancements, bug fixes only.
project('leancrypto', 'c',
	version: '0.3.0',
	default_options: [
		'warning_level=3',
		'optimization=s',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pic=true',
		'c_std=gnu18',
	])

################################################################################
# Generic project defines
################################################################################

# Hardening Compiler flags
add_global_arguments([ '-D_FORTIFY_SOURCE=2',
		       '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion',
		       '-Wcast-align',
		       '-Wmissing-field-initializers',
		       '-Wshadow',
		       '-Wswitch-enum' ],
		       language : 'c')

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
add_project_link_arguments('-Wl,--gc-sections', language : 'c')

# Link for full RELRO
add_project_link_arguments('-Wl,-z,relro', language : 'c')
add_project_link_arguments('-Wl,-z,now', language : 'c')

# Only link to truly needed libraries
add_project_link_arguments('-Wl,--as-needed', language : 'c')

################################################################################
# Project-specific defines
################################################################################

include_dirs = include_directories([ 'aead/api',
				     'drng/api',
				     'hash/api',
				     'hmac/api',
				     'kem/api',
				     'kdf/api',
				     'kmac/api',
				     'otp/api',
				     'signature/api',
				     'sym/api'
				   ])

include_files = [ ]

include_internal_dirs = include_directories([ 'internal/api' ])

subdirs = [ 'aead/src',
	    'drng/src',
	    'hash/src',
	    'internal/src',
	    'kdf/src',
	    'kem/src',
	    'otp/src',
	    'signature/src',
	    'sym/src'
	  ]

testdirs = [ 'aead/tests',
	     'drng/tests',
	     'hash/tests',
	     'internal/tests',
	     'kdf/tests',
	     'kem/tests',
	     'otp/tests',
	     'signature/tests',
	     'sym/tests'
	   ]

if get_option('drbg_hmac').enabled() and get_option('sha2-512').disabled()
	error('HMAC DRBG requires SHA2-512')
endif

if get_option('drbg_hash').enabled() and get_option('sha2-512').disabled()
	error('HMAC DRBG requires SHA2-512')
endif

if get_option('hmac').enabled()
	if get_option('sha2-256').disabled() and get_option('sha2-512').disabled()
		error('HMAC requires SHA2-256 or SHA2-512 support')
	endif

	subdirs += 'hmac/src'
	testdirs += 'hmac/tests'
endif

if get_option('hash_crypt').enabled()
	if get_option('drbg_hash').disabled()
		error('Hash Crypt support requires Hash DRBG SHA2-512 support')
	endif
	if get_option('hmac').disabled()
		error('Hash Crypt support requires HMAC support')
	endif
endif

if get_option('kmac').enabled()
	if get_option('sha3').disabled()
		error('KMAC support requires SHA-3 support')
	endif

	subdirs += 'kmac/src'
	testdirs += 'kmac/tests'
endif

if get_option('sha2-256').disabled() and get_option('hotp').enabled()
	error('HOTP support requires SHA2-256')
endif

if get_option('hmac').disabled() and get_option('hotp').enabled()
	error('HOTP support requires HMAC')
endif

if get_option('hotp').disabled() and get_option('totp').enabled()
	error('TOTP support requires HOTP support')
endif

if get_option('chacha20_drng').enabled() and get_option('chacha20').disabled()
	error('ChaCha20 DRNG requires ChaCha20 support')
endif

if get_option('sha3').disabled() and get_option('dilithium').enabled()
	error('Dilithium support requires SHA-3')
endif

if get_option('sha3').disabled() and get_option('kyber').enabled()
	error('Kyber support requires SHA-3')
endif

################################################################################
# Execute compilation
################################################################################

src = [ ]

foreach n : subdirs
    subdir(n)
endforeach

leancrypto_static_lib = static_library('leancrypto_static',
	[ src, internal_src ],
	include_directories: [ include_dirs, include_internal_dirs ],
	)

leancrypto_lib = library('leancrypto',
		     [ src, internal_src ],
		     include_directories: [ include_dirs, include_internal_dirs ],
		     soversion: version_array[0],
		     install: true
		     )
leancrypto = declare_dependency(link_with: leancrypto_lib,
				include_directories: include_dirs)

install_headers(include_files, subdir: 'leancrypto')

################################################################################
# Execute testing
################################################################################

foreach n : testdirs
    subdir(n)
endforeach
