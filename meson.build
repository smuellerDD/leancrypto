################################################################################
# Version Change Definition
################################################################################
# Major Version: API / ABI incompatible changes, functional changes that require
#		 consumer to be updated (as long as this number is zero, the API
#		 is not considered stable and can change without a bump of the
#		 major version).
# Minor Version: API compatible, ABI may change, functional enhancements only,
#		 consumer can be left unchanged if enhancements are not
#		 considered. Yet, consumer must be recompiled.
# Patchlevel Version: API / ABI compatible, no functional changes, no
#		      enhancements, bug fixes only.
project('leancrypto', 'c',
	version: '1.6.1',
	default_options: [
		'warning_level=3',
		'optimization=3',
		'strip=true',
		#LTO is enabled below
		#'b_lto=true',
		'b_staticpic=true',
		'b_pie=true',
		'b_asneeded=true'
	])

################################################################################
# Generic project defines
################################################################################

cc = meson.get_compiler('c')

# Hardening Compiler flags
add_global_arguments([ '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion',
		       '-Wcast-align',
		       '-Wmissing-field-initializers',
		       '-Wshadow',
		       '-Wswitch-enum',
		       '-Wmissing-prototypes',
		       '-Wformat=2',
		       '-fno-delete-null-pointer-checks',
		       '-fno-strict-aliasing',
		       '-Wundef',
		       '-Wvla',
		       '-Wunused-function',
		       '-Wunused-parameter',
		       '-Wunreachable-code'
		        ],
		       language : 'c')

if cc.has_argument('-Wdocumentation')
	add_global_arguments([ '-Wdocumentation' ],
			     language: 'c')
endif

# More hardening
if cc.has_argument('-fzero-call-used-regs=used-gpr')
	add_global_arguments([ '-fzero-call-used-regs=used-gpr' ],
			     language: 'c')
endif
if cc.has_argument('-ftrivial-auto-var-init=zero')
	add_global_arguments([ '-ftrivial-auto-var-init=zero' ],
			     language: 'c')
endif
if cc.has_argument('-Wshorten-64-to-32')
	add_global_arguments([ '-Wshorten-64-to-32' ],
			     language: 'c')
endif

# x86_64 hardening
if cc.has_argument('-fcf-protection=full')
	add_global_arguments([ '-fcf-protection=full' ],
			     language: 'c')
endif

# ARM64 hardening
if cc.has_argument('-mbranch-protection=standard')
	add_global_arguments([ '-mbranch-protection=standard' ], language: 'c')
endif

# MINGW64 cannot handle lto properly at the moment
if (cc.has_argument('-flto') and
    host_machine.system() != 'windows' and
    get_option('efi').disabled())
	add_global_arguments([ '-flto=auto' ], language: 'c')
	add_project_link_arguments('-flto=auto', language : 'c')
endif

if (cc.has_argument('-ffat-lto-objects') and
    host_machine.system() != 'windows' and
    host_machine.system() != 'darwin' and
    get_option('efi').disabled())
	add_global_arguments([ '-ffat-lto-objects' ], language: 'c')
endif

if get_option('optimization') == '0'
	add_global_arguments([ '-DDEBUG' ], language: 'c')
elif get_option('efi').disabled()
	add_global_arguments([ '-U_FORTIFY_SOURCE' ], language: 'c')
	add_global_arguments([ '-D_FORTIFY_SOURCE=3' ], language: 'c')
endif

if get_option('enable_selftests').enabled()
	add_global_arguments([ '-DLC_SELFTEST_ENABLED' ], language: 'c')
endif

if get_option('small_stack').enabled()
        add_global_arguments([ '-Wframe-larger-than=2048',
			       '-DLC_MEM_ON_HEAP' ],
			     language: 'c')
else
        add_global_arguments([ '-Wframe-larger-than=1048576' ], language: 'c')
endif

if get_option('debug')
	add_global_arguments([ '-DLC_DEBUG' ], language: 'c')
endif
if get_option('dilithium_debug').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_DEBUG' ], language: 'c')
endif
if get_option('kyber_debug').enabled()
	add_global_arguments([ '-DLC_KYBER_DEBUG' ], language: 'c')
endif

if get_option('sha2-256').enabled()
	add_global_arguments([ '-DLC_SHA2_256' ], language: 'c')
endif

if get_option('sha2-512').enabled()
	add_global_arguments([ '-DLC_SHA2_512' ], language: 'c')
endif
if get_option('hmac').enabled()
	add_global_arguments([ '-DLC_HMAC' ], language: 'c')
endif

fips_integrity_test_capable=true
if get_option('sha3').enabled()
	add_global_arguments([ '-DLC_SHA3' ], language: 'c')
else
	fips_integrity_test_capable=false
	message('FIPS 140 integrity checker disabled due to missing SHA-3 support')
endif

if get_option('kmac').enabled()
	add_global_arguments([ '-DLC_KMAC' ], language: 'c')
endif

if get_option('ascon').enabled()
	add_global_arguments([ '-DLC_ASCON_HASH' ], language: 'c')
endif
if get_option('ascon_keccak').enabled()
	add_global_arguments([ '-DLC_ASCON_KECCAK' ], language: 'c')
endif

if get_option('chacha20').enabled()
	add_global_arguments([ '-DLC_CHACHA20' ], language: 'c')
endif
if get_option('chacha20poly1305').enabled()
	add_global_arguments([ '-DLC_CHACHA20_POLY1305' ], language: 'c')
endif

kyber_enabled = false
if (get_option('kyber_1024').enabled() or
    get_option('kyber_768').enabled() or
    get_option('kyber_512').enabled())
	add_global_arguments([ '-DLC_KYBER' ], language: 'c')
	kyber_enabled = true
endif

hqc_enabled = false
if (get_option('hqc_256').enabled() or
    get_option('hqc_192').enabled() or
    get_option('hqc_128').enabled())
	add_global_arguments([ '-DLC_HQC' ], language: 'c')
	hqc_enabled = true
endif

dilithium_enabled = false
if (get_option('dilithium_87').enabled() or
    get_option('dilithium_65').enabled() or
    get_option('dilithium_44').enabled())
	add_global_arguments([ '-DLC_DILITHIUM' ], language: 'c')
	dilithium_enabled = true
endif

if get_option('dilithium_87').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_87_OPT_ENABLED' ], language: 'c')
endif
if get_option('dilithium_65').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_65_OPT_ENABLED' ], language: 'c')
endif
if get_option('dilithium_44').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_44_OPT_ENABLED' ], language: 'c')
endif

sphincs_enabled = false
if (get_option('sphincs_shake_256s').enabled() or
    get_option('sphincs_shake_256f').enabled() or
    get_option('sphincs_shake_192s').enabled() or
    get_option('sphincs_shake_192f').enabled() or
    get_option('sphincs_shake_128s').enabled() or
    get_option('sphincs_shake_128f').enabled() or
    get_option('slh_dsa_ascon_128s').enabled() or
    get_option('slh_dsa_ascon_128f').enabled())
	add_global_arguments([ '-DLC_SPHINCS' ], language: 'c')
	sphincs_enabled = true
endif

if get_option('sphincs_shake_256s').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_256S_OPT_ENABLED' ], language: 'c')
endif
if get_option('sphincs_shake_256f').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_256F_OPT_ENABLED' ], language: 'c')
endif
if get_option('sphincs_shake_192s').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_192S_OPT_ENABLED' ], language: 'c')
endif
if get_option('sphincs_shake_192f').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_192F_OPT_ENABLED' ], language: 'c')
endif
if get_option('sphincs_shake_128s').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_128S_OPT_ENABLED' ], language: 'c')
endif
if get_option('sphincs_shake_128f').enabled()
	add_global_arguments([ '-DLC_SPHINCS_SHAKE_128F_OPT_ENABLED' ], language: 'c')
endif

if get_option('kyber_x25519').enabled()
	add_global_arguments([ '-DLC_CURVE25519' ], language: 'c')
endif

if get_option('dilithium_ed25519').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_ED25519' ], language: 'c')
endif

if get_option('kyber_x448').enabled()
	add_global_arguments([ '-DLC_CURVE448' ], language: 'c')
endif

if get_option('dilithium_ed448').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_ED448' ], language: 'c')
endif

if (get_option('bike_5').enabled() or
    get_option('bike_3').enabled() or
    get_option('bike_1').enabled())
	add_global_arguments([ '-DLC_BIKE' ], language: 'c')
endif

if (get_option('hqc_256').enabled() or
    get_option('hqc_192').enabled() or
    get_option('hqc_128').enabled())
	add_global_arguments([ '-DLC_HQC' ], language: 'c')
endif

if get_option('efi').enabled()
	add_global_arguments([ '-DLC_EFI' ], language: 'c')
endif

if (get_option('aes_cbc').enabled() or
    get_option('aes_ctr').enabled() or
    get_option('aes_kw').enabled() or
    get_option('aes_xts').enabled() or
    get_option('aes_gcm').enabled())
	add_global_arguments([ '-DLC_AES' ], language: 'c')
endif

if get_option('aes_cbc').enabled()
	add_global_arguments([ '-DLC_AES_CBC' ], language: 'c')
endif
if get_option('aes_ctr').enabled()
	add_global_arguments([ '-DLC_AES_CTR' ], language: 'c')
endif
if get_option('aes_kw').enabled()
	add_global_arguments([ '-DLC_AES_KW' ], language: 'c')
endif
if get_option('aes_xts').enabled()
	add_global_arguments([ '-DLC_AES_XTS' ], language: 'c')
endif
if get_option('aes_gcm').enabled()
	add_global_arguments([ '-DLC_AES_GCM' ], language: 'c')
endif

if get_option('chacha20_drng').enabled()
	add_global_arguments([ '-DLC_DRNG_CC20' ], language: 'c')
endif
if get_option('kmac_drng').enabled()
	add_global_arguments([ '-DLC_DRNG_KMAC' ], language: 'c')
endif
if get_option('cshake_drng').enabled()
	add_global_arguments([ '-DLC_DRNG_CSHAKE' ], language: 'c')
endif
if (get_option('xdrbg').enabled() and get_option('ascon').enabled())
	add_global_arguments([ '-DLC_DRNG_XDRBG128' ], language: 'c')
endif
if (get_option('xdrbg').enabled() and get_option('sha3').enabled())
	add_global_arguments([ '-DLC_DRNG_XDRBG256' ], language: 'c')
	add_global_arguments([ '-DLC_DRNG_XDRBG512' ], language: 'c')
endif
if get_option('drbg_hash').enabled()
	add_global_arguments([ '-DLC_DRNG_HASH_DRBG' ], language: 'c')
endif
if get_option('drbg_hmac').enabled()
	add_global_arguments([ '-DLC_DRNG_HMAC_DRBG' ], language: 'c')
endif
if get_option('hkdf').enabled()
	add_global_arguments([ '-DLC_HKDF' ], language: 'c')
endif
if get_option('kdf_ctr').enabled()
	add_global_arguments([ '-DLC_KDF_CTR' ], language: 'c')
endif
if get_option('kdf_fb').enabled()
	add_global_arguments([ '-DLC_KDF_FB' ], language: 'c')
endif
if get_option('kdf_dpi').enabled()
	add_global_arguments([ '-DLC_KDF_DPI' ], language: 'c')
endif
if get_option('pbkdf2').enabled()
	add_global_arguments([ '-DLC_DRNG_PBKDF2' ], language: 'c')
endif

# Determine if AEAD support is enabled
aead_support_enabled = false
if (get_option('hash_crypt').enabled() or
    get_option('ascon').enabled() or
    get_option('ascon_keccak').enabled() or
    get_option('chacha20poly1305').enabled() or
    ((get_option('aes_cbc').enabled() or get_option('aes_ctr').enabled()) and
     (get_option('sha2-512').enabled() or get_option('kmac').enabled())))
	add_global_arguments([ '-DLC_AEAD' ], language: 'c')
	aead_support_enabled = true
endif

if get_option('hash_crypt').enabled()
	add_global_arguments([ '-DLC_HASH_CRYPT' ], language: 'c')
endif

if get_option('x509_generator').enabled()
	add_global_arguments([ '-DLC_X509_GENERATOR' ], language: 'c')
endif

# Determine support for secure exeuction
secure_execution_linux = false
if (host_machine.system() == 'linux' and
    get_option('secure_execution').enabled())
	add_global_arguments([ '-DLC_SECEXEC_LINUX' ], language: 'c')
	secure_execution_linux = true
endif

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
if (host_machine.system() == 'darwin')
	add_project_link_arguments('-Wl,-dead_strip', language : 'c')
else
	add_project_link_arguments('-Wl,--gc-sections', language : 'c')
endif

# Link for full RELRO
if (host_machine.system() == 'linux' and not get_option('efi').enabled())
	add_project_link_arguments('-Wl,-z,relro', language : 'c')
	add_project_link_arguments('-Wl,-z,now', language : 'c')
endif

if (host_machine.system() == 'linux')
	add_project_link_arguments('-Wl,-z,noexecstack', language : 'c')
endif

# Check for the endianess of the target
if (host_machine.endian() == 'big')
	add_global_arguments([ '-DLC_BIG_ENDIAN' ], language: 'c')
else
	add_global_arguments([ '-DLC_LITTLE_ENDIAN' ], language: 'c')
endif

# Debugging options
if get_option('timecop').enabled()
	add_global_arguments([ '-DLC_USE_TIMECOP' ], language: 'c')
endif

if get_option('pkcs7_debug').enabled()
	add_global_arguments([ '-DLC_PKCS7_DEBUG' ], language: 'c')
endif

# Whether to build the shared library alongside the static library
build_shared = (get_option('default_library') != 'static' and
		get_option('efi').disabled())
if (not build_shared)
	add_global_arguments([ '-DLC_STATIC' ], language: 'c')
endif

# Decide whether we are building for the FIPS integrity testing.
fips_integrity_test_enabled = false
if (build_shared and
    fips_integrity_test_capable and
    host_machine.system() == 'linux' and
    get_option('efi').disabled())
	fips_integrity_test_enabled = true
	add_global_arguments([ '-DLC_FIPS140_INTEGRITY_CHECKER' ], language: 'c')
endif

# 64 bit time to not suffer from Y2038 problem
add_global_arguments([ '-D_TIME_BITS=64' ], language: 'c')

fips140_negative_expect_fail = false
if get_option('fips140_negative').enabled()
	add_global_arguments([ '-DLC_FIPS140_DEBUG' ], language: 'c')
	fips140_negative_expect_fail = true
endif

# Header generation
header_script = find_program('addon/generate_header.sh', required: true)

# FIPS Header generation
fips_integrity_checker_script = find_program(
	'addon/fips_integrity_checker_elf_generator.sh', required: true)

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

# Find Doxygen program
doxygen = find_program('doxygen', required : false)

################################################################################
# EFI-specific defines
################################################################################

if get_option('efi').enabled()
	fs = import('fs')

	efi_crt0_file = '/usr/lib/crt0-efi-' + host_machine.cpu_family() + '.o'
	if (not fs.is_file(efi_crt0_file))
		efi_crt0_file = '/usr/lib64/crt0-efi-' + host_machine.cpu_family() + '.o'
	endif

	efi_lds_file = '/usr/lib/elf_' + host_machine.cpu_family() + '_efi.lds'
	if (not fs.is_file(efi_lds_file))
		efi_lds_file = '/usr/lib64/elf_' + host_machine.cpu_family() + '_efi.lds'
	endif

	# https://wiki.osdev.org/GNU-EFI
	add_global_arguments([
		'-fno-stack-protector',
		'-fno-stack-check',
		'-ffreestanding',
		'-fshort-wchar',
		'-DLC_EFI_ENVIRONMENT',
		],
		language: 'c')
	add_project_link_arguments([
		'-shared',
		'-Wl,-Bsymbolic',
		'-T' + efi_lds_file,
		efi_crt0_file,
		],
		language : 'c')

	if host_machine.cpu_family() == 'x86_64'
		add_global_arguments([
			'-mno-red-zone',
			],
			language: 'c')
	endif

	if cc.has_argument('-maccumulate-outgoing-args')
		add_global_arguments([ '-maccumulate-outgoing-args' ],
				       language: 'c')
	endif
endif

################################################################################
# Project-specific defines
################################################################################

pkgconfig = import('pkgconfig')

include_dirs = include_directories([ 'aead/api',
				     'apps/api',
				     'asn1/src',
				     'bike/api',
				     'curve25519/api',
				     'curve448/api',
				     'drng/api',
				     'drng/src',
				     'hash/api',
				     'hmac/api',
				     'hqc/api',
				     'ml-kem/api',
				     'ml-kem/src', # For "common/" directory
				     'kdf/api',
				     'kmac/api',
				     'otp/api',
				     'ml-dsa/api',
				     'slh-dsa/api',
				     'sym/api',
				     'asn1/api'
				   ])

include_files = [ ]

include_internal_dirs = include_directories([ 'internal/api' ])

subdirs = [
	    # These must be first to generate the header files
	    'internal/api',
	    'hash/api',

	    'aead/src',
	    'bike/api',
	    'bike/src',
	    'curve25519/src',
	    'curve448/src',
	    'drng/src',
	    'hash/src',
	    'hqc/api',
	    'hqc/src',
	    'internal/src',
	    'kdf/src',
	    'ml-kem/api',
	    'ml-kem/src',
	    'otp/src',
	    'ml-dsa/api',
	    'ml-dsa/src',
	    'slh-dsa/api',
	    'slh-dsa/src',
	    'sym/src',
	    'asn1/src',
	    'efi/src'
	  ]

testdirs = [ 'apps/tests',
	     'aead/tests',
	     'bike/tests',
	     'curve25519/tests',
	     'curve448/tests',
	     'drng/tests',
	     'hash/tests',
	     'hqc/tests',
	     'internal/tests',
	     'kdf/tests',
	     'ml-kem/tests',
	     'otp/tests',
	     'ml-dsa/tests',
	     'slh-dsa/tests',
	     'sym/tests',
	     'asn1/tests',
	     'efi/tests'
	   ]

appdirs = [ 'apps/src' ]

if (get_option('drbg_hmac').enabled() and
    (get_option('sha2-512').disabled() or get_option('hmac').disabled()))
	error('HMAC DRBG requires SHA2-512 and HMAC')
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

if (get_option('sha2-256').disabled() and
   (get_option('hkdf').enabled() or get_option('kdf_ctr').enabled() or
    get_option('kdf_fb').enabled() or get_option('kdf_dpi').enabled() or
    get_option('pbkdf2').enabled()))
	error('KDF support requires SHA2-256')
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

if (get_option('sha3').disabled() and
    (get_option('dilithium_87').enabled() or
     get_option('dilithium_65').enabled() or
     get_option('dilithium_44').enabled()))
	error('Dilithium support requires SHA-3')
endif

if (get_option('kmac').disabled() and
    (get_option('kyber_1024').enabled() or
     get_option('kyber_768').enabled() or
     get_option('kyber_512').enabled()))
	error('Kyper support requires KMAC due to SP800-108 KDF')
endif

if (get_option('sha3').disabled() and
    (get_option('sphincs_shake_256s').enabled() or
     get_option('sphincs_shake_256f').enabled() or
     get_option('sphincs_shake_192s').enabled() or
     get_option('sphincs_shake_192f').enabled() or
     get_option('sphincs_shake_128s').enabled() or
     get_option('sphincs_shake_128f').enabled()))
	error('Sphincs Plux support requires SHA-3')
endif

if (get_option('sha3').disabled() and
    (get_option('kyber_1024').enabled() or
     get_option('kyber_768').enabled() or
     get_option('kyber_512').enabled()))
	error('Kyber support requires SHA-3')
endif

if (get_option('sha3').disabled() and
    (get_option('bike_5').enabled() or
     get_option('bike_3').enabled() or
     get_option('bike_1').enabled()))
	error('BIKE support requires SHA-3')
endif

if (get_option('sha3').disabled() and
    (get_option('hqc_256').enabled() or
     get_option('hqc_192').enabled() or
     get_option('hqc_128').enabled()))
	error('HQC support requires SHA-3')
endif

if ((get_option('dilithium_ed25519').enabled() or
     get_option('kyber_x25519').enabled()) and
     get_option('sha2-512').disabled())
	error('Curve 25519 support requires SHA2-512')
endif

if get_option('sha3').disabled() and get_option('ascon_keccak').enabled()
	error('Ascon-Keccak support requires SHA-3')
endif

if (get_option('slh_dsa_ascon_128s').enabled() and
    get_option('ascon').disabled())
	error('SLH-DSA-Ascon-128s support requires Ascon')
endif

if (get_option('slh_dsa_ascon_128f').enabled() and
    get_option('ascon').disabled())
	error('SLH-DSA-Ascon-128f support requires Ascon')
endif

if get_option('x509_parser').disabled() and get_option('pkcs7_parser').enabled()
	error('PKCS#7 parser support requires X.509 parser support')
endif

if get_option('x509_parser').disabled() and get_option('x509_generator').enabled()
	error('X.509 generator support requires X.509 parser support')
endif

if get_option('pkcs7_parser').disabled() and get_option('pkcs7_generator').enabled()
	error('PKCS#7 / CMS generator support requires PKCS#7 / CMS parser support')
endif

if (get_option('chacha20poly1305').enabled() and
    get_option('chacha20').disabled())
	error('ChaCha20 Poly 1305 requires the presence of ChaCha20')
endif
################################################################################
# Enable assembler support
################################################################################

x86_64_asm = false
arm32_neon_asm = false
arm64_neon_gcc_asm = false
arm64_asm = false
riscv32_asm = false
riscv64_asm = false
riscv32_gcc_asm = false
riscv64_gcc_asm = false

# Enable x86_64 assembler code on x86 (naturally) with the following exceptions:
#	- macOS: the LLVM somehow does not seem to handle the x86_64 asm well
if (not get_option('disable-asm'))
	if (host_machine.cpu_family() == 'x86_64' and
	    host_machine.system() != 'darwin')

		# 64 bit AVX2 / AVX512 support
		x86_64_asm = true
		add_global_arguments([ '-DLC_HOST_X86_64' ], language: 'c')

		cc_avx2_args = [
			'-mavx2',
			'-mbmi2',
			'-mpopcnt',
			'-Wno-unused-command-line-argument',
		]
		cc_avx512_args = [
			'-mavx512f',
			'-mbmi2',
			'-mpopcnt',
			'-Wno-unused-command-line-argument',
		]
	endif

	# 32-bit ARM assembler support
	if (host_machine.cpu_family() == 'arm')

		# 32 bit ARM processor and GCC
		arm32_neon_asm = true

		add_global_arguments([ '-DLC_HOST_ARM32_NEON' ], language: 'c')

		cc_armv7_neon_simd_args = [
			'-mfpu=neon-vfpv4',
			'-mthumb',
			'-march=armv7-a+vfpv4',
			'-funsafe-math-optimizations'
		]

	# 64-bit ARM assembler support
	elif (host_machine.cpu_family() == 'aarch64')

		arm64_asm = true
		add_global_arguments([ '-DLC_HOST_AARCH64' ], language: 'c')

		cc_armv8_neon_simd_args = [
			'-march=armv8-a+simd',
			'-Wno-unused-result',
		]

		cc_armv8_neon_sha3_args = [
			'-march=armv8-a+simd+sha3',
			'-Wno-unused-result',
		]

		if (cc.get_id() == 'gcc')

			# 64 bit ARM processor and GCC
			# Disable assembler code as it is slower compared to C
			# see also issue https://github.com/XKCP/XKCP/issue/74
			arm64_neon_gcc_asm = false
			#arm64_neon_gcc_asm = true
		endif

	# The specific C code for RISCV is slower by a factor of more than 2
	# elif (host_machine.cpu_family() == 'riscv')
	# 	riscv32_asm = true
	elif (host_machine.cpu_family() == 'riscv64')
		riscv64_asm = true
		add_global_arguments([ '-DLC_HOST_RISCV64' ], language: 'c')

		cc_riscv64_asm_args = [
			'-march=rv64gc',
			'-mabi=lp64d',
			'-mcmodel=medany'
		]

		cc_riscv64_asm_zbb_args = [
			'-march=rv64imadc_zba_zbb',
			'-mabi=lp64d',
			'-mcmodel=medany'
		]

		cc_riscv64_asm_rvv_args = [
			'-march=rv64imadcv',
			'-mabi=lp64d',
			'-mcmodel=medany'
		]

		cc_riscv64_asm_rvv_zbb_args = [
			'-march=rv64imadcv_zba_zbb',
			'-mabi=lp64d',
			'-mcmodel=medany'
		]

	# elif (host_machine.cpu_family() == 'riscv' and
	#       cc.get_id() == 'gcc')
	#
	# 	# RISC-V and GCC
	# 	# riscv32_gcc_asm = true
	# 	# Disable implementation as it currently is not tested
	# 	riscv32_gcc_asm = false
	endif
endif

################################################################################
# Execute compilation
################################################################################

# FIPS non-approved crypto sources
src = [ ]

# FIPS-only code that shall not be compiled for the non-FIPS version
src_fips_wrapper = [ ]
src_wrapper = [ ]

# Internal non-cryptographic helper code
internal_src = [ ]

# Internal FIPS non-approved cryptographic support libs that need to be linked
# in as a whole
leancrypto_support_libs = [ ]

# External libraries leancrypto should link to
leancrypto_link = [ ]

foreach n : subdirs
	subdir(n)
endforeach

# Generate leancrypto.h
autogen_header = meson.project_build_root() + '/leancrypto.h'
leancrypto_header_subdir = 'leancrypto'

# meson under Windows does not resolve the script directory properly - thus
# under Windows the convenience include file of leancrypto.h is not yet
# available
if (host_machine.system() != 'windows')
	run_command(header_script,
		    autogen_header,
		    leancrypto_header_subdir,
		    include_files,
		    check: true)
endif

fips_integrity_hasher_dep = []
# Build FIPS 140 library
if build_shared
	link_args_fips140 = [ ]
	if fips_integrity_test_enabled
		link_args_fips140 = [
			'-T' + meson.project_source_root() + '/internal/src/fips_integrity_check.ld'
		]
	endif

	leancrypto_raw_static_lib = static_library('leancrypto-raw',
		[ src, internal_src ],
		include_directories: [ include_dirs, include_internal_dirs ],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_support_libs ],
		link_args: link_args_fips140,
		install: false
		)

	# Create the official shared library
	leancrypto_both_libs = both_libraries('leancrypto',
		[ src_wrapper ],
		include_directories: [ include_dirs, include_internal_dirs ],
		soversion: version_array[0],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_raw_static_lib ],
		link_args: link_args_fips140,
		install: true
		)

	leancrypto_lib = leancrypto_both_libs.get_shared_lib()
	leancrypto_static_lib = leancrypto_both_libs.get_static_lib()

	# Create the official shared FIPS library
	leancrypto_both_libs_fips = both_libraries('leancrypto-fips',
		[ src_fips_wrapper ],
		include_directories: [ include_dirs, include_internal_dirs ],
		soversion: version_array[0],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_raw_static_lib ],
		link_args: link_args_fips140,
		install: true
		)

	leancrypto_lib_fips = leancrypto_both_libs_fips.get_shared_lib()
	leancrypto_static_lib_fips = leancrypto_both_libs_fips.get_static_lib()

	# Generate the ELF FIPS integrity check control value
	if fips_integrity_test_enabled

		# This code simply re-purposes the sha3-256sum application
		# to compile it as a standalone application without dependencies
		integrity_generator_files = files([
			'apps/src/hasher_app.c',
			'apps/src/sha3-256sum.c',
			'hash/src/hash.c',
			'hash/src/sha256.c',
			'hash/src/sha512.c',
			'hash/src/sha3_c.c',
			'hash/src/sha3_selftest.c',
			'internal/src/binhexbin.c',
			'internal/src/compare.c',
			'internal/src/fips_mode.c',
			'internal/src/fips_integrity_checker_none.c',
			'internal/src/memcmp_secure_c.c',
			'internal/src/memory_support.c',
			'internal/src/status_algorithms.c',
			'internal/src/status_api.c',
		])

		# Compile the hasher application for build_machine to obtain
		# digest inserted into the shared object
		integrity_generator = executable('leancrypto-fips-hasher',
			[ integrity_generator_files ],
			include_directories: [ include_dirs,
					include_internal_dirs ],
			c_args: [ '-DLC_HASHER_SMALL' ],
			install: false,
			native: true # Compile executable for build_machine
			)

		# Execute generate tool to create message digest of relevant
		# ELF sections and inserts it into the shared object
		# The "output" definition is set to tell meson to wait before
		# anybody links to leancrypto_lib_fips
		fips_integrity_hasher = custom_target(
			'fips_integrity_hasher',
			build_always_stale: true,
			build_by_default: true,
			install: false,
			depends: [ leancrypto_lib_fips, integrity_generator ],
			input: [ leancrypto_lib_fips, integrity_generator ],
			output: leancrypto_lib_fips.name(),
			command: [
				fips_integrity_checker_script.full_path(),
				leancrypto_lib_fips.full_path(),
				integrity_generator.full_path() ]
			)
		fips_integrity_hasher_dep = declare_dependency(sources: fips_integrity_hasher)
	endif
else
	leancrypto_raw_static_lib = static_library('leancrypto-raw',
		[ src, internal_src ],
		include_directories: [ include_dirs, include_internal_dirs ],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_support_libs ],
		install: true
		)

	# Create the official static library
	leancrypto_static_lib = static_library('leancrypto',
		[ src_wrapper ],
		include_directories: [ include_dirs, include_internal_dirs ],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_raw_static_lib ],
		install: true
		)
	leancrypto_lib = leancrypto_static_lib

	# Create the official static FIPS library
	leancrypto_static_lib_fips = static_library('leancrypto-fips',
		[ src_fips_wrapper ],
		include_directories: [ include_dirs,
					include_internal_dirs ],
		dependencies: [ leancrypto_link ],
		link_whole: [ leancrypto_raw_static_lib ],
		install: true
		)
	leancrypto_lib_fips = leancrypto_static_lib_fips
endif

if get_option('efi').disabled()
	pkgconfig.generate(leancrypto_lib_fips,
			description: 'PQC-resistant cryptographic library with FIPS -140 compliance')
endif

leancrypto_fips = declare_dependency(link_with: leancrypto_lib_fips,
				     include_directories: include_dirs)

if get_option('efi').disabled()
	pkgconfig.generate(leancrypto_lib,
			   description: 'PQC-resistant cryptographic library')
endif

leancrypto = declare_dependency(link_with: leancrypto_lib,
				include_directories: include_dirs)

install_headers(include_files, subdir: leancrypto_header_subdir)
if (host_machine.system() != 'windows')
	# TODO: reenable
	install_headers(autogen_header)
endif

################################################################################
# Create apps
################################################################################
foreach n : appdirs
	subdir(n)
endforeach

################################################################################
# Create Doxygen documentation
################################################################################
if doxygen.found()
	subdir('doc')
else
	message('Doxygen documentation not generated due to missing Doxygen binary')
endif

################################################################################
# Execute testing
################################################################################
performance = 'performance'
regression = 'regression'

if (get_option('efi').disabled() and
    get_option('tests').enabled())
	foreach n : testdirs
		subdir(n)
	endforeach
else
	subdir('efi/tests')
endif
