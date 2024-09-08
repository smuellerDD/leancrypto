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
	version: '1.1.0',
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
		        ],
		       language : 'c')

# More hardening
if cc.has_argument('-fzero-call-used-regs=used-gpr')
	add_global_arguments([ '-fzero-call-used-regs=used-gpr' ],
			     language: 'c')
endif
if cc.has_argument('-ftrivial-auto-var-init=zero')
	add_global_arguments([ '-ftrivial-auto-var-init=zero' ],
			     language: 'c')
endif

# x86_64 hardening
if cc.has_argument('-fcf-protection=full')
	add_global_arguments([ '-fcf-protection=full' ],
			     language: 'c')
endif

# ARM64 hardening
if cc.has_argument('-mbranch-protection=standard')
	add_global_arguments([ '-mbranch-protection=standard' ],
			     language: 'c')
endif

# MINGW64 cannot handle lto properly at the moment
if (cc.has_argument('-flto') and
    host_machine.system() != 'windows')
	add_global_arguments([ '-flto=auto' ], language: 'c')
	add_project_link_arguments('-flto=auto', language : 'c')
endif

if (cc.has_argument('-ffat-lto-objects') and
    host_machine.system() != 'windows')
	add_global_arguments([ '-ffat-lto-objects' ], language: 'c')
endif

if get_option('optimization') == '0'
	add_global_arguments([ '-DDEBUG' ], language: 'c')
else
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

if get_option('dilithium_debug').enabled()
	add_global_arguments([ '-DLC_DILITHIUM_DEBUG' ], language: 'c')
endif
if get_option('kyber_debug').enabled()
	add_global_arguments([ '-DLC_KYBER_DEBUG' ], language: 'c')
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
if (host_machine.system() == 'linux')
	add_project_link_arguments('-Wl,-z,relro', language : 'c')
	add_project_link_arguments('-Wl,-z,now', language : 'c')
	add_project_link_arguments('-Wl,-z,noexecstack', language : 'c')
	add_project_link_arguments('-Wl,-z,nodlopen', language : 'c')
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

# Header generation
header_script = find_program('addon/generate_header.sh', required: true)

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

# Find Doxygen program
doxygen = find_program('doxygen', required : false)

################################################################################
# Project-specific defines
################################################################################

pkgconfig = import('pkgconfig')

include_dirs = include_directories([ 'aead/api',
				     'bike/api',
				     'curve25519/api',
				     'drng/api',
				     'drng/src',
				     'hash/api',
				     'hmac/api',
				     'ml-kem/api',
				     'kdf/api',
				     'kmac/api',
				     'otp/api',
				     'ml-dsa/api',
				     'sym/api'
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
	    'drng/src',
	    'hash/src',
	    'internal/src',
	    'kdf/src',
	    'ml-kem/api',
	    'ml-kem/src',
	    'otp/src',
	    'ml-dsa/api',
	    'ml-dsa/src',
	    'sym/src'
	  ]

testdirs = [ 'apps/tests',
	     'aead/tests',
	     'bike/tests',
	     'curve25519/tests',
	     'drng/tests',
	     'hash/tests',
	     'internal/tests',
	     'kdf/tests',
	     'ml-kem/tests',
	     'otp/tests',
	     'ml-dsa/tests',
	     'sym/tests'
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

if (host_machine.endian() == 'big' and
    (get_option('bike_5').enabled() or
     get_option('bike_3').enabled() or
     get_option('bike_1').enabled()))
	error('BIKE support currently limited to Little Endian - you MUST disable all BIKE options to proceed')
endif

if ((get_option('dilithium_ed25519').enabled() or
     get_option('kyber_x25519').enabled()) and
     get_option('sha2-512').disabled())
	error('Curve 25519 support requires SHA2-512')
endif

if get_option('sha3').disabled() and get_option('ascon_keccak').enabled()
	error('Ascon-Keccak support requires SHA-3')
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
if (host_machine.cpu_family() == 'x86_64' and
    host_machine.system() != 'darwin')

	# 64 bit AVX2 / AVX512 support
	x86_64_asm = true
	add_global_arguments([ '-DLC_HOST_X86_64' ], language: 'c')

	cc_avx2_args = [
		'-mavx2',
		'-mbmi2',
		'-mpopcnt',
		'-Wno-unused-command-line-argument'
	]
	cc_avx512_args = [
		'-mavx512f',
		'-mbmi2',
		'-mpopcnt',
		'-Wno-unused-command-line-argument'
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
# elif (host_machine.cpu_family() == 'riscv' and
#       cc.get_id() == 'gcc')
#
# 	# RISC-V and GCC
# 	# riscv32_gcc_asm = true
# 	# Disable implementation as it currently is not tested
# 	riscv32_gcc_asm = false
endif

################################################################################
# Execute compilation
################################################################################

src = [ ]
internal_src = [ ]

# Internal support libs that need to be linked in as a whole
leancrypto_support_libs = [ ]

# External libraries leancrypto should link to
leancrypto_link = [ ]

foreach n : subdirs
	subdir(n)
endforeach

# Generate leancrypto.h
autogen_header = meson.build_root() + '/leancrypto.h'
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

# Create the official static library
leancrypto_static_lib = static_library('leancrypto',
	[ src, internal_src ],
	include_directories: [ include_dirs, include_internal_dirs ],
	dependencies: [ leancrypto_link ],
	link_whole: [ leancrypto_support_libs ],
	install: true
	)

# Create the official shared library
leancrypto_lib = library('leancrypto',
	[ src, internal_src ],
	include_directories: [ include_dirs, include_internal_dirs ],
	soversion: version_array[0],
	dependencies: [ leancrypto_link ],
	link_whole: [ leancrypto_support_libs ],
	install: true
	)
leancrypto = declare_dependency(link_with: leancrypto_lib,
				include_directories: include_dirs)

pkgconfig.generate(leancrypto_lib,
		   description: 'PQC-resistant cryptographic library')

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

foreach n : testdirs
	subdir(n)
endforeach
