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
	version: '0.5.4',
	default_options: [
		'warning_level=3',
		'optimization=3',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pic=true',
	])

################################################################################
# Generic project defines
################################################################################

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
		        ],
		       language : 'c')

c_compiler = meson.get_compiler('c')
if c_compiler.get_id() == 'gcc'
	add_global_arguments([ '-ffat-lto-objects' ], language: 'c')
endif

if get_option('optimization') != '0'
        add_global_arguments([ '-U_FORTIFY_SOURCE' ], language: 'c')
        add_global_arguments([ '-D_FORTIFY_SOURCE=3' ], language: 'c')
else
        add_global_arguments([ '-DDEBUG' ], language: 'c')
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

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
if (build_machine.system() == 'darwin')
	add_project_link_arguments('-Wl,-dead_strip', language : 'c')
else
	add_project_link_arguments('-Wl,--gc-sections', language : 'c')
endif

# Link for full RELRO
if (build_machine.system() == 'linux')
	add_project_link_arguments('-Wl,-z,relro', language : 'c')
	add_project_link_arguments('-Wl,-z,now', language : 'c')
	add_project_link_arguments('-Wl,-z,noexecstack', language : 'c')
endif

# Only link to truly needed libraries
if (build_machine.system() != 'darwin')
	add_project_link_arguments('-Wl,--as-needed', language : 'c')
endif

# Header generation
header_script = find_program('addon/generate_header.sh', required: true)

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

################################################################################
# Project-specific defines
################################################################################

include_dirs = include_directories([ 'aead/api',
				     'drng/api',
				     'drng/src',
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

if get_option('sha2-256').disabled() and
   (get_option('hkdf').enabled() or get_option('kdf_ctr').enabled() or
    get_option('kdf_fb').enabled() or get_option('kdf_dpi').enabled() or
    get_option('pbkdf2').enabled())
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

if get_option('sha3').disabled() and get_option('dilithium').enabled()
	error('Dilithium support requires SHA-3')
endif

if get_option('sha3').disabled() and get_option('kyber').enabled()
	error('Kyber support requires SHA-3')
endif


################################################################################
# Enable assembler support
################################################################################

x86_64_asm = false
arm32_neon_gcc_asm = false
arm64_neon_gcc_asm = false
arm64_asm = false
riscv = false
riscv32_gcc_asm = false
riscv64_gcc_asm = false

# Enable x86_64 assembler code only on x86 (naturally) and with the presence of
# the GNU assembler - the LLVM assembler on MacOS does not work!
if (host_machine.cpu_family() == 'x86_64' and
    host_machine.system() != 'darwin')

	# 64 bit AVX2 / AVX512 support
	x86_64_asm = true

	# Alignment x86_64: 8 bytes as required by AVX2 / AVX512
	add_global_arguments([ '-DLC_HASH_COMMON_ALIGNMENT=8' ], language: 'c')
endif

if (host_machine.cpu_family() == 'arm' and
    c_compiler.get_id() == 'gcc')

	# 32 bit ARM processor and GCC
	arm32_neon_gcc_asm = true

	# Alignment ARM 32 bits: 32 bytes as required by NEON on ARMv7
	add_global_arguments([ '-DLC_HASH_COMMON_ALIGNMENT=32' ], language: 'c')

elif (host_machine.cpu_family() == 'aarch64')

	arm64_asm = true

	if (c_compiler.get_id() == 'gcc')

		# 64 bit ARM processor and GCC
		# Disable assembler code as it is slower compared to C
		# see also issue https://github.com/XKCP/XKCP/issue/74
		arm64_neon_gcc_asm = false
		#arm64_neon_gcc_asm = true

		# Alignment ARM 64 bits: 64 bytes as required by NEON on ARMv8
		#add_global_arguments([ '-DLC_HASH_COMMON_ALIGNMENT=64' ], language: 'c')
	endif

# The specific C code for RISCV is slower by a factor of more than 2
# elif (host_machine.cpu_family() == 'riscv')
# 	riscv = true
# elif (host_machine.cpu_family() == 'riscv64')
# 	riscv = true
# elif (host_machine.cpu_family() == 'riscv' and
#       c_compiler.get_id() == 'gcc')
#
# 	# RISC-V and GCC
# 	# riscv32_gcc_asm = true
# 	# Disable implementation as it currently is not tested
# 	riscv32_gcc_asm = false
#
# elif (host_machine.cpu_family() == 'riscv64' and
#       c_compiler.get_id() == 'gcc')
#
# 	# RISC-V and GCC
# 	# Current code is not 64-bit ready
# 	riscv64_gcc_asm = true
endif

################################################################################
# Execute compilation
################################################################################

src = [ ]
leancrypto_support_libs = [ ]

foreach n : subdirs
	subdir(n)
endforeach

# Generate leancrypto.h
autogen_header = meson.build_root() + '/leancrypto.h'
leancrypto_header_subdir = 'leancrypto'
run_command(header_script,
	    autogen_header,
	    leancrypto_header_subdir,
	    include_files,
	    check: true)

leancrypto_static_lib = static_library('leancrypto',
	[ src, internal_src ],
	include_directories: [ include_dirs, include_internal_dirs ],
	link_whole: [ leancrypto_support_libs ],
	install: true
	)

leancrypto_lib = library('leancrypto',
	[ src, internal_src ],
	include_directories: [ include_dirs, include_internal_dirs ],
	soversion: version_array[0],
	link_whole: [ leancrypto_support_libs ],
	install: true
	)
leancrypto = declare_dependency(link_with: leancrypto_lib,
				include_directories: include_dirs)

install_headers(include_files, subdir: leancrypto_header_subdir)
install_headers(autogen_header)

################################################################################
# Execute testing
################################################################################

foreach n : testdirs
	subdir(n)
endforeach
