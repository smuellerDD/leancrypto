memory_support_conf_data = configuration_data()
memory_support_conf_data.set('LC_DEF_HOST_X86_64', x86_64_asm)
memory_support_conf_data.set('LC_DEF_HOST_ARM32_NEON', arm32_neon_gcc_asm)
memory_support_conf_data.set('LC_DEF_HOST_AARCH64', arm64_asm)
include_files += configure_file(input: 'lc_memory_support.h.in',
				output: 'lc_memory_support.h',
				configuration: memory_support_conf_data)
