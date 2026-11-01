# Set the XOR alignment value for target_arch
{
	if (target_arch=="x86_64") {
		gsub("mesondefine LC_DEF_HOST_X86_64", "define LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "undef LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "undef LC_DEF_HOST_AARCH64", $0) ;
	} else if (target_arch=="arm") {
		gsub("mesondefine LC_DEF_HOST_X86_64", "undef LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "define LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "undef LC_DEF_HOST_AARCH64", $0) ;
	} else if (target_arch=="aarch64") {
		gsub("mesondefine LC_DEF_HOST_X86_64", "undef LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "undef LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "define LC_DEF_HOST_AARCH64", $0) ;
	} else {
		gsub("mesondefine LC_DEF_HOST_X86_64", "undef LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "undef LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "undef LC_DEF_HOST_AARCH64", $0) ;
	}

	print $0
}
