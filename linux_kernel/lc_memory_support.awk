# Set the hash alignment value
BEGIN {
	"uname -m" | getline host
}
{
	if (host=="x86_64") {
		gsub("mesondefine LC_DEF_HOST_X86_64", "define LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "undef LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "undef LC_DEF_HOST_AARCH64", $0) ;
	} else if (host=="arm") {
		gsub("mesondefine LC_DEF_HOST_X86_64", "undef LC_DEF_HOST_X86_64", $0) ;
		gsub("mesondefine LC_DEF_HOST_ARM32_NEON", "define LC_DEF_HOST_ARM32_NEON", $0) ;
		gsub("mesondefine LC_DEF_HOST_AARCH64", "undef LC_DEF_HOST_AARCH64", $0) ;
	} else if (host=="aarch64") {
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
