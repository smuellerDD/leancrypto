# Set the Ascon memory size
BEGIN {
	"uname -m" | getline host
}
{
	if (host=="x86_64") {
		gsub("mesondefine LC_DEF_ASCON_AVX512", "define LC_DEF_ASCON_AVX512", $0) ;
	} else {
		gsub("mesondefine LC_DEF_ASCON_AVX512", "undef LC_DEF_ASCON_AVX512", $0) ;
	}

	print $0
}
