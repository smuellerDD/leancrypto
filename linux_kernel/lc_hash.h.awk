# Set the hash alignment value
BEGIN {
	"uname -m" | getline host
}
{
	if (host=="x86_64") {
		# This value has to be limited to 32 as otherwise the hash
		# algorithms fail to register since their state is larger than
		# HASH_MAX_DESCSIZE - this is an arbitrary defined value in
		# the kernel. When this kernel variable would be increased,
		# we could increase this back to 64.
		#
		# As long as this value is not 64, we cannot enable the AVX-512
		# implementation as it requires an alignment of the buffer to
		# 512 bits.
		gsub("@hash_common_alignment@", "32", $0) ;
	} else if (host=="arm") {
		gsub("@hash_common_alignment@", "32", $0) ;
	} else {
		gsub("@hash_common_alignment@", "8", $0) ;
	}

	print $0
}
