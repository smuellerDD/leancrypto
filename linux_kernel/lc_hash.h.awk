# Set the hash alignment value
BEGIN {
	"uname -m" | getline host
}
{
	if (host=="x86_64") {
		gsub("@hash_common_alignment@", "64", $0) ;
	} else if (host=="arm") {
		gsub("@hash_common_alignment@", "32", $0) ;
	} else {
		gsub("@hash_common_alignment@", "8", $0) ;
	}

	print $0
}
