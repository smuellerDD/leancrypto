# Set the Kyber security strength
{gsub("@kyber_strength@", "4", $0) ;
 gsub("@kyber_name@", "lc_kyber_1024", $0) ;
 gsub("@kex_name@", "lc_kex_1024", $0) ;
 gsub("@kyber_header@", "1024_", $0) ;

 # Define LC_KYBER_X25519_KEM
 # Comment out if CONFIG_LEANCRYPTO_KEM_X25519 is unset
 gsub("mesondefine", "define", $0) ;

 print $0}
