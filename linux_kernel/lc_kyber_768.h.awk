# Set the Kyber security strength
{gsub("@kyber_strength@", "3", $0) ;
 gsub("@kyber_name@", "lc_kyber_768", $0) ;
 gsub("@kex_name@", "lc_kex_768", $0) ;
 gsub("@kyber_header@", "768_", $0) ;

 # Define LC_KYBER_X25519_KEM and LC_KYBER_IES
 # Comment out if CONFIG_LEANCRYPTO_KEM_X25519 or if all AEAD algorithms
 # are unset
 gsub("mesondefine", "define", $0) ;

 print $0}
