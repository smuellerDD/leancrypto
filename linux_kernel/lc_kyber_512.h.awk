# Set the Kyber security strength
{gsub("@kyber_strength@", "2", $0) ;
 gsub("@kyber_name@", "lc_kyber_512", $0) ;
 gsub("@kex_name@", "lc_kex_512", $0) ;
 gsub("@kyber_header@", "512_", $0) ;

 # Define LC_KYBER_X25519_KEM, LC_KYBER_X448_KEM and LC_KYBER_IES
 # Comment out if CONFIG_LEANCRYPTO_KEM_X25519, CONFIG_LEANCRYPTO_KEM_X448 or if
 # all AEAD algorithms are unset
 gsub("mesondefine", "define", $0) ;

 print $0}
