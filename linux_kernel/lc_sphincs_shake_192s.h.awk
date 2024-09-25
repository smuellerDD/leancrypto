# Set the Dilithium security strength
{gsub("@sphincs_strength@", "16224", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_192s", $0) ;
 gsub("@sphincs_header@", "SHAKE_192S_", $0) ;

 print $0}
