# Set the Dilithium security strength
{gsub("@sphincs_strength@", "7856", $0) ;
 gsub("@sphincs_hash@", "lc_shake256", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_128s", $0) ;
 gsub("@sphincs_header@", "SHAKE_128S_", $0) ;

 print $0}
