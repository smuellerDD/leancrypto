# Set the Dilithium security strength
{gsub("@sphincs_strength@", "49856", $0) ;
 gsub("@sphincs_hash@", "lc_shake256", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_256f", $0) ;
 gsub("@sphincs_header@", "SHAKE_256F_", $0) ;

 print $0}
