# Set the Dilithium security strength
{gsub("@sphincs_strength@", "35664", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_192f", $0) ;
 gsub("@sphincs_header@", "SHAKE_192F_", $0) ;

 print $0}
