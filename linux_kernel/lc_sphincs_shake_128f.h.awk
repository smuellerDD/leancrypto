# Set the Dilithium security strength
{gsub("@sphincs_strength@", "17088", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_128f", $0) ;
 gsub("@sphincs_header@", "SHAKE_128F_", $0) ;

 print $0}
