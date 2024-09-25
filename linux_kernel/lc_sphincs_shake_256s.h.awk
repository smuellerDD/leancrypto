# Set the Dilithium security strength
{gsub("@sphincs_strength@", "29792", $0) ;
 gsub("@sphincs_name@", "lc_sphincs_shake_256s", $0) ;
 gsub("@sphincs_header@", "SHAKE_256S_", $0) ;

 print $0}
