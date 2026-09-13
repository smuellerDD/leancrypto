# Set the SNTRUP security strength
{gsub("@sntrup_mode@", "1013", $0) ;
 gsub("@sntrup_name@", "lc_sntrup_1013", $0) ;
 gsub("@sntrup_header@", "SNTRUP_1013_", $0) ;

 print $0}
