# Set the SNTRUP security strength
{gsub("@sntrup_mode@", "1277", $0) ;
 gsub("@sntrup_name@", "lc_sntrup_1277", $0) ;
 gsub("@sntrup_header@", "SNTRUP_1277_", $0) ;

 print $0}
