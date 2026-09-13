# Set the SNTRUP security strength
{gsub("@sntrup_mode@", "761", $0) ;
 gsub("@sntrup_name@", "lc_sntrup_761", $0) ;
 gsub("@sntrup_header@", "SNTRUP_761_", $0) ;

 print $0}
