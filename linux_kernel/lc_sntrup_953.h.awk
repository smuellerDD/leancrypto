# Set the SNTRUP security strength
{gsub("@sntrup_mode@", "953", $0) ;
 gsub("@sntrup_name@", "lc_sntrup_953", $0) ;
 gsub("@sntrup_header@", "SNTRUP_953_", $0) ;

 print $0}
