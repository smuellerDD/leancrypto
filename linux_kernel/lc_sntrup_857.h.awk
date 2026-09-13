# Set the SNTRUP security strength
{gsub("@sntrup_mode@", "857", $0) ;
 gsub("@sntrup_name@", "lc_sntrup_857", $0) ;
 gsub("@sntrup_header@", "SNTRUP_857_", $0) ;

 print $0}
