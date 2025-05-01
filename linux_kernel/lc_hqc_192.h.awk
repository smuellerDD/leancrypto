# Set the HQC security strength
{gsub("@hqc_strength@", "192", $0) ;
 gsub("@hqc_name@", "lc_hqc_192", $0) ;
 gsub("@hqc_header@", "192_", $0) ;

 print $0}
