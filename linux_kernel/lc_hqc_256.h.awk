# Set the HQC security strength
{gsub("@hqc_strength@", "256", $0) ;
 gsub("@hqc_name@", "lc_hqc_256", $0) ;
 gsub("@hqc_header@", "256_", $0) ;

 print $0}
