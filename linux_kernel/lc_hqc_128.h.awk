# Set the HQC security strength
{gsub("@hqc_strength@", "128", $0) ;
 gsub("@hqc_name@", "lc_hqc_128", $0) ;
 gsub("@hqc_header@", "128_", $0) ;

 print $0}
