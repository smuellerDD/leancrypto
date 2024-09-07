# Set the Kyber security strength
{gsub("@bike_strength@", "3", $0) ;
 gsub("@bike_name@", "lc_bike_3", $0) ;
 gsub("@bike_header@", "3_", $0) ;

 print $0}
