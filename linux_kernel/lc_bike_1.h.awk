# Set the Kyber security strength
{gsub("@bike_strength@", "1", $0) ;
 gsub("@bike_name@", "lc_bike_1", $0) ;
 gsub("@bike_header@", "1_", $0) ;

 print $0}
