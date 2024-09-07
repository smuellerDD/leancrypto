# Set the Kyber security strength
{gsub("@bike_strength@", "5", $0) ;
 gsub("@bike_name@", "lc_bike_5", $0) ;
 gsub("@bike_header@", "5_", $0) ;

 print $0}
