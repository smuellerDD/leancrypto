# for i in $(ls *.c | sort); do echo "'$i',"; done
bike_c = files([
	'bike_decode.c',
	'bike_decode_portable.c',
	'bike_gf2x_inv.c',
	'bike_gf2x_ksqr_portable.c',
	'bike_gf2x_mul.c',
	'bike_gf2x_mul_base_portable.c',
	'bike_gf2x_mul_portable.c',
	'bike_kem.c',
	'bike_sampling.c',
	'bike_sampling_portable.c',
])

if get_option('bike').enabled()
	include_files += files([ '../api/lc_bike.h' ])

	src += bike_c
endif

