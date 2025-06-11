# for i in $(ls *.c | sort); do echo "'$i',"; done

curve448_avx2 = files([
	'curve448_mladder.S',
	'curve448_mladder_base.S',
	'curve448_scalarmult_avx2.c',
	'gf_p4482241_inv.c',
	'gf_p4482241_makeunique.S',
	'gf_p4482241_mul.S',
	'gf_p4482241_mulx.S',
	'gf_p4482241_nsqr.S',
	'gf_p4482241_nsqrx.S',
	'gf_p4482241_pack.c',
])

leancrypto_curve448_avx2_lib = static_library(
		'leancrypto_curve448_avx2_lib',
		[ curve448_avx2 ],
		include_directories: [
			'../',
			include_dirs,
			include_internal_dirs
		],
		c_args: cc_avx2_args
	)

leancrypto_support_libs_fips += leancrypto_curve448_avx2_lib
