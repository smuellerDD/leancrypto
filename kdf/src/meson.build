if get_option('hkdf').enabled()
	src_fips += files([ 'hkdf.c' ])
	include_files += files([ '../api/lc_hkdf.h' ])
endif

if get_option('kdf_ctr').enabled()
	src_fips += files([ 'kdf_ctr.c' ])
	include_files += files([ '../api/lc_kdf_ctr.h' ])
endif

if get_option('kdf_fb').enabled()
	src_fips += files([ 'kdf_fb.c' ])
	include_files += files([ '../api/lc_kdf_fb.h' ])
endif

if get_option('kdf_dpi').enabled()
	src_fips += files([ 'kdf_dpi.c' ])
	include_files += files([ '../api/lc_kdf_dpi.h' ])
endif

if get_option('pbkdf2').enabled()
	src_fips += files([ 'pbkdf2.c' ])
	include_files += files([ '../api/lc_pbkdf2.h' ])
endif
