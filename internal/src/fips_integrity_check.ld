SECTIONS
{
	.lc_fips_integrity_hash :
	{
		/* Executable code */
		PROVIDE(lc_fips_start_init = ADDR(.init));
		PROVIDE(lc_fips_end_init = ADDR(.init) + SIZEOF(.init));

		/* Executable code */
		PROVIDE(lc_fips_start_text = ADDR(.text));
		PROVIDE(lc_fips_end_text = ADDR(.text) + SIZEOF(.text));

		/* Modifiable data */
		PROVIDE(lc_fips_start_data = ADDR(.data));
		PROVIDE(lc_fips_end_data = ADDR(.data) + SIZEOF(.data));

		/* Read-only data */
		#PROVIDE(lc_fips_start_rodata = ADDR(.rodata));
		#PROVIDE(lc_fips_end_rodata = ADDR(.rodata) + SIZEOF(.rodata));
		PROVIDE(lc_fips_start_rodata = ADDR(.lc_fips_rodata));
		PROVIDE(lc_fips_end_rodata = ADDR(.lc_fips_rodata) + SIZEOF(.lc_fips_rodata));

		/* Relocatable, then read-only */
		PROVIDE(lc_fips_start_datarelro = ADDR(.data.rel.ro));
		PROVIDE(lc_fips_end_datarelro = ADDR(.data.rel.ro) + SIZEOF(.data.rel.ro));

		*(.lc_fips_integrity_hash)
  	}
}
INSERT AFTER .rodata;

SECTIONS {
	.lc_fips_integrity_data : { *(.fips_integrity_data) }
}
INSERT AFTER .lc_fips_integrity_hash;
