SECTIONS
{
	.lc_fips_integrity_hash :
	{
		/* Executable code */
		PROVIDE(fips_start_init = ADDR(.init));
		PROVIDE(fips_end_init = ADDR(.init) + SIZEOF(.init));

		/* Executable code */
		PROVIDE(fips_start_text = ADDR(.text));
		PROVIDE(fips_end_text = ADDR(.text) + SIZEOF(.text));

		/* Modifiable data */
		PROVIDE(fips_start_data = ADDR(.data));
		PROVIDE(fips_end_data = ADDR(.data) + SIZEOF(.data));

		/* Read-only data */
		#PROVIDE(fips_start_rodata = ADDR(.rodata));
		#PROVIDE(fips_end_rodata = ADDR(.rodata) + SIZEOF(.rodata));
		PROVIDE(fips_start_rodata = ADDR(.fips_rodata));
		PROVIDE(fips_end_rodata = ADDR(.fips_rodata) + SIZEOF(.fips_rodata));

		/* Relocatable, then read-only */
		PROVIDE(fips_start_datarelro = ADDR(.data.rel.ro));
		PROVIDE(fips_end_datarelro = ADDR(.data.rel.ro) + SIZEOF(.data.rel.ro));

		*(.lc_fips_integrity_hash)
  	}
}
INSERT AFTER .rodata;

SECTIONS {
	.fips_integrity_data : { *(.fips_integrity_data) }
}
INSERT AFTER .lc_fips_integrity_hash;
