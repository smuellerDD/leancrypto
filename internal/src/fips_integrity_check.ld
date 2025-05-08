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
		PROVIDE(fips_data_base = ADDR(.data));
		PROVIDE(fips_data_end = ADDR(.data) + SIZEOF(.data));

		/* Read-only data */
		PROVIDE(fips_rodata_base = ADDR(.rodata));
		PROVIDE(fips_rodata_end = ADDR(.rodata) + SIZEOF(.rodata));

		/* Relocatable, then read-only */
		PROVIDE(fips_datarelro_base = ADDR(.data.rel.ro));
		PROVIDE(fips_datarelro_end = ADDR(.data.rel.ro) + SIZEOF(.data.rel.ro));

		*(.lc_fips_integrity_hash)
  }
}
INSERT AFTER .rodata;
