SECTIONS
{
	_start_init = .;
	PROVIDE(start_init = .);
}
INSERT BEFORE .init;

SECTIONS
{
	_end_init = .;
	PROVIDE(end_init = .);
}
INSERT AFTER .init;

SECTIONS
{
	_start_ctors = .;
	PROVIDE(start_ctors = .);
}
INSERT BEFORE .init;

SECTIONS
{
	_end_ctors = .;
	PROVIDE(end_ctors = .);
}
INSERT AFTER .init;

SECTIONS
{
	_start_text = .;
	PROVIDE(start_text = .);
}
INSERT BEFORE .text;

SECTIONS
{
	_end_text = .;
	PROVIDE(end_text = .);
}
INSERT AFTER .text;

#SECTIONS
#{
#	_start_rodata = .;
#	PROVIDE(start_rodata = .);
#}
#INSERT BEFORE .rodata;
#
#SECTIONS
#{
#	_end_rodata = .;
#	PROVIDE(end_rodata = .);
#}
#INSERT AFTER .rodata;
