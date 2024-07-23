doxygen_cdata = configuration_data()
doxygen_cdata.set('VERSION', meson.project_version())
doxygen_cdata.set('TOP_SRCDIR', meson.project_source_root())
doxygen_cdata.set('TOP_BUILDDIR', meson.project_build_root())

if find_program('dot', required : false).found()
	doxygen_cdata.set('HAVE_DOT', 'YES')
else
	doxygen_cdata.set('HAVE_DOT', 'NO')
endif

doxyfile = configure_file(input: 'Doxyfile.in',
                          output: 'Doxyfile',
                          configuration: doxygen_cdata,
                          install: false)

datadir = join_paths(get_option('datadir'), 'doc', 'leancrypto')

html_target = custom_target('leancrypto-docs',
                            input: doxyfile,
                            output: 'html',
                            command: [doxygen, doxyfile],
                            install: true,
                            install_dir: datadir)
