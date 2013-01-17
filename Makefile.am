ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = $(FW_INCLUDE) $(TSK_INCLUDE) -Wall
LDFLAGS="-lmagic"

lib_LTLIBRARIES = libtskFileTypeSigModule.la
libtskFileTypeSigModule_la_SOURCES = FileTypeModule.cpp
libtskFileTypeSigModule_la_LIBADD = $(FW_LIBS)

nobase_dist_data_DATA = tsk/FileTypeSigModule/*

bin_PROGRAMS = maybe_copy_configs

MODULE_CONFIG_DIR = $(RUNTIME_MODULES_CONFIG_DIR)/FileTypeSigModule

maybe_copy_configs:
	if test "$(FW_LIBS)" != ""; then \
		mkdir -p $(MODULE_CONFIG_DIR); \
		(cd $(MODULE_CONFIG_DIR); ln -sf $(MODULES_ROOT_DIR)/c_FileTypeSigModule/file-5.08/magic/magic.mgc .); \
	fi

