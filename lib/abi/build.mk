include $(TOP)/build/header.mk

products_$(d) := libabi.dylib

libabi.dylib_sources_$(d) += \
	personality.cpp

libabi.dylib_precompiled_$(d) :=
libabi.dylib_target_dir_$(d)  := lib
libabi.dylib_cxx_flags_$(d)   := -std=c++14
libabi.dylib_ld_flags_$(d)    := -rdynamic -shared -undefined dynamic_lookup

include $(TOP)/build/footer.mk
