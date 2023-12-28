include $(TOP)/build/header.mk

products_$(d) := libabi.$(so)

libabi.$(so)_sources_$(d) += \
	personality.cpp

libabi.$(so)_precompiled_$(d) :=
libabi.$(so)_target_dir_$(d)  := lib
libabi.$(so)_cxx_flags_$(d)   := -std=c++14
libabi.$(so)_ld_flags_$(d)    := -rdynamic -shared -undefined dynamic_lookup

include $(TOP)/build/footer.mk
