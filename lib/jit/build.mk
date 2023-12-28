include $(TOP)/build/header.mk

products_$(d) := libjit.$(so)

ifeq ($(OS),Darwin)
  LLVM_INCLUDES := $(shell brew --prefix llvm@15)/include
  LLVM_LIBS := $(shell brew --prefix llvm@15)/lib
else
	LLVM_INCLUDES := $(shell pkg-config --cflags-only-I)
endif

libjit.$(so)_sources_$(d) += \
	core.cpp

libjit.$(so)_needs_$(d)       := lib/libabi.$(so)
libjit.$(so)_precompiled_$(d) :=
libjit.$(so)_target_dir_$(d)  := lib
libjit.$(so)_cxx_flags_$(d)   := -std=c++14 -I$(LLVM_INCLUDES)
libjit.$(so)_ld_flags_$(d)    := -shared -dylib -undefined dynamic_lookup -L$(BUILD_DIR)/lib -L$(LLVM_LIBS) -lLLVM -labi

include $(TOP)/build/footer.mk
