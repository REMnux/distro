#
# UPX top-level Makefile - needs GNU make and CMake >= 3.13
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#

ifeq ($(UPX_MAKEFILE_EXTRA_MK_INCLUDED),)
override UPX_MAKEFILE_EXTRA_MK_INCLUDED := 1

#***********************************************************************
# support functions
#***********************************************************************

override check_defined   = $(foreach 1,$1,$(if $(filter undefined,$(origin $1)),$(error ERROR: variable '$1' is not defined),))
override check_undefined = $(foreach 1,$1,$(if $(filter undefined,$(origin $1)),,$(error ERROR: variable '$1' is already defined)))

# return "1" or empty-string
override eq = $(if $(subst x$1,,x$2)$(subst x$2,,x$1),,1)
override ne = $(if $(subst x$1,,x$2)$(subst x$2,,x$1),1,)

override tolower = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))
override toupper = $(subst a,A,$(subst b,B,$(subst c,C,$(subst d,D,$(subst e,E,$(subst f,F,$(subst g,G,$(subst h,H,$(subst i,I,$(subst j,J,$(subst k,K,$(subst l,L,$(subst m,M,$(subst n,N,$(subst o,O,$(subst p,P,$(subst q,Q,$(subst r,R,$(subst s,S,$(subst t,T,$(subst u,U,$(subst v,V,$(subst w,W,$(subst x,X,$(subst y,Y,$(subst z,Z,$1))))))))))))))))))))))))))

# canonicalize the case of CMAKE_BUILD_TYPE to "Debug" and "Release"
override cm_build_type = $(if $(call eq,$1,),$(error EMPTY-build-type),$(if $(call eq,$(call tolower,$1),debug),Debug,$(if $(call eq,$(call tolower,$1),release),Release,$(if $(call eq,$(call tolower,$1),none),None,$1))))

#***********************************************************************
# extra builds: some pre-defined build configurations
#***********************************************************************

$(call check_defined,run_config run_build)
$(call check_undefined,run_config_and_build)

define run_config_and_build
	$(call run_config,$1,$2)
	$(call run_build,$1,$2)
endef

# force building with clang/clang++
build/extra/clang/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang/%: export CC  = clang
build/extra/clang/%: export CXX = clang++

# force building with clang/clang++ -m32
build/extra/clang-m32/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-m32/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-m32/%: export CC  = clang   -m32
build/extra/clang-m32/%: export CXX = clang++ -m32

# force building with clang/clang++ -mx32
build/extra/clang-mx32/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-mx32/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-mx32/%: export CC  = clang   -mx32
build/extra/clang-mx32/%: export CXX = clang++ -mx32

# force building with clang/clang++ -m64
build/extra/clang-m64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-m64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-m64/%: export CC  = clang   -m64
build/extra/clang-m64/%: export CXX = clang++ -m64

# force building with clang/clang++ -flto=auto
build/extra/clang-lto-auto/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-lto-auto/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-lto-auto/%: export CC  = clang   -flto=auto
build/extra/clang-lto-auto/%: export CXX = clang++ -flto=auto

# force building with clang/clang++ -pie
build/extra/clang-pie/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-pie/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-pie/%: export CC  = clang   -pie -fPIE -Wno-unused-command-line-argument
build/extra/clang-pie/%: export CXX = clang++ -pie -fPIE -Wno-unused-command-line-argument
build/extra/clang-pie/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with clang/clang++ -static
build/extra/clang-static/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-static/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-static/%: export CC  = clang   -static
build/extra/clang-static/%: export CXX = clang++ -static
build/extra/clang-static/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with clang/clang++ -static-pie
build/extra/clang-static-pie/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-static-pie/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-static-pie/%: export CC  = clang   -static-pie -fPIE -Wno-unused-command-line-argument
build/extra/clang-static-pie/%: export CXX = clang++ -static-pie -fPIE -Wno-unused-command-line-argument
build/extra/clang-static-pie/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with clang/clang++ -static -flto
build/extra/clang-static-lto/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-static-lto/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-static-lto/%: export CC  = clang   -static -flto
build/extra/clang-static-lto/%: export CXX = clang++ -static -flto
build/extra/clang-static-lto/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with clang/clang++ C++20 (and C17)
build/extra/clang-std-cxx20/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-std-cxx20/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-std-cxx20/%: export CC  = clang   -std=gnu17
build/extra/clang-std-cxx20/%: export CXX = clang++ -std=gnu++20
build/extra/clang-std-cxx20/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/clang-std-cxx20/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# force building with clang/clang++ C++23 (and C23)
build/extra/clang-std-cxx23/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-std-cxx23/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-std-cxx23/%: export CC  = clang   -std=gnu2x -Wno-constant-logical-operand
build/extra/clang-std-cxx23/%: export CXX = clang++ -std=gnu++2b
build/extra/clang-std-cxx23/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/clang-std-cxx23/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# force building with clang/clang++ C++26 (and C23)
build/extra/clang-std-cxx26/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/clang-std-cxx26/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/clang-std-cxx26/%: export CC  = clang   -std=gnu2x -Wno-constant-logical-operand
build/extra/clang-std-cxx26/%: export CXX = clang++ -std=gnu++2c
build/extra/clang-std-cxx26/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/clang-std-cxx26/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# force building with gcc/g++
build/extra/gcc/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc/%: export CC  = gcc
build/extra/gcc/%: export CXX = g++

# force building with gcc/g++ -m32
build/extra/gcc-m32/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-m32/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-m32/%: export CC  = gcc -m32
build/extra/gcc-m32/%: export CXX = g++ -m32

# force building with gcc/g++ -mx32
build/extra/gcc-mx32/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-mx32/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-mx32/%: export CC  = gcc -mx32
build/extra/gcc-mx32/%: export CXX = g++ -mx32

# force building with gcc/g++ -m64
build/extra/gcc-m64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-m64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-m64/%: export CC  = gcc -m64
build/extra/gcc-m64/%: export CXX = g++ -m64

# force building with gcc/g++ -flto=auto
build/extra/gcc-lto-auto/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-lto-auto/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-lto-auto/%: export CC  = gcc -flto=auto
build/extra/gcc-lto-auto/%: export CXX = g++ -flto=auto

# force building with gcc/g++ -pie
build/extra/gcc-pie/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-pie/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-pie/%: export CC  = gcc -pie -fPIE
build/extra/gcc-pie/%: export CXX = g++ -pie -fPIE
build/extra/gcc-pie/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with gcc/g++ -static
build/extra/gcc-static/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-static/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-static/%: export CC  = gcc -static
build/extra/gcc-static/%: export CXX = g++ -static
build/extra/gcc-static/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with gcc/g++ -static-pie
build/extra/gcc-static-pie/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-static-pie/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-static-pie/%: export CC  = gcc -static-pie -fPIE
build/extra/gcc-static-pie/%: export CXX = g++ -static-pie -fPIE
build/extra/gcc-static-pie/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with gcc/g++ -static -flto
build/extra/gcc-static-lto/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-static-lto/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-static-lto/%: export CC  = gcc -static -flto
build/extra/gcc-static-lto/%: export CXX = g++ -static -flto
build/extra/gcc-static-lto/%: export UPX_CONFIG_DISABLE_SHARED_LIBS = ON

# force building with gcc/g++ C++20 (and C17)
build/extra/gcc-std-cxx20/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-std-cxx20/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-std-cxx20/%: export CC  = gcc -std=gnu17
build/extra/gcc-std-cxx20/%: export CXX = g++ -std=gnu++20
build/extra/gcc-std-cxx20/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/gcc-std-cxx20/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# force building with gcc/g++ C++23 (and C23)
build/extra/gcc-std-cxx23/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-std-cxx23/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-std-cxx23/%: export CC  = gcc -std=gnu2x
build/extra/gcc-std-cxx23/%: export CXX = g++ -std=gnu++2b
build/extra/gcc-std-cxx23/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/gcc-std-cxx23/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# force building with gcc/g++ C++26 (and C23)
build/extra/gcc-std-cxx26/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/gcc-std-cxx26/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/gcc-std-cxx26/%: export CC  = gcc -std=gnu23
build/extra/gcc-std-cxx26/%: export CXX = g++ -std=gnu++26
build/extra/gcc-std-cxx26/%: export UPX_CONFIG_DISABLE_C_STANDARD = ON
build/extra/gcc-std-cxx26/%: export UPX_CONFIG_DISABLE_CXX_STANDARD = ON

# cross compiler: Linux glibc aarch64-linux-gnu (arm64)
build/extra/cross-linux-gnu-aarch64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-linux-gnu-aarch64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-linux-gnu-aarch64/%: export CC  = aarch64-linux-gnu-gcc
build/extra/cross-linux-gnu-aarch64/%: export CXX = aarch64-linux-gnu-g++
build/extra/cross-linux-gnu-aarch64/%: CMAKE_SYSTEM_NAME ?= Linux
build/extra/cross-linux-gnu-aarch64/%: CMAKE_CROSSCOMPILING_EMULATOR ?= qemu-aarch64

# cross compiler: Linux glibc arm-linux-gnueabihf
build/extra/cross-linux-gnu-arm-eabihf/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-linux-gnu-arm-eabihf/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-linux-gnu-arm-eabihf/%: export CC  = arm-linux-gnueabihf-gcc
build/extra/cross-linux-gnu-arm-eabihf/%: export CXX = arm-linux-gnueabihf-g++ -Wno-psabi
build/extra/cross-linux-gnu-arm-eabihf/%: CMAKE_SYSTEM_NAME ?= Linux
build/extra/cross-linux-gnu-arm-eabihf/%: CMAKE_CROSSCOMPILING_EMULATOR ?= qemu-arm

# cross compiler: Windows x86 win32 MinGW (i386)
build/extra/cross-windows-mingw32/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-windows-mingw32/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-windows-mingw32/%: export CC  = i686-w64-mingw32-gcc -static -D_WIN32_WINNT=0x0501
build/extra/cross-windows-mingw32/%: export CXX = i686-w64-mingw32-g++ -static -D_WIN32_WINNT=0x0501
build/extra/cross-windows-mingw32/%: CMAKE_SYSTEM_NAME ?= Windows
build/extra/cross-windows-mingw32/%: CMAKE_SYSTEM_PROCESSOR ?= X86
build/extra/cross-windows-mingw32/%: CMAKE_CROSSCOMPILING_EMULATOR ?= wine

# cross compiler: Windows x64 win64 MinGW (amd64)
build/extra/cross-windows-mingw64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-windows-mingw64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-windows-mingw64/%: export CC  = x86_64-w64-mingw32-gcc -static -D_WIN32_WINNT=0x0501
build/extra/cross-windows-mingw64/%: export CXX = x86_64-w64-mingw32-g++ -static -D_WIN32_WINNT=0x0501
build/extra/cross-windows-mingw64/%: CMAKE_SYSTEM_NAME ?= Windows
build/extra/cross-windows-mingw64/%: CMAKE_SYSTEM_PROCESSOR ?= AMD64
build/extra/cross-windows-mingw64/%: CMAKE_CROSSCOMPILING_EMULATOR ?= wine

# cross compiler: macOS arm64 (aarch64)
build/extra/cross-darwin-arm64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-darwin-arm64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-darwin-arm64/%: export CC  = clang   -target arm64-apple-darwin
build/extra/cross-darwin-arm64/%: export CXX = clang++ -target arm64-apple-darwin
build/extra/cross-darwin-arm64/%: CMAKE_SYSTEM_NAME ?= Darwin
build/extra/cross-darwin-arm64/%: CMAKE_SYSTEM_PROCESSOR ?= arm64

# cross compiler: macOS x86_64 (amd64)
build/extra/cross-darwin-x86_64/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/extra/cross-darwin-x86_64/release: PHONY; $(call run_config_and_build,$@,Release)
build/extra/cross-darwin-x86_64/%: export CC  = clang   -target x86_64-apple-darwin
build/extra/cross-darwin-x86_64/%: export CXX = clang++ -target x86_64-apple-darwin
build/extra/cross-darwin-x86_64/%: CMAKE_SYSTEM_NAME ?= Darwin
build/extra/cross-darwin-x86_64/%: CMAKE_SYSTEM_PROCESSOR ?= x86_64

#***********************************************************************
# C/C++ static analyzers
#***********************************************************************

# force building with clang Static Analyzer (scan-build)
SCAN_BUILD = scan-build
build/analyze/clang-analyzer/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/analyze/clang-analyzer/release: PHONY; $(call run_config_and_build,$@,Release)
build/analyze/clang-analyzer/%: override CMAKE := $(SCAN_BUILD) $(CMAKE)
build/analyze/clang-analyzer/%: export CCC_CC  ?= clang
build/analyze/clang-analyzer/%: export CCC_CXX ?= clang++

# run clang-tidy: uses file compile_commands.json from an existing clang build;
#   does not create any actual files, so purely PHONY
CLANG_TIDY_BUILD_BASE = build/extra/clang
RUN_CLANG_TIDY = time python3 ./misc/analyze/clang-tidy/run-clang-tidy.py -p "$<"
RUN_CLANG_TIDY_WERROR = $(RUN_CLANG_TIDY) '-warnings-as-errors=*'
build/analyze/clang-tidy-upx/debug build/analyze/clang-tidy-upx/release: $$(CLANG_TIDY_BUILD_BASE)/$$(notdir $$@) PHONY
	$(RUN_CLANG_TIDY_WERROR) -config-file ./.clang-tidy '/src/.*\.cpp'
build/analyze/clang-tidy-bzip2/debug build/analyze/clang-tidy-bzip2/release: $$(CLANG_TIDY_BUILD_BASE)/$$(notdir $$@) PHONY
	$(RUN_CLANG_TIDY)        -config-file ./misc/analyze/clang-tidy/clang-tidy-bzip2.yml /vendor/bzip2/
build/analyze/clang-tidy-ucl/debug build/analyze/clang-tidy-ucl/release: $$(CLANG_TIDY_BUILD_BASE)/$$(notdir $$@) PHONY
	$(RUN_CLANG_TIDY_WERROR) -config-file ./misc/analyze/clang-tidy/clang-tidy-ucl.yml   /vendor/ucl/
build/analyze/clang-tidy-zlib/debug build/analyze/clang-tidy-zlib/release: $$(CLANG_TIDY_BUILD_BASE)/$$(notdir $$@) PHONY
	$(RUN_CLANG_TIDY)        -config-file ./misc/analyze/clang-tidy/clang-tidy-zlib.yml  /vendor/zlib/
build/analyze/clang-tidy-zstd/debug build/analyze/clang-tidy-zstd/release: $$(CLANG_TIDY_BUILD_BASE)/$$(notdir $$@) PHONY
	$(RUN_CLANG_TIDY)        -config-file ./misc/analyze/clang-tidy/clang-tidy-zstd.yml  /vendor/zstd/
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: build/analyze/clang-tidy-upx/$$(notdir $$@)
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: build/analyze/clang-tidy-bzip2/$$(notdir $$@)
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: build/analyze/clang-tidy-ucl/$$(notdir $$@)
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: build/analyze/clang-tidy-zlib/$$(notdir $$@)
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: build/analyze/clang-tidy-zstd/$$(notdir $$@)
build/analyze/clang-tidy/debug build/analyze/clang-tidy/release: PHONY

# OLD names [deprecated]
build/extra/scan-build/debug:   build/analyze/clang-analyzer/debug PHONY
build/extra/scan-build/release: build/analyze/clang-analyzer/release PHONY

#***********************************************************************
# advanced: generic eXtra target
#***********************************************************************

# usage:
#   make UPX_XTARGET=my-target CC="my-cc -flags" CXX="my-cxx -flags"
#   make UPX_XTARGET=my-target CC="my-cc -flags" CXX="my-cxx -flags" xtarget/debug

ifneq ($(UPX_XTARGET),)
ifneq ($(CC),)
ifneq ($(CXX),)

UPX_XTARGET := $(UPX_XTARGET)
build/$(UPX_XTARGET)/debug:   PHONY; $(call run_config_and_build,$@,Debug)
build/$(UPX_XTARGET)/release: PHONY; $(call run_config_and_build,$@,Release)
build/$(UPX_XTARGET)/%: export CC  := $(CC)
build/$(UPX_XTARGET)/%: export CXX := $(CXX)
# shortcuts
xtarget/debug:   build/$(UPX_XTARGET)/debug PHONY
xtarget/release: build/$(UPX_XTARGET)/release PHONY
xtarget/all:     xtarget/debug xtarget/release PHONY
xtarget/debug+test:   build/$(UPX_XTARGET)/debug+test PHONY
xtarget/release+test: build/$(UPX_XTARGET)/release+test PHONY
xtarget/all+test:     xtarget/debug+test xtarget/release+test PHONY
# set new default
.DEFAULT_GOAL := build/$(UPX_XTARGET)/release

endif
endif
endif

#***********************************************************************
# assemble cmake config flags; useful for CI jobs
#
# info: by default CMake only honors the CC and CXX environment variables; make
# it easy to set other variables like CMAKE_AR or CMAKE_RANLIB
#***********************************************************************

UPX_CMAKE_CONFIG_FLAGS += $(UPX_CMAKE_CONFIG_FLAGS_GENERATOR)
UPX_CMAKE_CONFIG_FLAGS += $(UPX_CMAKE_CONFIG_FLAGS_TOOLSET)
UPX_CMAKE_CONFIG_FLAGS += $(UPX_CMAKE_CONFIG_FLAGS_PLATFORM)

$(call check_undefined,__add_cmake_config)
# promote an environment or Make variable to a CMake cache entry:
__add_cmake_config = $(and $($1),-D$1="$($1)")

# pass common CMake settings
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_INSTALL_PREFIX)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_VERBOSE_MAKEFILE)
# pass common CMake toolchain settings
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_ADDR2LINE)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_AR)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_DLLTOOL)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_LINKER)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_NM)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_OBJCOPY)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_OBJDUMP)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_RANLIB)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_READELF)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_STRIP)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_TAPI)
# pass common CMake LTO toolchain settings
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_C_COMPILER_AR)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_C_COMPILER_RANLIB)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_CXX_COMPILER_AR)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_CXX_COMPILER_RANLIB)
# pass common CMake cross compilation settings
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_SYSTEM_NAME)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_SYSTEM_PROCESSOR)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,CMAKE_CROSSCOMPILING_EMULATOR)
# pass UPX config options; see CMakeLists.txt
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_GITREV)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_SANITIZE)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_WERROR)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_WSTRICT)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_SELF_PACK_TEST)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_DISABLE_EXHAUSTIVE_TESTS)
# pass UPX extra compile options; see CMakeLists.txt
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_EXTRA_COMPILE_OPTIONS_BZIP2)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_EXTRA_COMPILE_OPTIONS_UCL)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_EXTRA_COMPILE_OPTIONS_UPX)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_EXTRA_COMPILE_OPTIONS_ZLIB)
UPX_CMAKE_CONFIG_FLAGS += $(call __add_cmake_config,UPX_CONFIG_EXTRA_COMPILE_OPTIONS_ZSTD)

#***********************************************************************
# check git submodules
#***********************************************************************

SUBMODULES = doctest lzma-sdk ucl valgrind zlib

$(foreach 1,$(SUBMODULES),$(if $(wildcard vendor/$1/[CL]*),,\
  $(error ERROR: missing git submodule '$1'; run 'git submodule update --init')))

endif # UPX_MAKEFILE_EXTRA_MK_INCLUDED

# vim:set ts=8 sw=8 noet:
