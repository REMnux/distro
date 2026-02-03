#
# UPX top-level Makefile - needs GNU make and CMake >= 3.13
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#

# INFO: this Makefile is just a convenience wrapper for calling CMake

# HINT: if you only have an older CMake 3.x then you can invoke cmake manually like this:
#   mkdir -p build/release
#   cd build/release
#   cmake ../..         # run config
#   make -j4            # and run build

CMAKE = cmake
UPX_CMAKE_BUILD_FLAGS += --parallel
ifneq ($(VERBOSE),)
  #UPX_CMAKE_BUILD_FLAGS += --verbose # requires CMake >= 3.14
  UPX_CMAKE_CONFIG_FLAGS += -DCMAKE_VERBOSE_MAKEFILE=ON
endif
# enable this if you prefer Ninja for the actual builds:
#UPX_CMAKE_CONFIG_FLAGS += -G Ninja

#***********************************************************************
# default
#***********************************************************************

.DEFAULT_GOAL = build/release

.NOTPARALLEL: # because the actual builds use "cmake --parallel"
.PHONY: PHONY
.SECONDEXPANSION:
.SUFFIXES:

run_cmake_config = $(CMAKE) -S . -B "$1" $(UPX_CMAKE_CONFIG_FLAGS) -DCMAKE_BUILD_TYPE="$2"
run_cmake_build  = $(CMAKE) --build "$1" $(UPX_CMAKE_BUILD_FLAGS) --config "$2"
# avoid re-running run_cmake_config if .upx_cmake_config_done.txt already exists
run_config       = $(if $(wildcard $1/CMakeFiles/.*_cmake_config_done.txt),,$(call run_cmake_config,$1,$2))
run_build        = $(call run_cmake_build,$1,$2)

build/debug: PHONY
	$(call run_config,$@,Debug)
	$(call run_build,$@,Debug)

build/release: PHONY
	$(call run_config,$@,Release)
	$(call run_build,$@,Release)

# shortcuts (all => debug + release)
debug:   build/debug PHONY
release: build/release PHONY
all build/all: build/debug build/release PHONY
build/%/all:   $$(dir $$@)debug $$(dir $$@)release PHONY ;

#***********************************************************************
# test
#***********************************************************************

CTEST = ctest
CTEST_JOBS ?= 8
CTEST_FLAGS = --output-on-failure --parallel $(CTEST_JOBS)

build/debug+test:     $$(dir $$@)debug PHONY; cd "$(dir $@)debug" && $(CTEST) $(CTEST_FLAGS) -C Debug
build/%/debug+test:   $$(dir $$@)debug PHONY; cd "$(dir $@)debug" && $(CTEST) $(CTEST_FLAGS) -C Debug
build/release+test:   $$(dir $$@)release PHONY; cd "$(dir $@)release" && $(CTEST) $(CTEST_FLAGS) -C Release
build/%/release+test: $$(dir $$@)release PHONY; cd "$(dir $@)release" && $(CTEST) $(CTEST_FLAGS) -C Release
build/%/all+test:     $$(dir $$@)debug+test $$(dir $$@)release+test PHONY ;

# shortcuts
debug+test:   build/debug+test PHONY
release+test: build/release+test PHONY
all+test build/all+test: build/debug+test build/release+test PHONY

test: $$(patsubst %+test,%,$$(.DEFAULT_GOAL))+test PHONY

#***********************************************************************
# install
#***********************************************************************

build/debug+install:     $$(dir $$@)debug PHONY; cd "$(dir $@)debug" && $(CMAKE) --install . --config Debug
build/%/debug+install:   $$(dir $$@)debug PHONY; cd "$(dir $@)debug" && $(CMAKE) --install . --config Debug
build/release+install:   $$(dir $$@)release PHONY; cd "$(dir $@)release" && $(CMAKE) --install . --config Release
build/%/release+install: $$(dir $$@)release PHONY; cd "$(dir $@)release" && $(CMAKE) --install . --config Release
build/%/all+install:     $$(dir $$@)debug+install $$(dir $$@)release+install PHONY ;

# shortcuts
debug+install:   build/debug+install PHONY
release+install: build/release+install PHONY
all+install build/all+install: build/debug+install build/release+install PHONY

install: $$(patsubst %+install,%,$$(.DEFAULT_GOAL))+install PHONY

#***********************************************************************
# END of Makefile
#***********************************************************************

# extra pre-defined build configurations and some utility; optional
-include ./Makevars-local.mk
-include ./misc/make/Makefile-extra.mk

# developer convenience
ifneq ($(wildcard /usr/bin/env),) # need Unix utils like bash, perl, sed, xargs, etc.
ifneq ($(and $(wildcard ./misc/scripts/.),$(wildcard ./doc/upx.pod)),)
check-whitespace clang-format run-testsuite run-testsuite-all run-testsuite-debug run-testsuite-release: src/Makefile PHONY
	$(MAKE) -C src $@
endif
endif

# vim:set ts=8 sw=8 noet:
