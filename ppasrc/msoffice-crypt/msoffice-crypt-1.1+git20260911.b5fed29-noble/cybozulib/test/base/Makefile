include ../../common.mk

TARGET=$(TEST_FILE)
#LIBS=$(TOPDIR)lib/libcybozu_base$(OBJSUF).a
LIBS=

SRC=$(wildcard *.cpp)
ifneq ($(HAS_BOOST),1)
	SRC:=$(filter-out regex_test.cpp,$(SRC))
endif
#ifneq ($(HAS_MECAB),1)
	SRC:=$(filter-out mecab_test.cpp,$(SRC))
#endif
ifeq ($(TRAVIS_TEST),1)
	SRC:=$(filter-out env_test.cpp,$(SRC))
	SRC:=$(filter-out fmindex_test.cpp,$(SRC))
	SRC:=$(filter-out mmap_test.cpp,$(SRC))
	SRC:=$(filter-out minixml_test.cpp,$(SRC))
	SRC:=$(filter-out zlib_test.cpp,$(SRC))
endif

all: $(TARGET)

test: $(TARGET)
	@$(UNIT_TEST)

$(OBJDIR):
	@$(MKDIR) $(OBJDIR)

clean:
	$(CLEAN)

$(LIBS):
	$(MAKE) -C ../../src

-include $(DEPEND_FILE)

