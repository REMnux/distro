include ../../common.mk

TARGET=$(TEST_FILE)
#LIBS=$(TOPDIR)lib/libcybozu_base$(OBJSUF).a
LIBS=

SRC=$(wildcard *.cpp)
ifneq ($(HAS_EIGEN),1)
	SRC:=$(filter-out svd_test.cpp,$(SRC))
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

