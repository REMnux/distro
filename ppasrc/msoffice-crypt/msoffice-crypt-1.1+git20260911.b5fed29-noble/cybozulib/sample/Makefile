include ../common.mk

TARGET=$(TEST_FILE)
LIBS=

SRC=$(wildcard *smpl.cpp)
ifneq ($(HAS_EIGEN),1)
	SRC:=$(filter-out svd_bench_smpl.cpp,$(SRC))
	SRC:=$(filter-out svd_smpl.cpp,$(SRC))
endif
ifneq ($(HAS_MECAB),1)
	SRC:=$(filter-out mecab_smpl.cpp,$(SRC))
endif

all: $(TARGET)

test: $(TARGET)
	@$(SAMPLE_TEST)

$(OBJDIR):
	@$(MKDIR) $(OBJDIR)

clean:
	$(CLEAN)

$(LIBS):
	$(MAKE) -C ../src

-include $(DEPEND_FILE)

