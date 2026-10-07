include ../../common.mk

#TARGET=../../lib/libcybozu_base$(OBJSUF).a
TARGET=
SRC=

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) $@ $(OBJS)

$(OBJDIR):
	@$(MKDIR) $(OBJDIR)

clean:
	$(CLEAN)

-include $(DEPEND_FILE)

