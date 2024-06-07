ifeq ("$(ROOT_PATH)","")
ROOT_PATH=$(shell pwd | sed 's/\/common.*//')
endif

include $(ROOT_PATH)/build/build-include.mk

OBJS = myopenssl.o

SHARE_LIB = libopensslrsa.so
STATIC_LIB = libopensslrsa.a

LD_FLAGS = $(OPENSSL_LIB)

CFLAGS += -Os -Wall -Werror -fPIC

ifdef OPENSSL_DEBUG
CFLAGS += -D_OPENSSL_DEBUG
endif

ARFLAGS = -c -r

.PHONY: clean install

all: $(SHARE_LIB) $(STATIC_LIB)

$(PROJECT): $(PRJOBJS)
	@echo " LD     $@"
	@$(CC) $(PRJLDFLAGS) -o $@ $(PRJOBJS)
	@echo " STRIP  $@"
	@$(STRIP) $@

$(SHARE_LIB): $(OBJS)
	@echo " LD	$@ $^"
	@$(CC) -Werror -shared -Wl,--whole-archive,-soname,$@ -o $@ $^ -Wl,--no-whole-archive $(LD_FLAGS)

$(STATIC_LIB): $(OBJS)
	@echo " AR	$@ $^"
	@$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	@echo " CC	$@"
	@$(CC) $(CFLAGS) -g -c -o $@ $^

clean:
	$(RM) *.o $(SHARE_LIB) $(STATIC_LIB) $(PROJECT)

install: all
	cp -af $(SHARE_LIB) $(LIB_FOLDER)
