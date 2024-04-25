CC = gcc
TARGET = demo str_demo
SOURCE = myopenssl.c demo_include/b64_codec.c
OBJECT = $(SOURCE:.c=.o)
INCLUDE = -I/usr/include/openssl -I./demo_include
LIBS = -lssl -lcrypto

ifdef OPENSSL_DEBUG
CFLAGS += -D_OPENSSL_DEBUG
endif

ifdef B64_DEBUG
CFLAGS += -D_B64_DEBUG
endif

all: $(TARGET)

demo: demo.o $(OBJECT)
	$(CC) -o $@ $^ $(INCLUDE) $(LIBS)

str_demo: str_demo.o $(OBJECT)
	$(CC) -o $@ $^ $(INCLUDE) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

.PHONY : clean all

clean : 
	-rm $(TARGET) $(OBJECT) *.o *.key