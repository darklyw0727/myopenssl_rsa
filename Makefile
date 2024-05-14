CC = gcc
TARGET = demo
SOURCE = myopenssl.c
OBJECT = $(SOURCE:.c=.o)
INCLUDE = -I/usr/include/openssl
LIBS = -lssl -lcrypto

ifdef OPENSSL_DEBUG
CFLAGS += -D_OPENSSL_DEBUG
endif

all: $(TARGET)

demo: demo.o $(OBJECT)
	$(CC) -g -o $@ $^ $(INCLUDE) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

.PHONY : clean all

clean : 
	-rm $(TARGET) *.o *.key