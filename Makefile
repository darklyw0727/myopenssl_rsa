CC = gcc
TARGET = demo str_demo
SOURCE = myopenssl.c b64_crypt.c
OBJECT = $(SOURCE:.c=.o)
INCLUDE = -I/usr/include/openssl
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
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY : clean all

clean : 
	rm $(TARGET) *.o *.key