# This Makefile can be used with GNU Make or BSD Make

LIB=libml-dsa-44_clean.a
HEADERS=api.h ntt.h packing.h params.h poly.h polyvec.h reduce.h rounding.h sign.h symmetric.h 
OBJECTS=ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o 

CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../../common $(EXTRAFLAGS)

COMMON_PATH = ../../../common


all: $(LIB)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)


pqc_cli: pqc_cli.c ntt.c packing.c poly.c polyvec.c reduce.c rounding.c sign.c symmetric-shake.c $(COMMON_PATH)/fips202.c \
	$(COMMON_PATH)/randombytes.c
	$(CC) -O3 -Wall -std=c99 -I. -I$(COMMON_PATH) -o $@ $^

test_bench_dsa: test_bench_dsa.c ntt.c packing.c poly.c polyvec.c reduce.c rounding.c sign.c symmetric-shake.c $(COMMON_PATH)/fips202.c \
	$(COMMON_PATH)/randombytes.c
	$(CC) -O3 -Wall -std=c99 -I. -I$(COMMON_PATH) -o $@ $^

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
