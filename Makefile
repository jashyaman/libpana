CC = gcc
RM = rm -rf

COMMONINCLUDES = -I./src


PACINCLUDES += $(COMMONINCLUDES)
PAAINCLUDES += $(COMMONINCLUDES)
LIBPANA_INCLUDES += $(COMMONINCLUDES) -Isrc/eap_peer -Isrc/eap_server

PAC_SRC += src/*.c
PAC_SRC += src/utils/*.c
PAC_SRC += src/crypto/*.c
PAC_SRC += src/eap_common/*.c src/eap_peer/*.c
PAC_SRC += apps/pacd.c apps/common.c

PAA_SRC += src/*.c
PAA_SRC += src/utils/*.c
PAA_SRC += src/crypto/*.c
PAA_SRC += src/eap_common/*.c src/eap_server/*.c
PAA_SRC += apps/nasd.c apps/common.c


LIBPANASRC += src/*.c
LIBPANASRC += src/utils/*.c
LIBPANASRC += src/crypto/*.c
LIBPANASRC += src/eap_common/*.c src/eap_server/*.c src/eap_peer/*.c

all: pacd nasd

pacd: $(PAC_SRC)
	$(CC) $(PACINCLUDES) $(PAC_SRC) -o pacd

nasd: $(PAA_SRC)
	$(CC) $(PACINCLUDES) $(PAC_SRC) -o nasd

clean:
	$(RM) *.o pacd nasd

.PHONY: all clean pacd nasd

