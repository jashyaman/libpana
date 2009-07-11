CC = gcc
RM = rm -rf

COMMONINCLUDES = -I./src


PACINCLUDES += $(COMMONINCLUDES) -Isrc/apps
PAAINCLUDES += $(COMMONINCLUDES) -Isrc/apps
LIBPANA_INCLUDES += $(COMMONINCLUDES) -Isrc/eap_peer -Isrc/eap_server

PAC_SRC += src/*.c
PAC_SRC += src/utils/*.c
PAC_SRC += src/crypto/*.c
PAC_SRC += src/eap_common/*.c src/eap_peer/*.c
PAC_SRC += apps/pacd.c

PAA_SRC += src/*.c
PAA_SRC += src/utils/*.c
PAA_SRC += src/crypto/*.c
PAA_SRC += src/eap_common/*.c src/eap_server/*.c
PAA_SRC += apps/nasd.c


LIBPANASRC += src/*.c
LIBPANASRC += src/utils/*.c
LIBPANASRC += src/crypto/*.c
LIBPANASRC += src/eap_common/*.c src/eap_server/*.c src/eap_peer/*.c

all: pacd nasd

pacd: $(PAC_SRC)
	$(CC) $(PACINCLUDES) $(PAC_SRC)

nasd: $(PAA_SRC)
	$(CC) $(PACINCLUDES) $(PAC_SRC)

clean:
	$(RM) *.o

.PHONY: all clean pacd nasd

