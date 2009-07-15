CC = gcc
RM = rm -rf
DEBUG := yes


COMMONINCLUDES = -I./src


PACINCLUDES += $(COMMONINCLUDES)
PAAINCLUDES += $(COMMONINCLUDES)
LIBPANA_INCLUDES += $(COMMONINCLUDES) -Isrc/eap_peer -Isrc/eap_server

PAC_SRC += src/pana_common/*.c src/pana_pac/*.c
PAC_SRC += src/utils/*.c
PAC_SRC += src/crypto/*.c
PAC_SRC += src/eap_common/*.c src/eap_peer/*.c
PAC_SRC += apps/pacd.c apps/common.c


PAA_SRC += src/pana_common/*.c src/pana_paa/*.c
PAA_SRC += src/utils/*.c
PAA_SRC += src/crypto/*.c
PAA_SRC += src/eap_common/*.c src/eap_server/*.c
PAA_SRC += apps/nasd.c apps/common.c


LIBPANASRC += src/*.c
LIBPANASRC += src/utils/*.c
LIBPANASRC += src/crypto/*.c
LIBPANASRC += src/eap_common/*.c src/eap_server/*.c src/eap_peer/*.c


PAC_OBJ = $(patsubst %.c,%.o,$(wildcard $(PAC_SRC)))
PAC_DEPS = $(patsubst %.c,%.d,$(wildcard $(PAC_SRC)))

PAA_OBJ = $(patsubst %.c,%.o,$(wildcard $(PAA_SRC)))
PAA_DEPS = $(patsubst %.c,%.d,$(wildcard $(PAA_SRC)))

ifeq ($(DEBUG),yes)
%.o: %.c %.h
	$(CC) $(COMMONINCLUDES) -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
else
%.o: %.c %.h
	$(CC) $(COMMONINCLUDES) -c -o"$@" "$<"
endif


all: pacd nasd


pacd: $(PAC_OBJ)
	$(CC) $(PACINCLUDES) $^ -o pacd

nasd: $(PAA_OBJ)
	$(CC) $(PAAINCLUDES) $^ -o nasd


clean:
	-$(RM) $(PAC_OBJ) $(PAC_DEPS)
	-$(RM) $(PAA_OBJ) $(PAA_DEPS)
	-$(RM) pacd nasd

.PHONY: all clean pacd nasd

