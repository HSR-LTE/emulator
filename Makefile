CC      := gcc
RM      := rm -f
CFLAGS  := -O3 -Wall

COMMA   := ,
define NEWLINE


endef

RULES   := \
	bin/client,endpoints/client.c,endpoints/common.h \
	bin/server,endpoints/server.c,endpoints/common.h \
	bin/router,src/main.c,src/list.h
TRAGETS :=

define c-target
TARGETS += $(word 1,$1)
$(word 1,$1): $(wordlist 2,$(words $1),$1)
	@echo -e '\tCC\t$$@'
	@$(CC) -o $$@ $(CFLAGS) $$<
endef

define rm-one
	@echo -e '\tRM\t$1'
	@$(RM) $1
endef

all: dummy

$(foreach rule,$(RULES),$(eval $(call c-target,$(subst $(COMMA), ,$(rule)))))

dummy: $(TARGETS)

clean:
	$(foreach target,$(TARGETS),$(call rm-one,$(target))$(NEWLINE))
