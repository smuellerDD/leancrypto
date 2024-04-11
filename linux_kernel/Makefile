include Kbuild

KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build

clean-files := lc_kyber.h lc_dilithium.h

default: modules
install: modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	@- $(RM) $(leancrypto-y)
	@- $(RM) $(join $(dir $(leancrypto-y)), $(addprefix ., $(notdir $(leancrypto-y:.o=.o.cmd))))
	@- $(RM) $(join $(dir $(leancrypto-y)), $(addprefix ., $(notdir $(leancrypto-y:.o=.o.d))))
	@- $(RM) $(leancrypto_test-y)
	@- $(RM) $(join $(dir $(leancrypto_test-y)), $(addprefix ., $(notdir $(leancrypto_test-y:.o=.o.cmd))))

modules modules_install: ../kem/api/lc_kyber.h.in lc_kyber.h.awk ../signature/api/lc_dilithium.h.in lc_dilithium.h.awk ../hash/api/lc_hash.h.in lc_hash.h.awk ../internal/api/lc_memory_support.h.in lc_memory_support.awk ../hash/api/lc_ascon_hash.h.in lc_ascon_hash.awk
	awk -f lc_kyber.h.awk ../kem/api/lc_kyber.h.in > lc_kyber.h
	awk -f lc_dilithium.h.awk ../signature/api/lc_dilithium.h.in > lc_dilithium.h
	awk -f lc_hash.h.awk ../hash/api/lc_hash.h.in > lc_hash.h
	awk -f lc_memory_support.awk ../internal/api/lc_memory_support.h.in > lc_memory_support.h
	awk -f lc_ascon_hash.awk ../hash/api/lc_ascon_hash.h.in > lc_ascon_hash.h
	$(MAKE) -C $(KDIR) M=$$PWD $@
