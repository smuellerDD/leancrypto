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

modules modules_install: ../kem/api/lc_kyber.h.in lc_kyber.h.awk ../signature/api/lc_dilithium.h.in lc_dilithium.h.awk
	awk -f lc_kyber.h.awk ../kem/api/lc_kyber.h.in > lc_kyber.h
	awk -f lc_dilithium.h.awk ../signature/api/lc_dilithium.h.in > lc_dilithium.h
	$(MAKE) -C $(KDIR) M=$$PWD $@
