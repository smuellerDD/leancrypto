KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build

clean-files := lc_kyber_1024.h lc_kyber_768.h lc_kyber_512.h lc_dilithium_87.h lc_dilithium_65.h lc_dilithium_44.h lc_hash.h lc_memory_support.h lc_ascon_hash.h lc_bike_1.h lc_bike_3.h lc_bike_5.h lc_sphincs_shake_256s.h lc_sphincs_shake_256f.h lc_sphincs_shake_192s.h lc_sphincs_shake_192f.h lc_sphincs_shake_128s.h lc_sphincs_shake_128f.h lc_hqc_128.h lc_hqc_192.h lc_hqc_256.h

default: modules
install: modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	@- $(RM) $(leancrypto-y)
	@- $(RM) $(join $(dir $(leancrypto-y)), $(addprefix ., $(notdir $(leancrypto-y:.o=.o.cmd))))
	@- $(RM) $(join $(dir $(leancrypto-y)), $(addprefix ., $(notdir $(leancrypto-y:.o=.o.d))))
	@- $(RM) $(leancrypto_test-y)
	@- $(RM) $(join $(dir $(leancrypto_test-y)), $(addprefix ., $(notdir $(leancrypto_test-y:.o=.o.cmd))))

modules modules_install: ../ml-kem/api/lc_kyber_size.h.in lc_kyber_1024.h.awk lc_kyber_768.h.awk lc_kyber_512.h.awk ../ml-dsa/api/lc_dilithium_size.h.in lc_dilithium_87.h.awk lc_dilithium_65.h.awk lc_dilithium_44.h.awk ../hash/api/lc_hash.h.in lc_hash.h.awk ../internal/api/lc_memory_support.h.in lc_memory_support.awk ../hash/api/lc_ascon_hash.h.in lc_ascon_hash.awk ../bike/api/lc_bike_size.h.in lc_bike_1.h.awk lc_bike_3.h.awk lc_bike_5.h.awk lc_sphincs_shake_256s.h.awk lc_sphincs_shake_256f.h.awk lc_sphincs_shake_192s.h.awk lc_sphincs_shake_192f.h.awk lc_sphincs_shake_128s.h.awk lc_sphincs_shake_128f.h.awk lc_hqc_128.h.awk lc_hqc_192.h.awk lc_hqc_256.h.awk
	awk -f lc_kyber_1024.h.awk ../ml-kem/api/lc_kyber_size.h.in > lc_kyber_1024.h
	awk -f lc_kyber_768.h.awk ../ml-kem/api/lc_kyber_size.h.in > lc_kyber_768.h
	awk -f lc_kyber_512.h.awk ../ml-kem/api/lc_kyber_size.h.in > lc_kyber_512.h
	awk -f lc_dilithium_87.h.awk ../ml-dsa/api/lc_dilithium_size.h.in > lc_dilithium_87.h
	awk -f lc_dilithium_65.h.awk ../ml-dsa/api/lc_dilithium_size.h.in > lc_dilithium_65.h
	awk -f lc_dilithium_44.h.awk ../ml-dsa/api/lc_dilithium_size.h.in > lc_dilithium_44.h
	awk -f lc_hash.h.awk ../hash/api/lc_hash.h.in > lc_hash.h
	awk -f lc_memory_support.awk ../internal/api/lc_memory_support.h.in > lc_memory_support.h
	awk -f lc_ascon_hash.awk ../hash/api/lc_ascon_hash.h.in > lc_ascon_hash.h
	awk -f lc_bike_1.h.awk ../bike/api/lc_bike_size.h.in > lc_bike_1.h
	awk -f lc_bike_3.h.awk ../bike/api/lc_bike_size.h.in > lc_bike_3.h
	awk -f lc_bike_5.h.awk ../bike/api/lc_bike_size.h.in > lc_bike_5.h
	awk -f lc_sphincs_shake_256s.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_256s.h
	awk -f lc_sphincs_shake_256f.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_256f.h
	awk -f lc_sphincs_shake_192s.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_192s.h
	awk -f lc_sphincs_shake_192f.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_192f.h
	awk -f lc_sphincs_shake_128s.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_128s.h
	awk -f lc_sphincs_shake_128f.h.awk ../slh-dsa/api/lc_sphincs_size.h.in > lc_sphincs_shake_128f.h
	awk -f lc_hqc_128.h.awk ../hqc/api/lc_hqc_size.h.in > lc_hqc_128.h
	awk -f lc_hqc_192.h.awk ../hqc/api/lc_hqc_size.h.in > lc_hqc_192.h
	awk -f lc_hqc_256.h.awk ../hqc/api/lc_hqc_size.h.in > lc_hqc_256.h

	# Compile the KO files
	$(MAKE) -C $(KDIR) M=$$PWD $@
