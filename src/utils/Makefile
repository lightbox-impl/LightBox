all:
	cd enclave && make all
	cd untrusted && make all

clean:
	cd enclave && make clean
	cd untrusted && make clean

######## Edl Header #######
edl:untrusted/Enclave_u.c enclave/Enclave_t.c
	cd enclave && make Enclave_t.c
	cd host && make Enclave_u.c
	sz host/Enclave_u.c host/Enclave_u.h enclave/Enclave_t.c enclave/Enclave_t.h

.PHONY: clean