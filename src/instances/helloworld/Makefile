all:
	cd enclave && make all
	cd host && make all

clean:
	cd enclave && make clean
	cd host && make clean

######## Edl Header #######
edl:untrusted/Enclave_u.c trusted/Enclave_t.c
	cd trusted && make Enclave_t.c
	cd untrusted && make Enclave_u.c
	sz untrusted/Enclave_u.c untrusted/Enclave_u.h trusted/Enclave_t.c trusted/Enclave_t.h

.PHONY: clean
