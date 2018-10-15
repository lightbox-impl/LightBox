all:
	cd trusted && make all
	cd untrusted && make all

clean:
	cd trusted && make clean
	cd untrusted && make clean

######## Edl Header #######
edl:untrusted/Enclave_u.c trusted/Enclave_t.c
	cd trusted && make Enclave_t.c
	cd untrusted && make Enclave_u.c
	sz untrusted/Enclave_u.c untrusted/Enclave_u.h trusted/Enclave_t.c trusted/Enclave_t.h

.PHONY: clean