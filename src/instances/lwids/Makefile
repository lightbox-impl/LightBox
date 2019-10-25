all:
	cd enclave && make all
	cd host  && make all

clean:
	cd enclave && make clean
	cd host && make clean

######## Edl Header #######
edl:untrusted/Enclave_u.c trusted/Enclave_t.c
	cd enclave && make lwids_edl_t.c
	cd host && make lwids_edl_u.c
	sz host/lwids_edl_u.c host/lwids_edl_u.h enclave/lwids_edl_t.c enclave/lwids_edl.edl_t.h

.PHONY: clean
