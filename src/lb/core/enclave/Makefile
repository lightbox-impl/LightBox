######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

######## Enclave Settings ########
Enclave_Version_Script := ./Enclave_debug.lds
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	# Choose to use 'Enclave.lds' for HW release mode
	Enclave_Version_Script = ./Enclave.lds 
endif
endif
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := crypto_t.c etap_send.c etap_t.c poll.c rx_ring_opt.c state_mgmt_t.c lb_utils_t.c cuckoo/cuckoo_hash.c cuckoo/lookup3.c
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

LB_Root_Dir := ../../../..
Enclave_Include := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -Iinclude -I$(LB_Root_Dir)/include
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include)

### LightBox switches ###
LightBox ?= 1
CAIDA ?= 1
LIVE ?= 0
MICRO ?= 0
CONNECTION ?= 0

Enclave_C_Flags += -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DCAIDA=$(CAIDA) -DLIVE=$(LIVE) -DMICRO=$(MICRO)

Target := lb_core
Enclave_Lib := $(LB_Root_Dir)/build/lib$(Target)_t.a
Enclave_EDL = ./$(Target)_edge.edl
Edge_File := ./$(Target)_edge_t.c
Edge_Object := ./$(Target)_edge_t.o

all: $(Enclave_Lib)

######## Enclave Objects ########
 
$(Edge_File): $(SGX_EDGER8R) $(Enclave_EDL)
	@$(SGX_EDGER8R) --trusted $(Enclave_EDL) 
	@echo "GEN  =>  $@"

$(Edge_Object): $(Edge_File)
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_C_Objects):  %.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Lib): $(Edge_Object) $(Enclave_C_Objects) 
	@ar crs -o $(Enclave_Lib) $(Edge_Object) $(Enclave_C_Objects)
	@echo "AR =>  $@"
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else ifeq ($(Build_Mode), HW_RELEASE)
	@echo "The project has been built in release hardware mode."
else
	@echo "The project has been built in release simulation mode."
endif
ifeq ($(LightBox), 1)
	@echo "*************************************************"
	@echo "************LightBox is enabled!*****************"
	@echo "*************************************************"
endif
ifeq ($(CAIDA), 1)
	@echo "*************************************************"
	@echo "*************CAIDA mode is enabled!**************"
	@echo "*************************************************"
endif
ifeq ($(LIVE), 1)
	@echo "*************************************************"
	@echo "*************LIVE mode is enabled!***************"
	@echo "*************************************************"
endif
ifeq ($(MICRO), 1)
	@echo "*************************************************"
	@echo "*************MICRO mode is enabled!**************"
	@echo "*************************************************"
endif
ifeq ($(CONNECTION), 1)
	@echo "*************************************************"
	@echo "****CONNECTION mode is enabled! (PRADS only)*****"
	@echo "*************************************************"
endif

.PHONY: clean

clean:
	@rm -f $(Enclave_Lib) $(Enclave_C_Objects) ./$(Target)_edge_*

