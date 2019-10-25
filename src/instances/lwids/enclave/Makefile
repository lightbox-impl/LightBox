######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
LightBox ?=1
CAIDA ?= 1
CONNECTION ?= 0

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

######## Enclave Settings ########

Enclave_Dir = .

Enclave_Version_Script := $(Enclave_Dir)/Enclave.lds
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	# Choose to use 'Enclave.lds' for HW release mode
	Enclave_Version_Script = $(Enclave_Dir)/Enclave.lds 
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



Root_Dir := ../../../..
LightBox_Dir := $(Root_Dir)/src/lb/core
LightBox_Include := -I$(LightBox_Dir)/enclave  -I$(LightBox_Dir)/../ -I$(Root_Dir)/include
LightBox_Lib := $(Root_Dir)/build/liblb_core_t.a
LightBox_Flag := -DLightBox=${LightBox} -DCAIDA=$(CAIDA) -DUSE_ETAP -DMSG64=0  -DCONNECTION=$(CONNECTION)
Build_Lib_Dir := $(Root_Dir)/build
Trusted_Lib_Dir := $(Root_Dir)/trusted_lib


Enclave_Cpp_Files := $(wildcard $(Enclave_Dir)/*.c)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.c=.o) 
Enclave_Include_Paths := -IInclude -I$(Enclave_Dir) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(Enclave_Dir)/src/include -I$(Enclave_Dir)/src/include/sgx   $(LightBox_Include) -I/usr/include -I../ -I$(LightBox_Dir) -I$(LightBox_Dir)/.. -I../../../../include 

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) $(LightBox_Flag)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++11 -Wno-write-strings $(LightBox_Flag)




# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) \
	 $(LightBox_Lib) $(Build_Lib_Dir)/liblb_ntoh_t.a $(Trusted_Lib_Dir)/libpcre.a\
	 -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(Enclave_Version_Script)


Enclave_Name := ../enclave.so
Signed_Enclave_Name := ../enclave.signed.so
Enclave_Config_File := $(Enclave_Dir)/Enclave.config.xml

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

all: $(Signed_Enclave_Name)
	@echo "LightBox = ${LightBox}"

######## Enclave Objects ########

$(Enclave_Dir)/lwids_edl_t.c: $(SGX_EDGER8R) $(Enclave_Dir)/lwids_edl.edl
	@cd $(Enclave_Dir) && $(SGX_EDGER8R) --trusted ../enclave/lwids_edl.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Enclave_Dir)/lwids_edl_t.o: $(Enclave_Dir)/lwids_edl_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Dir)/%.o: $(Enclave_Dir)/%.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): $(Enclave_Dir)/lwids_edl_t.o $(Enclave_Cpp_Objects)  
	@$(CC) $^ -o $@ $(Enclave_Link_Flags) 
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Dir)/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean edl

clean:
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) $(Enclave_Dir)/lwids_edl_t.*  
