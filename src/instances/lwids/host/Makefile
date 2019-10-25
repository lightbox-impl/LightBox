######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
LightBox ?= 1
CONNECTION ?= 0
MSG64 ?= 0
CAIDA ?= 1

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


######## App Settings ########

App_Dir = .

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Root_Dir := ../../../..
LightBox_Dir := $(Root_Dir)/src/lb/core
LightBox_Include := -I$(LightBox_Dir)/host -I$(LightBox_Dir)/../ -I$(Root_Dir)/include -I$(LightBox_Dir)/host/include -I$(LightBox_Dir)
LightBox_Flag := -DUSE_ETAP -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DCAIDA=$(CAIDA) -DMSG64=$(MSG64)
LightBox_Lib := $(Root_Dir)/build/liblb_core_u.a

App_C_Files := $(wildcard $(App_Dir)/*.c)
App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) $(LightBox_Include) $(LightBox_Flag) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -Wno-delete-incomplete
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread $(LightBox_Lib)

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_C_Objects := $(App_C_Files:.c=.o)

App_Name := ../app

App_Link_Flags +=  -L.. -Llib -lpcap -lpthread 


all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name)
	@echo "LightBox = ${LightBox}"


######## App Objects ########

$(App_Dir)/lwids_edl_u.c: $(SGX_EDGER8R) ../enclave/lwids_edl.edl
	@cd $(App_Dir) && $(SGX_EDGER8R) --untrusted ../enclave/lwids_edl.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_Dir)/lwids_edl_u.o: $(App_Dir)/lwids_edl_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Dir)/%.o: $(App_Dir)/%.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): $(App_Dir)/lwids_edl_u.o $(App_C_Objects) 
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH): ../enclave.signed.so
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) $(App_Dir)/lwids_edl_u.* $(Enclave_Cpp_Objects) $(Enclave_Ntoh_C_Objects) trusted/lwids_edl_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)
	
.PHONY: clean edl

clean:
	@rm -f .config_* $(App_Name) $(App_C_Objects) $(App_Dir)/lwids_edl_u.* 
