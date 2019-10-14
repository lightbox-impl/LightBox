######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 0

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

Enclave_Version_Script := $(Enclave_Dir)/Enclave_debug.lds
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


Enclave_Cpp_Files := $(wildcard $(Enclave_Dir)/*.cpp)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o) 
Enclave_Include_Paths := -IInclude -I$(Enclave_Dir) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc 

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++11 -Wno-write-strings

Pcap_Dir := $(Enclave_Dir)
LightBox_Dir := $(Enclave_Dir)
Root_Dir := ../../../../..

LightBox_Include_Paths := -I$(LightBox_Dir) -I$(LightBox_Dir)/cuckoo  -I$(Root_Dir)/include
LightBox_EDL = $(LightBox_Dir)/lb_edge.edl
LightBox_C_Files := $(wildcard $(LightBox_Dir)/*.c) $(wildcard $(LightBox_Dir)/cuckoo/*.c)
LightBox_C_Objects := $(LightBox_C_Files:.c=.o)

LightBox ?= 1
CAIDA ?= 0
LIVE ?= 0
MICRO ?= 0
CONNECTION ?= 0
MSG64 ?= 0

LightBox_FLAGS = -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DCAIDA=$(CAIDA) -DLIVE=$(LIVE) -DMICRO=$(MICRO) -DMSG64=$(MSG64)
LightBox_FLAGS += $(LightBox_Include_Paths)
LightBox_FLAGS += $(Enclave_C_Flags)

Enclave_Name := $(Root_Dir)/build/liblb_pcap_t.a

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

all: $(Enclave_Name)

######## Enclave Objects ########

$(Enclave_Dir)/lb_edge_t.c: $(SGX_EDGER8R) $(LightBox_EDL)
	@cd $(Enclave_Dir) && $(SGX_EDGER8R) --trusted $(LightBox_EDL) --search-path $(Enclave_Dir) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Enclave_Dir)/lb_edge_t.o: $(Enclave_Dir)/lb_edge_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(LightBox_C_Objects):  %.o: %.c
	@$(CC) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): $(Enclave_Dir)/lb_edge_t.o $(LightBox_C_Objects) 
	@ar crs -o $(Enclave_Name) $(LightBox_C_Objects) 
	@echo "AR =>  $@"
#$(Enclave_Dir)/lb_edge_t.o

.PHONY: clean

clean:
	@rm -f $(Enclave_Name) $(LightBox_C_Objects) $(Enclave_Dir)/lb_edge_t.*

