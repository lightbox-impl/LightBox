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


######## Host Settings ########
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Host_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Host_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Host_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Host_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

LB_Root_Dir := ../../../../..
Enclave_Dir = ../enclave

Host_Include_Paths := -I$(SGX_SDK)/include -I/usr/include -I$(LB_Root_Dir)/include
Host_C_Flags += $(Host_Include_Paths)

Host_C_Files := pcap_u.c $(wildcard bpf/*.c)
Host_C_Objects := $(Host_C_Files:.c=.o)

Target := lb_pcap
Host_Lib := $(LB_Root_Dir)/build/lib$(Target)_u.a
Enclave_EDL = $(Enclave_Dir)/$(Target)_edge.edl
Edge_File := ./$(Target)_edge_u.c
Edge_Object := ./$(Target)_edge_u.o

all: $(Host_Lib)

######## Host Objects ########

$(Edge_File): $(SGX_EDGER8R) $(Enclave_EDL)
	@$(SGX_EDGER8R) --untrusted $(Enclave_EDL) --search-path $(Enclave_Dir) 
	@echo "GEN  =>  $@"

$(Edge_Object): $(Edge_File)
	@$(CC) $(Host_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Host_C_Objects):  %.o: %.c
	@$(CC) $(Host_C_Flags) -c $< -o $@ 
	@echo "CC  <=  $<"

$(Host_Lib): $(Edge_Object) $(Host_C_Objects) 
	@ar crs $(Host_Lib) $(Edge_Object) $(Host_C_Objects)
	@echo "AR =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(Host_Lib) $(Host_C_Objects) ./$(Target)_edge_* 
