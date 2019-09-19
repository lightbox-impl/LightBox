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


######## App Settings ########


ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Include_Paths := -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

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


# LightBox ?= 0
# CAIDA ?= 0
# CONNECTION ?= 0
# MSG64 ?= 0

Enclave_Dir = ../enclave
App_Dir = .
Root_Dir := ../../..

LightBox_Include_Paths := -I$(App_Dir) -I../.. -Iinclude -I$(Root_Dir)/include

# LightBox_FLAGS = -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DCAIDA=$(CAIDA) -DMSG64=$(MSG64)
LightBox_FLAGS = $(LightBox_Include_Paths)
LightBox_FLAGS += $(App_C_Flags)

LightBox_EDL = $(Enclave_Dir)/lb_edge.edl
LightBox_C_Files := $(wildcard $(App_Dir)/*.c)
LightBox_C_Objects := $(LightBox_C_Files:.c=.o)


App_Name := ../liblb_core_u.a

all: $(App_Name)

######## App Objects ########

$(App_Dir)/lb_edge_u.c: $(SGX_EDGER8R) $(LightBox_EDL)
	@cd $(App_Dir) && $(SGX_EDGER8R) --untrusted $(LightBox_EDL) --search-path $(Enclave_Dir) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_Dir)/lb_edge_u.o: $(App_Dir)/lb_edge_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(LightBox_C_Objects):  %.o: %.c
	@$(CC) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): $(App_Dir)/lb_edge_u.o $(LightBox_C_Objects) 
	@ar crs $(App_Name) $(LightBox_C_Objects) 
	@echo "AR =>  $@"
# $(App_Dir)/lb_edge_u.o

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(LightBox_C_Objects) $(App_Dir)/lb_edge_u.* 
