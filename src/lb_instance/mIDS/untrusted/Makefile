######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
# LightBox ?= 1
# CAIDA ?= 0

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

LightBox_Dir := ../../../../src/lb_core
Root_Dir := ../../../..
LightBox_Include := -I$(LightBox_Dir)/host -I$(LightBox_Dir)/../ -I$(Root_Dir)/include
LightBox_Flag := -DUSE_ETAP 
# -DLightBox=$(LightBox) -DCAIDA=$(CAIDA) 
LightBox_Lib := $(LightBox_Dir)/liblb_core_u.a


App_Cpp_Files := $(wildcard $(App_Dir)/*.cpp)
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

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := ../app

MOS_C_Flags = -m64 -Wall -fgnu89-inline
MOS_C_Flags += -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR #-DNDEBUG -O3 
MOS_C_Flags += -L.. -lmtcp -lpcap -lpthread -lnuma
MOS_C_Flags += -D__thread="" -DBE_RESILIENT_TO_PACKET_DROP
MOS_C_Flags += -DENABLE_PCAP

MOS_C_Include := -I$(App_Dir)/include -I$(SGX_SDK)/include

#BPF_C_Dir := ./bpf
#BPF_C_Include := $(BPF_C_Dir)/include
#BPF_C_Files := 	$(BPF_C_Dir)/sf_bpf_filter.c $(BPF_C_Dir)/sfbpf-int.c $(BPF_C_Dir)/sf_gencode.c $(BPF_C_Dir)/sf_grammar.c \
#	$(BPF_C_Dir)/sf_nametoaddr.c $(BPF_C_Dir)/sf_optimize.c $(BPF_C_Dir)/sf_scanner.c
#BPF_C_Flags := -g -O3 -I$(BPF_C_Include)


MOS_C_Objs = $(patsubst %.c,%.o,$(MOS_C_Files))

DFC_Cpp_Files := $(wildcard $(App_Dir)/dfc/*.cpp)
DFC_Cpp_Objects = $(DFC_Cpp_Files:.cpp=.o) 

MOS_Lib := ../../../lb_networking/libmOS/liblb_mos_u.a
Pcap_Lib := ../../../lb_networking/libpcap/liblb_pcap_u.a #../../../lb_networking/libpcap/untrusted/libbpf.a


App_Link_Flags += $(MOS_Lib) -L.. -Llib -lmtcp_org -lpcap -lpthread -lnuma $(Pcap_Lib)


all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name)
	@echo "LightBox = ${LightBox}"


######## App Objects ########

$(App_Dir)/Enclave_u.c: $(SGX_EDGER8R) ../trusted/Enclave.edl
	@cd $(App_Dir) && $(SGX_EDGER8R) --untrusted ../trusted/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_Dir)/Enclave_u.o: $(App_Dir)/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Dir)/%.o: $(App_Dir)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

#$(BPF_C_Objs): %.o: %.c
#	@echo "BPF_CC  <=  $<"
#	$(CC) $(BPF_C_Flags) -c $< -o $@

$(MOS_C_Objs): %.o: %.c
	@echo "MOS_CC  <=  $<"
	@$(CC) $(MOS_C_Flags) $(MOS_C_Include) -c $< -o $@

$(DFC_Cpp_Objects): %.o: %.cpp
	@echo "DFC_CXX  <=  $<"
	@$(CXX) $(App_Cpp_Flags)  -c $< -o $@

#$(App_Dir)/mosTest.o: $(App_Dir)/mosTest.c
#	@echo "MOS_CC  <=  $<"
#	@$(CC) $(MOS_C_Flags) $(MOS_C_Include) -c $< -o $@
#
#$(App_Dir)/ocall_mos.o: $(App_Dir)/ocall_mos.c
#	@echo "MOS_CC  <=  $<"
#	@$(CC) $(MOS_C_Flags) $(MOS_C_Include) -c $< -o $@

$(App_Name): $(App_Dir)/Enclave_u.o $(App_Cpp_Objects) $(MOS_C_Objs) $(DFC_Cpp_Objects)#$(App_Dir)/mosTest.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH): ../enclave.signed.so
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(App_Dir)/Enclave_u.* $(Enclave_Cpp_Objects) $(Enclave_Ntoh_C_Objects) trusted/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)
	
.PHONY: clean edl

clean:
	@rm -f .config_* $(App_Name) $(App_Cpp_Objects) $(App_Dir)/Enclave_u.* $(MOS_C_Objs) $(DFC_Cpp_Objects)
