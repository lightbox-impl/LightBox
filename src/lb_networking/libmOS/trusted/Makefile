######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
LightBox ?=1
CAIDA ?= 1
TRACE_CLOCK ?= 0
FIX_TIMEOUT ?= 0

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

MOS_C_Files = $(Enclave_Dir)/src/core.c $(Enclave_Dir)/src/tcp_stream.c $(Enclave_Dir)/src/api.c $(Enclave_Dir)/src/mos_api.c $(Enclave_Dir)/src/eventpoll.c $(Enclave_Dir)/src/socket.c $(Enclave_Dir)/src/pipe.c \
	$(Enclave_Dir)/src/tcp_util.c $(Enclave_Dir)/src/eth_in.c $(Enclave_Dir)/src/ip_in.c $(Enclave_Dir)/src/tcp.c $(Enclave_Dir)/src/tcp_in.c $(Enclave_Dir)/src/eth_out.c $(Enclave_Dir)/src/ip_out.c $(Enclave_Dir)/src/tcp_out.c \
	$(Enclave_Dir)/src/arp.c $(Enclave_Dir)/src/timer.c $(Enclave_Dir)/src/cpu.c $(Enclave_Dir)/src/util.c $(Enclave_Dir)/src/addr_pool.c $(Enclave_Dir)/src/fhash.c $(Enclave_Dir)/src/memory_mgt.c $(Enclave_Dir)/src/logger.c $(Enclave_Dir)/src/debug.c \
	$(Enclave_Dir)/src/tcp_rb_frag_queue.c $(Enclave_Dir)/src/tcp_send_buffer.c $(Enclave_Dir)/src/tcp_sb_queue.c $(Enclave_Dir)/src/tcp_stream_queue.c \
	$(Enclave_Dir)/src/event_callback.c $(Enclave_Dir)/src/tcp_rb.c $(Enclave_Dir)/src/icmp.c $(Enclave_Dir)/src/scalable_event.c $(Enclave_Dir)/src/key_value_store.c\
	$(Enclave_Dir)/src/pcap_module.c $(Enclave_Dir)/src/config.c \
	$(Enclave_Dir)/src/sgx/sgxFunc.c 


DFC_Cpp_Files := $(wildcard $(Enclave_Dir)/dfc/*.cpp)
DFC_Cpp_Include := /usr/lib/gcc/x86_64-linux-gnu/5/include/
DFC_Cpp_Flags := -march=native -msse4


# trans to ocall
#MOS_C_Files := # 
	#$(Enclave_Dir)/src/bpf/sf_bpf_filter.c $(Enclave_Dir)/src/bpf/sfbpf-int.c $(Enclave_Dir)/src/bpf/sf_gencode.c $(Enclave_Dir)/src/bpf/sf_grammar.c \
	#$(Enclave_Dir)/src/bpf/sf_nametoaddr.c $(Enclave_Dir)/src/bpf/sf_optimize.c $(Enclave_Dir)/src/bpf/sf_scanner.c \


LightBox_Dir := ../../../../src/lb_core
Root_Dir := ../../../..
LightBox_Include := -I$(LightBox_Dir)/enclave -I$(LightBox_Dir)/enclave/cuckoo -I$(LightBox_Dir)/../ -I(Root_Dir)/include
LightBox_Flag := -DLightBox=$(LightBox) -DCAIDA=$(CAIDA) -DTRACE_CLOCK=$(TRACE_CLOCK) -DFIX_TIMEOUT=$(FIX_TIMEOUT) -DSGX_HANDLE_WEIRD_PKT #-DUSE_ETAP -DSGX_DEBUG_PIN -DALLOW_PKT_DROP #-DSGX_DEBUG_TIME
LightBox_Lib := $(LightBox_Dir)/liblb_core_t.a

Enclave_Cpp_Files := $(wildcard $(Enclave_Dir)/*.cpp)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o) 
Enclave_Include_Paths := -IInclude -I$(Enclave_Dir) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(Enclave_Dir)/src/include -I$(Enclave_Dir)/src/include/sgx  -I$(DFC_Cpp_Include) $(LightBox_Include)

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) $(DFC_Cpp_Flags) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++11 -Wno-write-strings $(LightBox_Flag)

MOS_C_Flags = #-DSGX_FUNC_H#
MOS_C_Flags += -m64 -Wall -fPIC -fgnu89-inline -DMAX_CPUS=1 -DNEWEV -D__thread="" -DENABLE_PCAP -DBE_RESILIENT_TO_PACKET_DROP
MOS_C_Flags += -g -DDISABLE_NUMA -Wno-unused-variable -Wno-unused-value -Wno-unused-function -Wno-write-strings
MOS_C_Flags += -DDBGERR -DDBGCERR -DDBGFUNC -DINFO -DDBGMSG -DRCVBUF# -O3 -DNDEBUG -DENABLE_DEBUG_EVENT   #-DNETSTAT #-DSTREAM
MOS_C_Flags += $(LightBox_Flag)
MOS_C_Include := -I$(Enclave_Dir)/src/include $(LightBox_Include)

MOS_C_Flags += $(Enclave_C_Flags) -I$(Enclave_Dir)/src/include/sgx
MOS_C_Include += -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx  -I$(SGX_SDK)/include/stlport

MOS_C_Objs = $(patsubst %.c,%.o,$(MOS_C_Files))
MOS_C_Deps = $(patsubst %.c,%.d,$(MOS_C_Files))
#MOS_C_Deps = $(patsubst %.c,.%.d,$(MOS_C_Files))

DFC_Cpp_Objects = $(DFC_Cpp_Files:.cpp=.o) 





###pcap
#MOS_C_Link_Flags = -lpcap

MTCP_LIB=../libmtcp.a

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
	 $(LightBox_Lib) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(Enclave_Version_Script)


Enclave_Name := ../liblb_mos_t.a
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

all: $(Enclave_Name)
	@echo "LightBox = ${LightBox}"

######## Enclave Objects ########

$(Enclave_Dir)/Enclave_t.c: $(SGX_EDGER8R) $(Enclave_Dir)/Enclave.edl
	@cd $(Enclave_Dir) && $(SGX_EDGER8R) --trusted ../trusted/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Enclave_Dir)/Enclave_t.o: $(Enclave_Dir)/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Dir)/%.o: $(Enclave_Dir)/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Dir)/dfc/%.o: $(Enclave_Dir)/dfc/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): $(Enclave_Dir)/Enclave_t.c $(Enclave_Cpp_Objects) $(MOS_C_Objs) $(DFC_Cpp_Objects)
	@ar crs -o $(Enclave_Name) $(Enclave_Cpp_Objects) $(MOS_C_Objs) $(DFC_Cpp_Objects)
	@echo "AR =>  $@"

$(MOS_C_Objs): %.o: %.c
	@echo "MOS_CC  <=  $<"
	@$(CC) $(MOS_C_Flags) $(MOS_C_Include) -c $< -o $@

$(MOS_C_Deps): %.d: %.c
	@mkdir -p .bpf
	@$(CC) $(MOS_C_Flags) $(MOS_C_Include) -MM $(CFLAGS) $< > $@


.PHONY: clean edl

clean:
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) $(Enclave_Dir)/Enclave_t.* $(MOS_C_Deps) $(MOS_C_Objs) $(MTCP_LIB) $(DFC_Cpp_Objects) 

