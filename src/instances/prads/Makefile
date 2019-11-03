### LightBox switches ###
LightBox ?= 1
CAIDA ?= 0
CONNECTION ?= 0

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
        SGX_COMMON_CFLAGS += -O3
endif

######## Host Settings ########
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Host_C_Files := host/host.c host/lb_prads.c host/mem_utils_u.c host/prads_core/servicefp/servicefp.c $(wildcard host/prads_core/*.c)
Host_C_Objects := $(Host_C_Files:.c=.o)

LB_Root_Dir := ../../..
Host_Include := -I$(SGX_SDK)/include -I/usr/include -I$(LB_Root_Dir)/include -I$(LB_Root_Dir)/src/lb/core/host/include

Host_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Host_Include)

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

Host_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)  -L$(LB_Root_Dir)/build -llb_core_u -llb_pcap_u -lpthread  -lpcre
# -lpcap

ifneq ($(SGX_MODE), HW)
	Host_Link_Flags += -lsgx_uae_service_sim
else
	Host_Link_Flags += -lsgx_uae_service
endif

Target := lb_prads

######## Enclave Settings ########
# PRADS_CFLAGS=-D__USE_GNU -DCONFDIR='"/usr/local/etc/prads/"' 
# PRADS_Link_Flags=-lpcap -lresolv -lpcre -L../../lb_core -llb_core_u

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := enclave/prads_enclave.c enclave/mem_utils_t.c $(wildcard enclave/prads_core/*.c) $(wildcard enclave/prads_core/ipfp/*.c) $(wildcard enclave/prads_core/output-plugins/*.c) $(wildcard enclave/prads_core/servicefp/*.c) 
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Include := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(LB_Root_Dir)/include -I$(LB_Root_Dir)/trusted_lib -I$(LB_Root_Dir)/src/lb/core/enclave -I$(LB_Root_Dir)/src/lb/core/enclave/include -I$(LB_Root_Dir)/src/lb/networking/libpcap/enclave
# -I/usr/lib/gcc/x86_64-linux-gnu/4.8/include -I/usr/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include) -DCAIDA=$(CAIDA) -DLightBox=$(LightBox)
Test_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L../../../build -L../../../trusted_lib \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -lpcre -llb_core_t -llb_pcap_t -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/Enclave.lds

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
# -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) ./lib/libpcre.a -Wl,--end-group \
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
# 	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
# 	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(LB_Root_dir)/trusted_lib/libpcre.a -lpcre $(LB_Root_dir)/build/liblb_core_t.a $(LB_Root_dir)/build/liblb_pcap_t.a -llb_core_t -llb_pcap -Wl,--end-group \
# 	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
# 	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
# 	-Wl,--defsym,__ImageBase=0 \
# 	-Wl,--version-script=prads_enclave/Enclave.lds

Enclave_Name := prads_enclave.so
Signed_Enclave_Name := prads_enclave.signed.so
Enclave_Config_File := enclave/Enclave.config.xml

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

.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Target) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Target) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Target) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
ifeq ($(LightBox), 1)
	@echo "*************************************************"
	@echo "************LightBox is enabled!********************"
	@echo "*************************************************"
endif
ifeq ($(CAIDA), 1)
	@echo "*************************************************"
	@echo "*************CAIDA trace is used!****************"
	@echo "*************************************************"
endif
ifeq ($(CONNECTION), 1)
	@echo "*************************************************"
	@echo "*************CONNECTION mode is enabled!****************"
	@echo "*************************************************"
endif
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Target)
	@echo "RUN  =>  $(Target) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Host Objects ########

host/prads_edge_u.c: $(SGX_EDGER8R) enclave/prads_edge.edl
	@cd host && $(SGX_EDGER8R) --untrusted ../enclave/prads_edge.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

host/prads_edge_u.o: host/prads_edge_u.c
	@$(CC) $(Host_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
	
$(Host_C_Objects): %.o: %.c
	@$(CC) $(Host_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Target): host/prads_edge_u.o $(Host_C_Objects)
	@$(CC) $^ -o $@ $(Host_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave/prads_edge_t.c: $(SGX_EDGER8R) enclave/prads_edge.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/prads_edge.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/prads_edge_t.o: enclave/prads_edge_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_C_Objects): %.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): enclave/prads_edge_t.o $(Enclave_C_Objects)
	@$(CC) $^ -o $@ $(Test_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(Target) $(Enclave_Name) $(Signed_Enclave_Name) $(Host_C_Objects) $(Enclave_C_Objects) host/prads_edge_u* enclave/prads_edge_t*
