######## LightBox Settings ########
LightBox ?= 1
CAIDA ?= 0
CONNECTION ?= 0
MSG64 ?= 0

LightBox_FLAGS = -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DCAIDA=$(CAIDA) -DMSG64=$(MSG64)

LightBox_DIR = $(PWD)/../..
LB_CORE_DIR = $(LightBox_DIR)/lb_core
LightBox_C_Files_U = $(LB_CORE_DIR)/host/etap_u.c $(LB_CORE_DIR)/host/state_mgmt_u.c $(LB_CORE_DIR)/host/utils_u.c $(LB_CORE_DIR)/host/lightbox.c
LightBox_C_Objects_U := $(LightBox_C_Files_U:.c=.o) 
LightBox_C_Files_T = $(LB_CORE_DIR)/enclave/etap_t.c $(LB_CORE_DIR)/enclave/state_mgmt_t.c $(LB_CORE_DIR)/enclave/crypto_t.c $(LB_CORE_DIR)/enclave/utils_t.c $(wildcard $(LB_CORE_DIR)/enclave/cuckoo/*.c) 
LightBox_C_Objects_T := $(LightBox_C_Files_T:.c=.o)
LightBox_EDL = $(LB_CORE_DIR)/enclave/lb_edge.edl
LightBox_Edge_T = $(LB_CORE_DIR)/enclave/lb_edge_t.c
LightBox_Edge_TO = $(LB_CORE_DIR)/enclave/lb_edge_t.o
LightBox_Edge_U = $(LB_CORE_DIR)/host/lb_edge_u.c
LightBox_Edge_UO = $(LB_CORE_DIR)/host/lb_edge_u.o

TRUSTED_LIB_DIR = $(PWD)/../../../trusted_lib

######## SGX SDK Settings ########
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
#SGX_DEBUG ?= 1

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

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_C_Files := host/host.c host/lwids_u.c
App_Include_Paths := -I$(SGX_SDK)/include -I/usr/include -I$(LightBox_DIR)

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

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lpcap

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_C_Objects := $(App_C_Files:.c=.o)

App_Name := lb_lwids

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := enclave/lwids_t.c enclave/pattern_matching.c $(LightBox_DIR)/lb_linux/linux_type_ports.c $(wildcard $(LightBox_DIR)/lb_networking/libntoh/*.c) 
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK) -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I/usr/include -I$(LightBox_DIR)

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(services_lib) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(TRUSTED_LIB_DIR)/libpcre.a -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/Enclave.lds

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
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
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## LigtBox host ########
$(LightBox_Edge_U): $(SGX_EDGER8R) $(LightBox_EDL)
	@cd $(LB_CORE_DIR)/host && $(SGX_EDGER8R) --untrusted ../enclave/lb_edge.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
	
$(LightBox_Edge_UO): $(LightBox_Edge_U)
	@$(CC) $(App_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"
	
$(LightBox_C_Objects_U): %.o: %.c
	@$(CC) $(App_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"
	
######## LigtBox enclave ########
$(LightBox_Edge_T): $(SGX_EDGER8R) $(LightBox_EDL)
	@cd $(LB_CORE_DIR)/enclave && $(SGX_EDGER8R) --trusted lb_edge.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(LightBox_Edge_TO): $(LightBox_Edge_T)
	@$(CC) $(Enclave_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(LightBox_C_Objects_T): %.o: %.c
	@$(CC) $(Enclave_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"
	
######## App Objects ########
$(App_C_Objects): %.o: %.c 
	@$(CC) $(App_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): $(LightBox_Edge_UO) $(LightBox_C_Objects_U) $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########
$(Enclave_C_Objects): %.o: %.c
	@$(CC) $(Enclave_C_Flags) $(LightBox_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): $(LightBox_Edge_TO) $(LightBox_C_Objects_T) $(Enclave_C_Objects)
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) $(Enclave_C_Objects) $(LightBox_Edge_U) $(LightBox_Edge_UO) $(LightBox_Edge_T) $(LightBox_Edge_TO) $(LightBox_C_Objects_U) $(LightBox_C_Objects_T)
