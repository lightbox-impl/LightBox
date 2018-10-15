######## SGX SDK Settings ########

### LightBox switches ###
LightBox ?= 1
CAIDA ?= 0
CONNECTION ?= 0
MSG64 ?= 0

SGX_DEBUG = 0
SGX_PRERELEASE = 1
### SG-BOX switches ###
SGBOX ?= 0
TRACE_TRICK ?= 0
LOG_AGENCY ?= 0
NO_BUNDLE ?= 0
### End ###

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1


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

App_C_Files := $(wildcard prads_host/*.c) $(wildcard prads_host/servicefp/*.c) 
App_Include_Paths := -I$(SGX_SDK)/include -I/usr/include -I. -I.. -I../..

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

App_Name := lb_prads

######## Enclave Settings ########
###### PRADS ######
# refer to code
PRADS_CFLAGS=-D__USE_GNU -DCONFDIR='"/usr/local/etc/prads/"' -DSGBOX=$(SGBOX) -DTRACE_TRICK=$(TRACE_TRICK) -DLOG_AGENCY=$(LOG_AGENCY) -DNO_BUNDLE=$(NO_BUNDLE) -DCAIDA=$(CAIDA) -DLightBox=$(LightBox) -DCONNECTION=$(CONNECTION) -DMSG64=$(MSG64)
PRADS_Link_Flags=-lpcap -lresolv -lpcre -L../../lb_core -llb_core_u
###### End PRADS ######
	
ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := $(wildcard prads_enclave/*.c) $(wildcard prads_enclave/prads/*.c) $(wildcard prads_enclave/prads/*/*.c) $(wildcard prads_enclave/sg-box/*.c) $(wildcard prads_enclave/cuckoo/*.c)
Enclave_Include_Paths := -Iprads_enclave/prads -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I/usr/lib/gcc/x86_64-linux-gnu/4.8/include -I/usr/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) ./lib/libpcre.a -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=prads_enclave/Enclave.lds

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := prads_enclave/Enclave.config.xml

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
ifeq ($(SGBOX), 1)
	@echo "*************************************************"
	@echo "************SGBOX is enabled!********************"
	@echo "*************************************************"
endif
ifeq ($(TRACE_TRICK), 1)
	@echo "*************************************************"
	@echo "*********Trick for CAIDA Internet trace!*********"
	@echo "*************************************************"
endif
ifeq ($(LOG_AGENCY), 1)
	@echo "*************************************************"
	@echo "**************Log Agency is enabled!*************"
	@echo "*************************************************"
endif
ifeq ($(NO_BUNDLE), 1)
	@echo "*************************************************"
	@echo "***********Bundle model is disabled!*************"
	@echo "*************************************************"
endif
ifeq ($(CAIDA), 1)
	@echo "*************************************************"
	@echo "*************CAIDA trace is used!****************"
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
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

prads_host/prads_u.c: $(SGX_EDGER8R) prads_enclave/prads.edl
	@cd prads_host && $(SGX_EDGER8R) --untrusted ../prads_enclave/prads.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

prads_host/prads_u.o: prads_host/prads_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
	
prads_host/%.o: prads_host/%.c
	@$(CC) $(App_C_Flags) $(PRADS_CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

prads_host/servicefp/%.o: prads_host/servicefp/%.c
	@$(CC) $(App_C_Flags) $(PRADS_CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): prads_host/prads_u.o $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags) $(PRADS_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

prads_enclave/prads_t.c: $(SGX_EDGER8R) prads_enclave/prads.edl
	@cd prads_enclave && $(SGX_EDGER8R) --trusted ../prads_enclave/prads.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

prads_enclave/prads_t.o: prads_enclave/prads_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

prads_enclave/%.o: prads_enclave/%.c
	@$(CC) $(Enclave_C_Flags) $(PRADS_CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): prads_enclave/prads_t.o $(Enclave_C_Objects)
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key prads_enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) $(Enclave_C_Objects) prads_host/prads_u.* prads_enclave/prads_t.*
