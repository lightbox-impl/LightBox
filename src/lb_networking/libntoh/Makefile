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

SGXNtoh_Dir := $(Enclave_Dir)

SGXNtoh_Include_Paths := -I$(SGXNtoh_Dir) -I../.. -Iinclude/
SGXNtoh_C_Files := $(wildcard $(SGXNtoh_Dir)/*.c) 
SGXNtoh_C_Objects := $(SGXNtoh_C_Files:.c=.o)

SGXNtoh_FLAGS = $(SGXNtoh_Include_Paths)
SGXNtoh_FLAGS += $(Enclave_C_Flags)


Enclave_Name := liblb_ntoh_t.a

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

$(SGXNtoh_C_Objects):  %.o: %.c
	@$(CC) $(SGXNtoh_FLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): $(SGXNtoh_C_Objects) 
	@ar crs -o $(Enclave_Name) $(SGXNtoh_C_Objects) 
	@echo "AR =>  $@"


.PHONY: clean

clean:
	@rm -f $(Enclave_Name) $(SGXNtoh_C_Objects)

