# LightBox

Full-stack protected stateful middlebox at lightning speed.

### Development Stage

The project is still under development. All core functionalities have been implemented and tested on Ubuntu 18.04 LTS with Intel SGX Linux SDK 2.6.

## Build

### Prerequisites  

Recommended environment: Ubuntu 18.04 LTS with gcc version 7.4.0 or higher. The CPU has to be SGX-enabled.

This software requires the following libraries:

* [Intel SGX](https://software.intel.com/en-us/sgx)

### Installation

- Environment setup: 

```shell
sudo apt-get update
sudo apt-get install build-essential git libpcap-dev
```
- SGX installation:

Please follow the instructions at [Intel(R) Software Guard Extensions for Linux* OS](https://github.com/intel/linux-sgx)

### Compilation
```bash
git clone [this repo]
cd LightBox
make
```

## Components
There are currently four sample middleboxes at src/instances

- helloworld
- lwIDS
- mIDS
- PRADS

The sample gateway is also provided at src/gateway_cli

## Maintainer
- Ruochen Wang, City University of Hong Kong, ruochwang2-c@cityu.edu.hk
- Huayi Duan, City University of Hong Kong, hy.duan@my.cityu.edu.hk



