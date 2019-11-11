# LightBox
Full-stack protected stateful middlebox at lightning speed

## Getting Started 

LightBox is developed and tested on ubuntu machine only at current stage. Other Linux distribution may enter some small issues. 

## Publication 
Huayi Duan, Cong Wang, Xingliang Yuan, Yajin Zhou, Qian Wang, and Kui Ren. 2019. LightBox: Full-stack Protected Stateful Middlebox at Lightning Speed. In 2019 ACM SIGSAC Conference on Computer and Communications Security (CCS’19), November 11–15, 2019, London, United Kingdom.  

### Prerequisites  

Recommended Environments: Ubuntu 18.04 LTS with gcc version 7.4.0 or higher.   
The CPU has to support Intel Software Guard Extensions. The recommended environment is Ubuntu 18.04 LTS with gcc version 7.4.0 or higher. 

This software requires the following libraries:  
* [Intel SGX](https://software.intel.com/en-us/sgx)
* [libpcap] (https://www.tcpdump.org/)

## Installation

- Environment setup: 

```shell
sudo apt-get update
sudo apt-get install build-essential git 
```

- SGX installation:

You need to enable SGX follow the [Intel_SGX_Installation_Guide_Linux](https://download.01.org/intel-sgx/linux-2.1/docs/Intel_SGX_Installation_Guide_Linux_2.1_Open_Source.pdf)

- Mode
There are several different mode for LightBox to run. The default mode is **CAIDA**. You can switch to different mode by modifying corresponding variable in Makefile scripts. 

## Compiling
```bash
git clone https://github.com/XXXXXXX
cd LightBox
make
```

## etap Usage
We encapsulate the network communication parts of LightBox into etap (a virtual network interface). The packet I/O APIs are  designed like this:

```c
poll_driver_t* pd = poll_driver_init();

pd->read_pkt(pkt_buffer, &pkt_size, &time_stamp, pd->etap);
pd->write_pkt(pkt_buffer, pkt_size, time_stamp, pd->etap);
```

## Gateway Client

## Application
- helloworld
- lwIDS
- mIDS
- prads


## Maintainer
- Ruochen Wang, City University of Hong Kong, ruochwang2-c@cityu.edu.hk
- Huayi Duan, City University of Hong Kong, hduan2-c@my.cityu.edu.hk



