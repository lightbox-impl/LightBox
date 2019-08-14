# LightBox
Full-stack protected stateful middlebox at lightning speed

## Getting Started 

LightBox is developed and tested on ubuntu machine only at current stage. Other Linux distribution may enter some small issues.   

### Prerequisites  

First of all, Intel SGX driver, PSW Package and SDK needs to be installed on your machine to compile and run LightBox. Please refer to the offical 
guide of SGX to install them. [Click me](https://github.com/intel/linux-sgx) 

After installing the Intel SGX on your machine, run the following command to install libpcap's header file:

```
sudo apt-get install libpcap libpcap-dev
```

### Compiling

There are mainly five component within `LightBox/src` directory, _core_, _gateway_, _instance_, _linux_ and _networking_.
The _core_ and _network_ need to be built before others. Then you can build _gateway_ and _instance_. 
The building processing is fairly simple, just run the following command:

```
cd LightBox/src/
cd lb_core && make && cd ..
cd lb_networking && make && cd ..
cd lb_gateway && make && cd ..
cd lb_instance/mIDS && make && cd ../..
```


There are several different mode for LightBox to run. The default mode is **CAIDA**. You can switch to different mode by modifying corresponding variable in Makefile. 



