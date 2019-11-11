
CORE_DIR = lb/core

PCAP_DIR = lb/networking/libpcap
MOS_DIR = lb/networking/libmOS
NTOH_DIR = lb/networking/libntoh
NETWORKING_DIR = $(PCAP_DIR) $(MOS_DIR) $(NTOH_DIR)

GATEWAY_DIR = gateway_cli
HELLOWORLD = instances/helloworld
LWIDS = instances/lwids
MIDS = instances/mIDS
PRADS = instances/prads
INSTANCE_DIR = $(HELLOWORLD) $(LWIDS) $(MIDS) $(PRADS) 

ALL_DIR = $(CORE_DIR) $(NETWORKING_DIR) $(GATEWAY_DIR) $(INSTANCE_DIR)

.PHONY: clean core networking gateway instances 

all: core networking gateway instances

core: 
	$(MAKE) -C $(CORE_DIR)

libpcap: core 
	$(MAKE) -C $(PCAP_DIR)

libmos: libpcap core
	$(MAKE) -C $(MOS_DIR)

libntoh: core 
	$(MAKE) -C $(NTOH_DIR)

networking: libpcap libmos libntoh

gateway:
	$(MAKE) -C $(GATEWAY_DIR)

helloworld: core 
	$(MAKE) -C $(HELLOWORLD)

lwids: core libntoh 
	$(MAKE) -C $(LWIDS)

mids: core libpcap libmos 
	$(MAKE) -C $(MIDS)

prads: core 
	$(MAKE) -C $(PRADS)

instances: helloworld lwids mids #prads


clean:
	for dir in $(ALL_DIR); do \
		$(MAKE) -C $$dir clean ; \
		done
	


