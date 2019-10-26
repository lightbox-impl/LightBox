

SRC_DIR = src

.PHONY: clean  

all: 
	mkdir build
	$(MAKE) -C $(SRC_DIR)
clean:
	$(MAKE) -C $(SRC_DIR) clean
	rmdir build


