

SRC_DIR = src

.PHONY: clean  

all: 
	mkdir -p build
	$(MAKE) -C $(SRC_DIR)
clean:
	$(MAKE) -C $(SRC_DIR) clean
	rm -rf build


