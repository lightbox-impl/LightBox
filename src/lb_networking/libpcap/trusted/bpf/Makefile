CC=gcc
INC=./
CFLAGS=-g -O3 -I$(INC) -DTEST_BPF -Wall
LDFLAGS=
# TARGET=main
TARGET=../libbpf.a

SRCS=sf_bpf_filter.c
OBJS=$(SRCS:.c=.o)

all: $(TARGET)

$(OBJS): %.o:%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	ar crs $(TARGET) $(OBJS)

.PHONY: clean

clean:
	rm -f $(OBJS) $(TARGET)


# all: sf_bpf_filter.c sfbpf-int.c sf_gencode.c sf_grammar.c \
	# sf_nametoaddr.c sf_optimize.c sf_scanner.c main.c
	# $(CC) $(CFLAGS) $(LDFLAGS) $? -o $(TARGET)
# clean:
	# rm -rf *.o $(TARGET) *~

