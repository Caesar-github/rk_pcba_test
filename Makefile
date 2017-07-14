PWD=`pwd`
TOP_DIR=${PWD}/../..

TOOLCHAIN_PATH=$(TOP_DIR)/buildroot/output/host/usr
INC_DIR=$(TOOLCHAIN_PATH)/include
LIB_DIR=$(TOOLCHAIN_PATH)/lib

CC = $(TOOLCHAIN_PATH)/bin/arm-rockchip-linux-gnueabihf-gcc
CPP = $(TOOLCHAIN_PATH)/bin/arm-rockchip-linux-gnueabihf-g++
STRIP = $(TOOLCHAIN_PATH)/bin/arm-rockchip-linux-gnueabihf-strip

INCS = -I ./ -I ./cJSON/ -I ./rk_vendor_storage/ -I ./tinyalsa/  -I $(INC_DIR)
ALL_LIB_DIR = -L $(LIB_DIR)
CFLAGS = -Wno-multichar

.PHONY: all

AT=@
all_target_dir=rk_pcba_test
test_item_compile_lone=echo_pcbatest_server.c \
					   echo_uevent_detect.c write_storage.c
test_item_compile_lone_taget=$(basename $(test_item_compile_lone))

t1_source=$(filter-out $(test_item_compile_lone), $(wildcard *.c))
t1_target=$(basename $(t1_source))
t1_objects=$(patsubst %.c, %.o, $(t1_source))

all_target=$(test_item_compile_lone_taget) $(t1_target)

all: $(all_target) 
	$(AT)$(STRIP) $(t1_target)
	$(AT)mv -f $(all_target) $(all_target_dir)

$(t1_objects): $(t1_source)
	$(AT)$(CC) -c $(filter $(basename $@)%, $^) $(ALL_LIB_DIR) $(INCS) $(CFLAGS)

$(t1_target):$(t1_objects)
	$(AT)$(CC) $(patsubst %,%.o,$@) -o $(patsubst %,%,$@) $(ALL_LIB_DIR) $(INCS) $(CFLAGS)

write_storage:
	$(AT)$(CC) write_storage.c rk_vendor_storage/rk_vendor_storage.c -o $@ $(ALL_LIB_DIR) $(INCS) $(CFLAGS)

echo_uevent_detect:
	$(AT)$(CC) uevent/echo_uevent_detect.c -o $@ $(ALL_LIB_DIR) $(INCS) $(CFLAGS)

echo_pcbatest_server:
	$(AT)$(CC) echo_pcbatest_server.c cJSON/cJSON.c -lm -o $@ $(ALL_LIB_DIR) $(INCS) $(CFLAGS)

clean:
	$(AT)rm -f $(all_target) $(t1_objects) $(addprefix $(all_target_dir)/,$(all_target))
