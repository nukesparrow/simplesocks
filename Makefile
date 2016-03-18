.DEFAULT_GOAL := all

NSUTIL_PATH ?= /home/portable/projects/galaot/util
#NSUTIL_PATH ?= ../util

STATIC_ANL_PATH ?= /home/portable/projects/libanl-static

INCLUDES += -I$(NSUTIL_PATH) -I$(STATIC_ANL_PATH)

CFLAGS += $(INCLUDES) -DSTATIC_ANL -g -Wall -Os -ffunction-sections -fdata-sections
LDLIBS += -pthread -Wl,--gc-sections $(NSUTIL_PATH)/libutil.a $(STATIC_ANL_PATH)/libanl.a

objects=socksserver.o

simplesocks.a: $(objects)
	$(AR) rcs simplesocks.a $(objects)
	
simplesocks: main.o $(objects)
	$(CC) $(CFLAGS) main.o $(objects) $(LDLIBS) -o $@

all: simplesocks.a
	
run: simplesocks
	./simplesocks
	
run-valgrind:
	valgrind --vgdb=yes --leak-check=full --show-leak-kinds=all ./simplesocks
	
splint:
	splint +posixlib $(INCLUDES) *.c

clean:
	-rm -f simplesocks main.o simplesocks.a $(objects)
