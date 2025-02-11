warn := -Wall -Wextra -Wpedantic
nowarn := -Wno-implicit-fallthrough -Wno-switch
#nowarn += -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set
override CPPFLAGS := -std=c99 $(warn) $(nowarn) -Ilibcx/include $(CPPFLAGS)
override CFLAGS := $(CFLAGS)
#override CFLAGS += -g -fsanitize=undefined,address,leak

elfdump: elfdump.c libcx/libcx.a

libcx/libcx.a:
	$(MAKE) -C libcx

clean:
	rm -f elfdump *.o
