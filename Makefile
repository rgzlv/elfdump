warn = -Wall -Wextra -Wpedantic
nowarn = -Wno-implicit-fallthrough -Wno-switch # -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set
CPPFLAGS = -std=c99 $(warn) $(nowarn) -Ilibcx/include

elfdump: elfdump.c libcx/libcx.a

libcx/libcx.a:
	$(MAKE) -C libcx

clean:
	rm -f elfdump *.o
