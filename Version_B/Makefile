
GUESTS = $(shell find . -name 'guest*.c' -printf "%P ")
GUEST_OBJS = $(patsubst guests/%.c,guests/build/%.o,$(GUESTS))
GUEST_IMGS = $(patsubst guests/%.c,%.img,$(GUESTS))


all: mini_hypervisor $(GUEST_IMGS)

run: all
	./mini_hypervisor -m 4 -p 2 -g $(GUEST_IMGS)

mini_hypervisor: mini_hypervisor.cpp Makefile
	gcc $< -g -o $@ -lpthread -lstdc++

guest%.img: guests/build/guest%.o guests/guest.ld | guests/build
	ld -T guests/guest.ld $< -o	$@

guests/build/guest%.o: guests/guest%.c Makefile | guests/build
	gcc -m64 -fno-stack-protector -fpic -Iguests/h -g -c -o $@ $<

guests/build:
	mkdir -p guests/build

clean:
	rm -f mini_hypervisor $(GUEST_IMGS)
	rm -rf guests/build
	rm -f $(GUEST_IMGS)