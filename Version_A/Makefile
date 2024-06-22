
CC = gcc

all: mini_hypervisor guest.img 

run: all
	./mini_hypervisor -m 4 -p 2 -g guest.img

mini_hypervisor: mini_hypervisor.c
	gcc mini_hypervisor.c -o mini_hypervisor


guest.img: guest.o
	ld -T guest.ld guest.o -o guest.img

guest.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^


clean:
	rm -f mini_hypervisor
	rm -f guest.o guest.img
