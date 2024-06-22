#include <stddef.h>
#include <stdint.h>


static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}


static uint8_t inb(uint16_t port) {
	uint8_t value;
	asm("inb %1,%0" : "=a" (value) : "Nd" (port) : "memory");
	return value;
}



void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;

	for (p = "Guest 1 usao\n"; *p; ++p)
		outb(0xE9, *p);

	for(;;) {
		uint8_t c = inb(0xE9);
		if(c == '.') {
			outb(0xE9, '\n');
			break;
		}
		outb(0xE9, c);
	}

	for (;;)
		asm("hlt");
}
