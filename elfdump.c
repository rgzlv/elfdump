#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>

#include <unistd.h>
#include <sys/stat.h>

#include <elf.h>

#include <cx.h>

// TODO: get rid of these macros, they're useless and "work" only because of that
// C99 6.5.15 "both operands are pointers to qualified or unqualified versions of compatible types"

#define ELFXX_HALF(class, ptr) \
	((class) == ELFCLASS32 ? (Elf32_Half *)(ptr) : (Elf64_Half *)(ptr))

#define ELFXX_WORD(class, ptr) \
	((class) == ELFCLASS32 ? (Elf32_Word *)(ptr) : (Elf64_Word *)(ptr))

#define ELFXX_WORD_PRI PRIu32
#define ELFXX_ADDR_PRI(class) ((class) == ELFCLASS32 ? PRIx32 : PRIx64)

struct buf {
	unsigned char *org, *pos;
	size_t size;
};

enum color {
	COLOR_NONE,
	COLOR_RED,
	COLOR_GREEN,
	COLOR_YELLOW,
	COLOR_BLUE,
	COLOR_MAGENTA,
	COLOR_CYAN,
	COLOR_BRIGHT_RED,
	COLOR_BRIGHT_GREEN,
	COLOR_BRIGHT_YELLOW,
	COLOR_BRIGHT_BLUE,
	COLOR_BRIGHT_MAGENTA,
	COLOR_BRIGHT_CYAN,
	COLOR_MAX,
};

// FIFO queue of messages about byte sequences
struct msg {
	const char *s;
	enum color color;
	bool own; // whether to take ownership of the string, i.e., free it
	struct msg *prev, *next;
};

char *fmt_byte = "%02x ";
char *fmt_addr = "%016x ";
int cols = 8;
char *ascii;
struct msg *msgs = &(struct msg){0};

void usage(void) {
	printf("Usage: %s [FLAG...] FILE\n", cx_progname);
	printf("Dump the bytes of FILE and show their ELF file format meaning.\n\n");
	printf("Flags:\n"
"  -x          hexadecimal byte output\n"
"  -d          decimal byte output\n"
"  -b          binary byte output\n"
"  -X          hexadecimal address output\n"
"  -D          decimal address output\n"
"  -B          binary address output\n"
"  -f FORMAT   C format string for byte output\n"
"  -F FORMAT   C format string for address output\n"
"  -c COLUMNS  number of columns (bytes) to show in a row\n"
	);
}

const char *abitostr(unsigned char abi) {
	switch (abi) {
	case ELFOSABI_NONE: return "none";
	case ELFOSABI_HPUX: return "HP-UX";
	case ELFOSABI_NETBSD: return "NetBSD";
	case ELFOSABI_GNU: return "GNU/Linux"; // same as ELFOSABI_LINUX
	case ELFOSABI_SOLARIS: return "Solaris";
	case ELFOSABI_AIX: return "AIX";
	case ELFOSABI_IRIX: return "IRIX";
	case ELFOSABI_FREEBSD: return "FreeBSD";
	case ELFOSABI_TRU64: return "TRU64";
	case ELFOSABI_MODESTO: return "Modesto";
	case ELFOSABI_OPENBSD: return "OpenBSD";
#ifdef ELFOSABI_OPENVMS
	case ELFOSABI_OPENVMS: return "OpenVMS";
#endif
#ifdef ELFOSABI_NSK
	case ELFOSABI_NSK: return "NonStop";
#endif
#ifdef ELFOSABI_AROS
	case ELFOSABI_AROS: return "Amiga Research OS";
#endif
#ifdef ELFOSABI_FENIXOS
	case ELFOSABI_FENIXOS: return "FenixOS";
#endif
#ifdef ELFOSABI_CLOUDABI
	case ELFOSABI_CLOUDABI: return "Nuxi CloudABI";
#endif
#ifdef ELFOSABI_OPENVOS
	case ELFOSABI_OPENVOS: return "Stratus OpenVOS";
#endif
	// not in SCO docs
#ifdef ELFOSABI_ARM
	case ELFOSABI_ARM: return "ARM";
#endif
	}
	if (abi > 64) return "arch specific"; // depends on ehdr.e_machine
	return "bad";
}

const char *machinetostr(void *machine, unsigned char class) {
	switch (*(ELFXX_HALF(class, machine))) {
	case EM_NONE: return "No machine";
	case EM_M32: return "AT&T WE 32100";
	case EM_SPARC: return "SPARC";
	case EM_386: return "Intel 80386";
	case EM_68K: return "Motorola 68000";
	case EM_88K: return "Motorola 88000";
	case EM_IAMCU: return "Intel MCU";
	case EM_860: return "Intel 80860";
	case EM_MIPS: return "MIPS I Architecture";
	case EM_S370: return "IBM System/370 Processor";
	case EM_MIPS_RS3_LE: return "MIPS RS3000 Little-endian";
	case EM_PARISC: return "Hewlett-Packard PA-RISC";
	case EM_VPP500: return "Fujitsu VPP500";
	case EM_SPARC32PLUS: return "Enhanced instruction set SPARC";
	case EM_960: return "Intel 80960";
	case EM_PPC: return "PowerPC";
	case EM_PPC64: return "64-bit PowerPC";
	case EM_S390: return "IBM System/390 Processor";
	case EM_SPU: return "IBM SPU/SPC";
	case EM_V800: return "NEC V800";
	case EM_FR20: return "Fujitsu FR20";
	case EM_RH32: return "TRW RH-32";
	case EM_RCE: return "Motorola RCE";
	case EM_ARM: return "ARM 32-bit architecture (AARCH32)";
	case EM_ALPHA: return "Digital Alpha";
	case EM_SH: return "Hitachi SH";
	case EM_SPARCV9: return "SPARC Version 9";
	case EM_TRICORE: return "Siemens TriCore embedded processor";
	case EM_ARC: return "Argonaut RISC Core, Argonaut Technologies Inc.";
	case EM_H8_300: return "Hitachi H8/300";
	case EM_H8_300H: return "Hitachi H8/300H";
	case EM_H8S: return "Hitachi H8S";
	case EM_H8_500: return "Hitachi H8/500";
	case EM_IA_64: return "Intel IA-64 processor architecture";
	case EM_MIPS_X: return "Stanford MIPS-X";
	case EM_COLDFIRE: return "Motorola ColdFire";
	case EM_68HC12: return "Motorola M68HC12";
	case EM_MMA: return "Fujitsu MMA Multimedia Accelerator";
	case EM_PCP: return "Siemens PCP";
	case EM_NCPU: return "Sony nCPU embedded RISC processor";
	case EM_NDR1: return "Denso NDR1 microprocessor";
	case EM_STARCORE: return "Motorola Star*Core processor";
	case EM_ME16: return "Toyota ME16 processor";
	case EM_ST100: return "STMicroelectronics ST100 processor";
	case EM_TINYJ: return "Advanced Logic Corp. TinyJ embedded processor family";
	case EM_X86_64: return "AMD x86-64 architecture";
	case EM_PDSP: return "Sony DSP Processor";
	case EM_PDP10: return "Digital Equipment Corp. PDP-10";
	case EM_PDP11: return "Digital Equipment Corp. PDP-11";
	case EM_FX66: return "Siemens FX66 microcontroller";
	case EM_ST9PLUS: return "STMicroelectronics ST9+ 8/16 bit microcontroller";
	case EM_ST7: return "STMicroelectronics ST7 8-bit microcontroller";
	case EM_68HC16: return "Motorola MC68HC16 Microcontroller";
	case EM_68HC11: return "Motorola MC68HC11 Microcontroller";
	case EM_68HC08: return "Motorola MC68HC08 Microcontroller";
	case EM_68HC05: return "Motorola MC68HC05 Microcontroller";
	case EM_SVX: return "Silicon Graphics SVx";
	case EM_ST19: return "STMicroelectronics ST19 8-bit microcontroller";
	case EM_VAX: return "Digital VAX";
	case EM_CRIS: return "Axis Communications 32-bit embedded processor";
	case EM_JAVELIN: return "Infineon Technologies 32-bit embedded processor";
	case EM_FIREPATH: return "Element 14 64-bit DSP Processor";
	case EM_ZSP: return "LSI Logic 16-bit DSP Processor";
	case EM_MMIX: return "Donald Knuth's educational 64-bit processor";
	case EM_HUANY: return "Harvard University machine-independent object files";
	case EM_PRISM: return "SiTera Prism";
	case EM_AVR: return "Atmel AVR 8-bit microcontroller";
	case EM_FR30: return "Fujitsu FR30";
	case EM_D10V: return "Mitsubishi D10V";
	case EM_D30V: return "Mitsubishi D30V";
	case EM_V850: return "NEC v850";
	case EM_M32R: return "Mitsubishi M32R";
	case EM_MN10300: return "Matsushita MN10300";
	case EM_MN10200: return "Matsushita MN10200";
	case EM_PJ: return "picoJava";
	case EM_OPENRISC: return "OpenRISC 32-bit embedded processor";
#ifdef EM_ARC_COMPACT
	case EM_ARC_COMPACT: return "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)";
#endif
	case EM_XTENSA: return "Tensilica Xtensa Architecture";
	case EM_VIDEOCORE: return "Alphamosaic VideoCore processor";
	case EM_TMM_GPP: return "Thompson Multimedia General Purpose Processor";
	case EM_NS32K: return "National Semiconductor 32000 series";
	case EM_TPC: return "Tenor Network TPC processor";
	case EM_SNP1K: return "Trebia SNP 1000 processor";
	case EM_ST200: return "STMicroelectronics (www.st.com) ST200 microcontroller";
	case EM_IP2K: return "Ubicom IP2xxx microcontroller family";
	case EM_MAX: return "MAX Processor";
	case EM_CR: return "National Semiconductor CompactRISC microprocessor";
	case EM_F2MC16: return "Fujitsu F2MC16";
	case EM_MSP430: return "Texas Instruments embedded microcontroller msp430";
	case EM_BLACKFIN: return "Analog Devices Blackfin (DSP) processor";
	case EM_SE_C33: return "S1C33 Family of Seiko Epson processors";
	case EM_SEP: return "Sharp embedded microprocessor";
	case EM_ARCA: return "Arca RISC Microprocessor";
	case EM_UNICORE: return "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University";
	case EM_EXCESS: return "eXcess: 16/32/64-bit configurable embedded CPU";
	case EM_DXP: return "Icera Semiconductor Inc. Deep Execution Processor";
	case EM_ALTERA_NIOS2: return "Altera Nios II soft-core processor";
	case EM_CRX: return "National Semiconductor CompactRISC CRX microprocessor";
	case EM_XGATE: return "Motorola XGATE embedded processor";
	case EM_C166: return "Infineon C16x/XC16x processor";
	case EM_M16C: return "Renesas M16C series microprocessors";
	case EM_DSPIC30F: return "Microchip Technology dsPIC30F Digital Signal Controller";
	case EM_CE: return "Freescale Communication Engine RISC core";
	case EM_M32C: return "Renesas M32C series microprocessors";
	case EM_TSK3000: return "Altium TSK3000 core";
	case EM_RS08: return "Freescale RS08 embedded processor";
	case EM_SHARC: return "Analog Devices SHARC family of 32-bit DSP processors";
	case EM_ECOG2: return "Cyan Technology eCOG2 microprocessor";
	case EM_SCORE7: return "Sunplus S+core7 RISC processor";
	case EM_DSP24: return "New Japan Radio (NJR) 24-bit DSP Processor";
	case EM_VIDEOCORE3: return "Broadcom VideoCore III processor";
	case EM_LATTICEMICO32: return "RISC processor for Lattice FPGA architecture";
	case EM_SE_C17: return "Seiko Epson C17 family";
	case EM_TI_C6000: return "The Texas Instruments TMS320C6000 DSP family";
	case EM_TI_C2000: return "The Texas Instruments TMS320C2000 DSP family";
	case EM_TI_C5500: return "The Texas Instruments TMS320C55x DSP family";
	case EM_TI_ARP32: return "Texas Instruments Application Specific RISC Processor, 32bit fetch";
	case EM_TI_PRU: return "Texas Instruments Programmable Realtime Unit";
	case EM_MMDSP_PLUS: return "STMicroelectronics 64bit VLIW Data Signal Processor";
	case EM_CYPRESS_M8C: return "Cypress M8C microprocessor";
	case EM_R32C: return "Renesas R32C series microprocessors";
	case EM_TRIMEDIA: return "NXP Semiconductors TriMedia architecture family";
	case EM_QDSP6: return "QUALCOMM DSP6 Processor";
	case EM_8051: return "Intel 8051 and variants";
	case EM_STXP7X: return "STMicroelectronics STxP7x family of configurable and extensible RISC processors";
	case EM_NDS32: return "Andes Technology compact code size embedded RISC processor family";
#ifdef EM_ECOG1
	case EM_ECOG1: return "Cyan Technology eCOG1X family";
#endif
	case EM_ECOG1X: return "Cyan Technology eCOG1X family";
	case EM_MAXQ30: return "Dallas Semiconductor MAXQ30 Core Micro-controllers";
	case EM_XIMO16: return "New Japan Radio (NJR) 16-bit DSP Processor";
	case EM_MANIK: return "M2000 Reconfigurable RISC Microprocessor";
	case EM_CRAYNV2: return "Cray Inc. NV2 vector architecture";
	case EM_RX: return "Renesas RX family";
	case EM_METAG: return "Imagination Technologies META processor architecture";
	case EM_MCST_ELBRUS: return "MCST Elbrus general purpose hardware architecture";
	case EM_ECOG16: return "Cyan Technology eCOG16 family";
	case EM_CR16: return "National Semiconductor CompactRISC CR16 16-bit microprocessor";
	case EM_ETPU: return "Freescale Extended Time Processing Unit";
	case EM_SLE9X: return "Infineon Technologies SLE9X core";
	case EM_L10M: return "Intel L10M";
	case EM_K10M: return "Intel K10M";
	case EM_AARCH64: return "ARM 64-bit architecture (AARCH64)";
	case EM_AVR32: return "Atmel Corporation 32-bit microprocessor family";
	case EM_STM8: return "STMicroeletronics STM8 8-bit microcontroller";
	case EM_TILE64: return "Tilera TILE64 multicore architecture family";
	case EM_TILEPRO: return "Tilera TILEPro multicore architecture family";
	case EM_MICROBLAZE: return "Xilinx MicroBlaze 32-bit RISC soft processor core";
	case EM_CUDA: return "NVIDIA CUDA architecture";
	case EM_TILEGX: return "Tilera TILE-Gx multicore architecture family";
	case EM_CLOUDSHIELD: return "CloudShield architecture family";
	case EM_COREA_1ST: return "KIPO-KAIST Core-A 1st generation processor family";
	case EM_COREA_2ND: return "KIPO-KAIST Core-A 2nd generation processor family";
#ifdef EM_ARC_COMPACT2
	case EM_ARC_COMPACT2: return "Synopsys ARCompact V2";
#endif
	case EM_OPEN8: return "Open8 8-bit RISC soft processor core";
	case EM_RL78: return "Renesas RL78 family";
	case EM_VIDEOCORE5: return "Broadcom VideoCore V processor";
	case EM_78KOR: return "Renesas 78KOR family";
	case EM_56800EX: return "Freescale 56800EX Digital Signal Controller (DSC)";
	case EM_BA1: return "Beyond BA1 CPU architecture";
	case EM_BA2: return "Beyond BA2 CPU architecture";
	case EM_XCORE: return "XMOS xCORE processor family";
	case EM_MCHP_PIC: return "Microchip 8-bit PIC(r) family";
#ifdef EM_INTEL205
	case EM_INTEL205: return "Reserved by Intel";
#endif
#ifdef EM_INTEL206
	case EM_INTEL206: return "Reserved by Intel";
#endif
#ifdef EM_INTEL207
	case EM_INTEL207: return "Reserved by Intel";
#endif
#ifdef EM_INTEL208
	case EM_INTEL208: return "Reserved by Intel";
#endif
#ifdef EM_INTEL209
	case EM_INTEL209: return "Reserved by Intel";
#endif
	case EM_KM32: return "KM211 KM32 32-bit processor";
	case EM_KMX32: return "KM211 KMX32 32-bit processor";
#ifdef EM_KMX16
	case EM_KMX16: return "KM211 KMX16 16-bit processor";
#endif
#ifdef EM_KMX8
	case EM_KMX8: return "KM211 KMX8 8-bit processor";
#endif
	case EM_KVARC: return "KM211 KVARC processor";
	case EM_CDP: return "Paneve CDP architecture family";
	case EM_COGE: return "Cognitive Smart Memory Processor";
	case EM_COOL: return "Bluechip Systems CoolEngine";
	case EM_NORC: return "Nanoradio Optimized RISC";
	case EM_CSR_KALIMBA: return "CSR Kalimba architecture family";
	case EM_Z80: return "Zilog Z80";
	case EM_VISIUM: return "Controls and Data Services VISIUMcore processor";
	case EM_FT32: return "FTDI Chip FT32 high performance 32-bit RISC architecture";
	case EM_MOXIE: return "Moxie processor family";
	case EM_AMDGPU: return "AMD GPU architecture";
	case EM_RISCV: return "RISC-V";
	}
	return NULL;
}

enum color color_next(enum color color) {
	color++;
	if (color == COLOR_MAX) color = 0;
	return color;
}

const char *color_fmt(enum color col) {
	switch (col) {
	case COLOR_NONE: return "\x1b[0m";
	case COLOR_RED: return "\x1b[31m";
	case COLOR_GREEN: return "\x1b[32m";
	case COLOR_YELLOW: return "\x1b[33m";
	case COLOR_BLUE: return "\x1b[34m";
	case COLOR_MAGENTA: return "\x1b[35m";
	case COLOR_CYAN: return "\x1b[36m";
	case COLOR_BRIGHT_RED: return "\x1b[31;1m";
	case COLOR_BRIGHT_GREEN: return "\x1b[32;1m";
	case COLOR_BRIGHT_YELLOW: return "\x1b[33;1m";
	case COLOR_BRIGHT_BLUE: return "\x1b[34;1m";
	case COLOR_BRIGHT_MAGENTA: return "\x1b[35;1m";
	case COLOR_BRIGHT_CYAN: return "\x1b[36;1m";
	}
	abort();
}

struct msg *msg_queue(const char *s, enum color color, bool bad, bool own) {
	struct msg *msg = malloc(sizeof(*msg));
	if (!msg) return NULL;
	msg->prev = msgs->prev; msg->next = msgs;
	if (!bad) msg->s = s;
	else {
		msg->s = malloc(strlen(s) + 2);
		if (!msg->s) {
			free(msg);
			return NULL;
		}
		*(char *)msg->s = '!';
		strcpy((char *)msg->s + 1, s);
		if (own) free((char *)s);
		else own = true;
	}
	msg->color = color;
	msg->own = own;
	msgs->prev->next = msg;
	msgs->prev = msg;
	return msg;
}

struct msg *msg_dequeue(void) {
	struct msg *msg = msgs->next;
	msg->next->prev = msgs;
	msgs->next = msg->next;
	return msg;
}

void msg_free(struct msg *msg) {
	if (msg->s && msg->own) free((char *)msg->s);
	free(msg);
}

void end_line(struct buf buf, bool last) {
	uintptr_t pos = (uintptr_t)buf.pos - (uintptr_t)buf.org;
	uintptr_t pos_col = pos % cols;
	int rem = cols - pos_col;
	// will there be empty space where bytes would have been shown?
	if (rem && rem != cols) {
		// get the length of a byte string (plus the space, if any)
		// 128 to accommodate longer formats passed to -f
		char byte_s[128] = {0};
		snprintf(byte_s, 128, fmt_byte, 0);
		int pad_len = strlen(byte_s) * rem;
		// pad that amount with spaces
		printf("%*c", pad_len, ' ');
		// clean up ascii so nothing's leftover from the previous row
		char *old_ascii = ascii + pos_col;
		while (*old_ascii) {
			*old_ascii = ' ';
			old_ascii++;
		}
	}
	printf("| %s |", ascii);
	struct msg *msg;
	for (;;) {
		// Don't fully dequeue unless this is the last end_line to
		// work around the message for the next row's first byte
		// sequence showing on the previous row, since msg_queue is
		// called before show_byte.
		if (!last && msgs->prev == msgs->next) break;

		msg = msg_dequeue();
		if (msg == msgs) break;
		if (msg->s) {
			printf(color_fmt(msg->color));
			printf(" %s", msg->s);
			printf(color_fmt(COLOR_NONE));
		}
		msg_free(msg);
	}
	putchar('\n');
}

void show_byte(struct buf *buf, enum color color) {
	uintptr_t pos = (uintptr_t)buf->pos - (uintptr_t)buf->org;
	uintptr_t pos_col = pos % cols;
	bool first = pos == 0;
	bool first_col = pos_col == (uintptr_t)0;
	if (first_col && !first) end_line(*buf, false);
	if (first || first_col) printf(fmt_addr, (void *)(buf->pos - buf->org));
	if (*buf->pos >= ' ' && *buf->pos <= '~') ascii[pos % cols] = *buf->pos;
	else ascii[pos % cols] = '.';
	printf(color_fmt(color));
	printf(fmt_byte, *buf->pos);
	printf(color_fmt(COLOR_NONE));
	buf->pos += 1;
}

void show_bytes(struct buf *buf, enum color color, size_t count) {
	while (count--) show_byte(buf, color);
}

int phdrdump(uint16_t phnum, uint16_t phentsize, struct buf *buf, uint8_t class, enum color color) {
	if (buf->size - (buf->pos - buf->org) < phnum * phentsize)
		cx_errx("file is too small for program header table to fit at phoff");

	for (uint16_t i = 0; i < phnum; i++) {
		if (i != phnum) color = color_next(color);

		uint32_t type = *(uint32_t *)buf->pos;
		char *type_msg = malloc(sizeof("phdr[#####].p_type == #") + 64);
		if (!type_msg) return EXIT_FAILURE;
		const char *type_msg_name;
		switch (type) {
		case PT_NULL: type_msg_name = "PT_NULL"; break;
		case PT_LOAD: type_msg_name = "PT_LOAD"; break;
		case PT_DYNAMIC: type_msg_name = "PT_DYNAMIC"; break;
		case PT_INTERP: type_msg_name = "PT_INTERP"; break;
		case PT_NOTE: type_msg_name = "PT_NOTE"; break;
		case PT_SHLIB: type_msg_name = "PT_SHLIB"; break;
		case PT_PHDR: type_msg_name = "PT_PHDR"; break;
		case PT_GNU_STACK: type_msg_name = "PT_GNU_STACK"; break;
		default:
			if (type >= PT_LOPROC && type <= PT_HIPROC)
				type_msg_name = "[PT_LOPROC, PT_HIPROC]";
			else type_msg_name = NULL;
		}
		if (!type_msg_name)
			sprintf(type_msg, "phdr[%" PRIu16 "].p_type", i);
		else
			sprintf(type_msg, "phdr[%" PRIu16 "].p_type == %s", i, type_msg_name);
		msg_queue(type_msg, color, !type_msg_name, true);
		show_bytes(buf, color, sizeof(type));
		if (type == PT_NULL) continue;
		color = color_next(color);

		if (class == ELFCLASS32) {
			msg_queue("TODO offset", color, false, false);
			show_bytes(buf, color, sizeof(uint32_t));
		} else {
			char *flags_msg = malloc(sizeof("phdr[#####].p_flags == #") + 32);
			if (!flags_msg) return EXIT_FAILURE;
		}

		msg_queue("remaining", color, false, false);
		show_bytes(buf, color, sizeof(Elf64_Phdr) - sizeof(type));
	}

	return EXIT_SUCCESS;
}

int shdrdump(uint16_t shnum, uint16_t shentsize, struct buf *buf, uint8_t class, enum color color) {
	if (buf->size - (buf->pos - buf->org) < shnum * shentsize)
		cx_errx("file is too small for section header table to fit at shoff");
	return EXIT_SUCCESS;
}

int elfdump(unsigned char *bytes, size_t size) {
	struct buf buf = {
		.org = bytes,
		.pos = bytes,
		.size = size,
	};
	if (buf.size < sizeof(Elf32_Ehdr)) cx_errx("size < ELF32 ELF header, not an ELF file");
	buf.org = buf.pos;
	enum color color = COLOR_NONE;

	bool bad_magic = false;
	if (*buf.pos != 0x7f || buf.pos[1] != 'E' || buf.pos[2] != 'L' || buf.pos[3] != 'F')
		bad_magic = true;
	msg_queue("ehdr.e_ident[EI_MAG0..EI_MAG3]", color, bad_magic, false);
	show_byte(&buf, color);
	show_byte(&buf, color);
	show_byte(&buf, color);
	show_byte(&buf, color);
	color = color_next(color);

	unsigned char class = *buf.pos;
	bool bad_class = false;
	if (class != ELFCLASS32 && class != ELFCLASS64) bad_class = true;
	char *class_msg = malloc(sizeof("ehdr.e_ident[EI_CLASS] == ELFCLASS##"));
	if (!class_msg) return EXIT_FAILURE;
	sprintf(class_msg, "ehdr.e_ident[EI_CLASS] == ELFCLASS%s", class == ELFCLASS32 ? "32" : "64");
	msg_queue(class_msg, color, bad_class, true);
	show_byte(&buf, color);
	color = color_next(color);

	bool bad_endian = false;
	if (*buf.pos != ELFDATA2LSB && *buf.pos != ELFDATA2MSB) bad_endian = true;
	char *endian_msg = malloc(sizeof("ehdr.e_ident[EI_DATA] == ELFDATA2#SB"));
	if (!endian_msg) return EXIT_FAILURE;
	sprintf(endian_msg, "ehdr.e_ident[EI_DATA] == ELFDATA2%cSB", *buf.pos == ELFDATA2LSB ? 'L' : 'M');
	msg_queue(endian_msg, color, bad_endian, true);
	show_byte(&buf, color);
	color = color_next(color);

	char *ident_version_msg = malloc(sizeof("ehdr.e_ident[EI_VERSION] == ### // #EV_CURRENT"));
	if (!ident_version_msg) return EXIT_FAILURE;
	sprintf(ident_version_msg, "ehdr.e_ident[EI_VERSION] == %hhu // %sEV_CURRENT", *buf.pos, *buf.pos == EV_CURRENT ? "" : "!");
	msg_queue(ident_version_msg, color, false, true);
	show_byte(&buf, color);
	color = color_next(color);

	bool bad_abi = false;
	char *abi_msg;
	const char *abi_str = abitostr(*buf.pos);
	if (!strcmp(abi_str, "bad")) bad_abi = true;
	if (bad_abi)
		abi_msg = "ehdr.e_ident[EI_OSABI]";
	else {
		abi_msg = malloc(sizeof("ehdr.e_ident[EI_OSABI] == #") + 64);
		if (!abi_msg) return EXIT_FAILURE;
		sprintf(abi_msg, "ehdr.e_ident[EI_OSABI] == %s", abi_str);
	}
	msg_queue(abi_msg, color, bad_abi, !bad_abi);
	show_byte(&buf, color);
	color = color_next(color);

	char *abiver_msg = malloc(sizeof("ehdr.e_ident[EI_ABIVERSION] == ###"));
	if (!abiver_msg) return EXIT_FAILURE;
	sprintf(abiver_msg, "ehdr.e_ident[EI_ABIVERSION] == %hhu", *buf.pos);
	msg_queue(abiver_msg, color, false, true);
	show_byte(&buf, color);
	color = color_next(color);

	msg_queue("ehdr.e_ident[EI_PAD..EI_NIDENT-1]", color, false, false);
	ptrdiff_t pad_amount = EI_NIDENT - (buf.pos - buf.org);
	for (unsigned char *pad = buf.pos; buf.pos - pad < pad_amount;)
		show_byte(&buf, color);
	color = color_next(color);

	uint16_t type = *(uint16_t *)buf.pos;
	const char *type_str = NULL;
	switch (*(ELFXX_HALF(class, buf.pos))) {
	case ET_NONE: type_str = "none"; break;
	case ET_REL: type_str = "relocatable"; break;
	case ET_EXEC: type_str = "executable"; break;
	case ET_DYN: type_str = "executable"; break;
	case ET_CORE: type_str = "executable"; break;
	}
	if (!type_str) {
		if (*(ELFXX_HALF(class, buf.pos)) >= ET_LOOS && *(ELFXX_HALF(class, buf.pos)) <= ET_HIOS)
			type_str = "OS specific";
		else if (*(ELFXX_HALF(class, buf.pos)) >= ET_LOPROC)
			type_str = "processor specific";
	}
	char *type_msg;
	if (!type_str)
		type_msg = "ehdr.e_type";
	else {
		type_msg = malloc(sizeof("ehdr.e_type == #") + 32);
		if (!type_msg) return EXIT_FAILURE;
		sprintf(type_msg, "ehdr.e_type == %s", type_str);
	}
	msg_queue(type_msg, color, !type_str, type_str);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	// TODO: there's regions of reserved values for machine's, check if the value
	// isn't in those regions
	const char *machine_str = machinetostr(buf.pos, class);
	char *machine_msg;
	if (!machine_str) machine_msg = "ehdr.e_machine";
	else {
		machine_msg = malloc(sizeof("ehdr.e_machine == #") + 128);
		if (!machine_msg) return EXIT_FAILURE;
		sprintf(machine_msg, "ehdr.e_machine == %s", machine_str);
	}
	msg_queue(machine_msg, color, !machine_str, machine_str);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	char *version_msg;
	if (!*ELFXX_WORD(class, buf.pos)) version_msg = "!ehdr.e_version";
	else {
		version_msg = malloc(sizeof("ehdr.e_version == # // #EV_CURRENT") + 16);
		if (!version_msg) return EXIT_FAILURE;
		sprintf(version_msg, "ehdr.e_version == %" ELFXX_WORD_PRI " // %sEV_CURRENT", *ELFXX_WORD(class, buf.pos), *ELFXX_WORD(class, buf.pos) == EV_CURRENT ? "" : "!");
	}
	msg_queue(version_msg, color, !*ELFXX_WORD(class, buf.pos), *ELFXX_WORD(class, buf.pos));
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Word) : sizeof(Elf64_Word));
	color = color_next(color);

	char *entry_msg = malloc(sizeof("ehdr.e_entry == #") + 16);
	if (!entry_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(entry_msg, "ehdr.e_entry == %#" PRIx32, *(Elf32_Addr *)buf.pos);
	else
		sprintf(entry_msg, "ehdr.e_entry == %#" PRIx64, *(Elf64_Addr *)buf.pos);
	msg_queue(entry_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Addr) : sizeof(Elf64_Addr));
	color = color_next(color);

	uintptr_t phoff = *(uintptr_t *)buf.pos;
	char *phoff_msg = malloc(sizeof("ehdr.e_phoff == #") + 16);
	if (!phoff_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(phoff_msg, "ehdr.e_phoff == %#" PRIx32, *(Elf32_Off *)buf.pos);
	else
		sprintf(phoff_msg, "ehdr.e_phoff == %#" PRIx64, *(Elf64_Off *)buf.pos);
	msg_queue(phoff_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Off) : sizeof(Elf64_Off));
	color = color_next(color);

	uintptr_t shoff = *(uintptr_t *)buf.pos;
	char *shoff_msg = malloc(sizeof("ehdr.e_shoff == #") + 16);
	if (!phoff_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(shoff_msg, "ehdr.e_shoff == %#" PRIx32, *(Elf32_Off *)buf.pos);
	else
		sprintf(shoff_msg, "ehdr.e_shoff == %#" PRIx64, *(Elf64_Off *)buf.pos);
	msg_queue(shoff_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Off) : sizeof(Elf64_Off));
	color = color_next(color);

	char *flags_msg = malloc(sizeof("ehdr.e_flags == #") + 8);
	if (!flags_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(flags_msg, "ehdr.e_flags == %#" PRIx32, *(Elf32_Word *)buf.pos);
	else
		sprintf(flags_msg, "ehdr.e_flags == %#" PRIx32, *(Elf64_Word *)buf.pos);
	msg_queue(flags_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Word) : sizeof(Elf64_Word));
	color = color_next(color);

	char *ehsize_msg = malloc(sizeof("ehdr.e_ehsize == 0x#### (#####)"));
	if (!ehsize_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(ehsize_msg, "ehdr.e_ehsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf32_Half *)buf.pos, *(Elf32_Half *)buf.pos);
	else
		sprintf(ehsize_msg, "ehdr.e_ehsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf64_Half *)buf.pos, *(Elf64_Half *)buf.pos);
	msg_queue(ehsize_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	uint16_t phentsize = *(uint16_t *)buf.pos;
	char *phentsize_msg = malloc(sizeof("ehdr.e_phentsize == 0x#### (#####)"));
	if (!phentsize_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(phentsize_msg, "ehdr.e_phentsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf32_Half *)buf.pos, *(Elf32_Half *)buf.pos);
	else
		sprintf(phentsize_msg, "ehdr.e_phentsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf64_Half *)buf.pos, *(Elf64_Half *)buf.pos);
	msg_queue(phentsize_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	uint16_t phnum = *(uint16_t *)buf.pos;
	char *phnum_msg = malloc(sizeof("ehdr.e_phnum == #####"));
	if (!phnum_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(phnum_msg, "ehdr.e_phnum == %" PRIu16, *(Elf32_Half *)buf.pos);
	else
		sprintf(phnum_msg, "ehdr.e_phnum == %" PRIu16, *(Elf64_Half *)buf.pos);
	msg_queue(phnum_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	uint16_t shentsize = *(uint16_t *)buf.pos;
	char *shentsize_msg = malloc(sizeof("ehdr.e_shentsize == 0x#### (#####)"));
	if (!shentsize_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(shentsize_msg, "ehdr.e_shentsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf32_Half *)buf.pos, *(Elf32_Half *)buf.pos);
	else
		sprintf(shentsize_msg, "ehdr.e_shentsize == %#" PRIx16 " (%" PRIu16 ")", *(Elf64_Half *)buf.pos, *(Elf64_Half *)buf.pos);
	msg_queue(shentsize_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	uint16_t shnum = *(uint16_t *)buf.pos;
	char *shnum_msg = malloc(sizeof("ehdr.e_shnum == #####"));
	if (!shnum_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(shnum_msg, "ehdr.e_shnum == %" PRIu16, *(Elf32_Half *)buf.pos);
	else
		sprintf(shnum_msg, "ehdr.e_shnum == %" PRIu16, *(Elf64_Half *)buf.pos);
	msg_queue(shnum_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	char *shstrndx_msg = malloc(sizeof("ehdr.e_shstrndx == #####"));
	if (!shstrndx_msg) return EXIT_FAILURE;
	if (class == ELFCLASS32)
		sprintf(shstrndx_msg, "ehdr.e_shstrndx == %" PRIu16, *(Elf32_Half *)buf.pos);
	else
		sprintf(shstrndx_msg, "ehdr.e_shstrndx == %" PRIu16, *(Elf64_Half *)buf.pos);
	msg_queue(shstrndx_msg, color, false, true);
	show_bytes(&buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	color = color_next(color);

	size_t ehdr_size = class == ELFCLASS32 ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);
	size_t phdr_size = class == ELFCLASS32 ? sizeof(Elf32_Phdr) : sizeof(Elf64_Phdr);
	size_t shdr_size = class == ELFCLASS32 ? sizeof(Elf32_Shdr) : sizeof(Elf64_Shdr);

	// smallest of phdr and shdr for the class
	size_t table_min;
	table_min = phdr_size < shdr_size ? phdr_size : shdr_size;
	if (buf.size - (buf.pos - buf.org) < table_min)
		cx_errx("file not large enough for shdr/phdr");

	// get the offset of the header table that is next after the ELF header
	uintptr_t next_off;
	if (!phoff && !shoff) {
		end_line(buf, true);
		cx_errx("phoff and shoff not set");
	}
	if (phoff == shoff) {
		end_line(buf, true);
		cx_errx("phoff == shoff");
	}
	switch (type) {
	case ET_EXEC:
		if (!phoff) cx_errx("missing program header table");
		break;
	case ET_REL:
		if (!shoff) cx_errx("missing section header table");
		break;
	default:
		cx_errx("unhandled ELF file type %d", type);
	}
	next_off = phoff < shoff ? phoff : shoff;
	// in case shdr is missing on executables, phdr on relocatables, etc.
	if (!next_off) next_off = next_off == phoff ? shoff : phoff;
	if (next_off > buf.size)
		cx_errx("first (%s) table starts out of file bounds", next_off == phoff ? "phdr" : "shdr");

	if ((uintptr_t)(buf.pos - buf.org) < next_off)
		msg_queue("non-ELF data", color, false, false);
	while ((uintptr_t)(buf.pos - buf.org) < next_off) show_byte(&buf, color);
	// had non-ELF data to show
	if (next_off > ehdr_size) color = color_next(color);

	int ret;
	if (next_off == phoff) {
		if ((ret = phdrdump(phnum, phentsize, &buf, class, color)))
			return ret;
	} else
		if ((ret = shdrdump(shnum, shentsize, &buf, class, color)))
			return ret;
	color = color_next(color);

	end_line(buf, true);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	cx_progname = "xelf";
	int opt;
	const char *opts = ":xdbXDBf:F:c:h";
	while ((opt = getopt(argc, argv, opts)) != -1) {
		switch (opt) {
		case 'x': fmt_byte = "%02x "; break;
		case 'd': fmt_byte = "%03d "; break;
		case 'b': fmt_byte = "%08b "; break;
		case 'X': fmt_addr = "%016x "; break;
		case 'D': fmt_addr = "%020d "; break;
		case 'B': fmt_addr = "%064b "; break;
		case 'f': fmt_byte = optarg; break;
		case 'F': fmt_addr = optarg; break;
		case 'c': {
			char *end;
			uintmax_t v = strtoumax(optarg, &end, 10);
			if (errno || end == optarg)
				cx_err("couldn't parse value %s", optarg);
			if (v > INT_MAX)
				cx_errx("value %ju > %d", v, INT_MAX);
			cols = (int)v;
			break;
		}
		case 'h': usage(); return EXIT_SUCCESS;
		case ':': cx_errx("missing value for flag -%c %s", optopt, optarg);
		case '?': cx_errx("unrecognized flag -%c", optopt);
		default: abort();
		}
	}
	argv += optind;
	if (!*argv) cx_errx("expected 1 filename argument");
	FILE *f = fopen(*argv, "rb");
	if (!f) cx_err("couldn't open file %s", *argv);
	struct stat st;
	if (stat(*argv, &st)) cx_err("couldn't stat file %s", *argv);
	unsigned char *buf = malloc(st.st_size);
	if (!buf) return EXIT_FAILURE;
	if (fread(buf, 1, st.st_size, f) != (size_t)st.st_size)
		cx_err("couldn't read file %s", *argv);
	fclose(f);
	ascii = calloc(cols + 1, 1);
	if (!ascii) return EXIT_FAILURE;
	msgs->prev = msgs; msgs->next = msgs;
	int ret = elfdump(buf, st.st_size);
	free(buf);
	free(ascii);
	return ret;
}
