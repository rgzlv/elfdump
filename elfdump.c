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

#define ELFXX_HALF(class, ptr) \
	((class) == ELFCLASS32 ? (Elf32_Half *)(ptr) : (Elf64_Half *)(ptr))

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

// TODO: Messages get queued before the byte is shown but that also means the
// message for the byte that will appear on the next row at column 0 will be
// shown at the previous row, which is incorrect but doesn't hurt readability
// that much at least.
// I guess this should be solved elsewhere, not in msg_queue.
// Maybe show_byte(s) should do the message queueing instead.
struct msg *msg_queue(const char *s, enum color color, bool bad, bool own) {
	struct msg *msg = malloc(sizeof(*msg));
	if (!msg) return NULL;
	msg->prev = msgs->prev; msg->next = msgs;
	if (!bad) msg->s = s;
	else {
		own = true;
		msg->s = malloc(strlen(s) + 2);
		if (!msg->s) return NULL;
		*(char *)msg->s = '!';
		strcpy((char *)msg->s + 1, s);
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

void end_line(unsigned char *org, unsigned char *buf) {
	uintptr_t pos = (uintptr_t)buf - (uintptr_t)org;
	uintptr_t pos_col = pos % cols;
	int rem = cols - pos_col;
	// will there be empty space where bytes would have been shown?
	if (rem && rem != cols) {
		// get the length of a byte string (plus the space, if any)
		// 128 to accommodate longer formats passed to -f
		char byte_s[128] = {0};
		snprintf(byte_s, 1024, fmt_byte, 0);
		int pad_len = strlen(byte_s) * rem;
		// pad that amount with spaces
		printf("%*c", pad_len, ' ');
		char *old_ascii = ascii + pos_col;
		while (*old_ascii) {
			*old_ascii = ' ';
			old_ascii++;
		}
	}
	printf("| %s |", ascii);
	struct msg *msg;
	while ((msg = msg_dequeue()) != msgs) {
		if (msg->s) {
			printf(color_fmt(msg->color));
			printf(" %s", msg->s);
			printf(color_fmt(COLOR_NONE));
		}
		msg_free(msg);
	}
	putchar('\n');
}

void show_byte(unsigned char *org, unsigned char **buf, enum color color) {
	uintptr_t pos = (uintptr_t)*buf - (uintptr_t)org;
	uintptr_t pos_col = pos % cols;
	bool first = pos == 0;
	bool first_col = pos_col == (uintptr_t)(0);
	if (first_col && !first) end_line(org, *buf);
	if (first || first_col) printf(fmt_addr, (void *)pos);
	if (**buf >= ' ' && **buf <= '~') ascii[pos % cols] = **buf;
	else ascii[pos % cols] = '.';
	printf(color_fmt(color));
	printf(fmt_byte, **buf);
	printf(color_fmt(COLOR_NONE));
	*buf += 1;
}

void show_bytes(unsigned char *org, unsigned char **buf, enum color color, size_t count) {
	while (count--) show_byte(org, buf, color);
}

int elfdump(unsigned char *buf, size_t size) {
	if (size < sizeof(Elf32_Ehdr)) cx_errx("size < ELF32 ELF header, not an ELF file");
	unsigned char *org = buf;
	enum color color = COLOR_NONE;

	bool bad_magic = false;
	if (*buf != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F')
		bad_magic = true;
	msg_queue("ehdr.e_ident[EI_MAG0..EI_MAG3]", color, bad_magic, false);
	show_byte(org, &buf, color);
	show_byte(org, &buf, color);
	show_byte(org, &buf, color);
	show_byte(org, &buf, color);
	color = color_next(color);

	unsigned char class = *buf;
	bool bad_class = false;
	if (class != ELFCLASS32 && class != ELFCLASS64) bad_class = true;
	char *class_msg = malloc(sizeof("ehdr.e_ident[EI_CLASS] == ELFCLASS##"));
	if (!class_msg) return EXIT_FAILURE;
	sprintf(class_msg, "ehdr.e_ident[EI_CLASS] == ELFCLASS%s", class == ELFCLASS32 ? "32" : "64");
	msg_queue(class_msg, color, bad_class, true);
	show_byte(org, &buf, color);
	color = color_next(color);

	bool bad_endian = false;
	if (*buf != ELFDATA2LSB && *buf != ELFDATA2MSB) bad_endian = true;
	char *endian_msg = malloc(sizeof("ehdr.e_ident[EI_DATA] == ELFDATA2#SB"));
	if (!endian_msg) return EXIT_FAILURE;
	sprintf(endian_msg, "ehdr.e_ident[EI_DATA] == ELFDATA2%cSB", *buf == ELFDATA2LSB ? 'L' : 'M');
	msg_queue(endian_msg, color, bad_endian, true);
	show_byte(org, &buf, color);
	color = color_next(color);

	char *version_msg = malloc(sizeof("ehdr.e_ident[EI_VERSION] == ### // #EV_CURRENT"));
	if (!version_msg) return EXIT_FAILURE;
	sprintf(version_msg, "ehdr.e_ident[EI_VERSION] == %hhu // %sEV_CURRENT", *buf, *buf == EV_CURRENT ? "" : "!");
	msg_queue(version_msg, color, false, true);
	show_byte(org, &buf, color);
	color = color_next(color);

	bool bad_abi = false;
	char *abi_msg;
	const char *abi_str = abitostr(*buf);
	if (!strcmp(abi_str, "bad")) bad_abi = true;
	if (bad_abi)
		abi_msg = "ehdr.e_ident[EI_OSABI]";
	else {
		abi_msg = malloc(sizeof("ehdr.e_ident[EI_OSABI] == #") + 64);
		if (!abi_msg) return EXIT_FAILURE;
		sprintf(abi_msg, "ehdr.e_ident[EI_OSABI] == %s", abi_str);
	}
	msg_queue(abi_msg, color, bad_abi, !bad_abi);
	show_byte(org, &buf, color);
	color = color_next(color);

	char *abiver_msg = malloc(sizeof("ehdr.e_ident[EI_ABIVERSION] == ###"));
	if (!abiver_msg) return EXIT_FAILURE;
	sprintf(abiver_msg, "ehdr.e_ident[EI_ABIVERSION] == %hhu", *buf);
	msg_queue(abiver_msg, color, false, true);
	show_byte(org, &buf, color);
	color = color_next(color);

	msg_queue("ehdr.e_ident[EI_PAD..EI_NIDENT-1]", color, false, false);
	ptrdiff_t pad_amount = EI_NIDENT - (buf - org);
	for (unsigned char *pad = buf; buf - pad < pad_amount;)
		show_byte(org, &buf, color);
	color = color_next(color);

	const char *type_str = NULL;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
	if (*(ELFXX_HALF(class, buf)) == ET_NONE) type_str = "none";
	else if (*(ELFXX_HALF(class, buf)) == ET_REL) type_str = "relocatable";
	else if (*(ELFXX_HALF(class, buf)) == ET_EXEC) type_str = "executable";
	else if (*(ELFXX_HALF(class, buf)) == ET_DYN) type_str = "shared object";
	else if (*(ELFXX_HALF(class, buf)) == ET_CORE) type_str = "core";
	else if (*(ELFXX_HALF(class, buf)) >= ET_LOOS && *(ELFXX_HALF(class, buf)) <= ET_HIOS)
		type_str = "OS specific";
	else if (*(ELFXX_HALF(class, buf)) >= ET_LOPROC && *(ELFXX_HALF(class, buf)) <= ET_HIPROC)
		type_str = "processor specific";
#pragma GCC diagnostic pop
	char *type_msg;
	if (!type_str)
		type_msg = "ehdr.e_type";
	else {
		type_msg = malloc(sizeof("ehdr.e_type == #") + 32);
		if (!type_msg) return EXIT_FAILURE;
		sprintf(type_msg, "ehdr.e_type == %s", type_str);
	}
	msg_queue(type_msg, color, !type_str, type_str);
	show_bytes(org, &buf, color, class == ELFCLASS32 ? sizeof(Elf32_Half) : sizeof(Elf64_Half));
	
	end_line(org, buf);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	cx_progname = "xelf";
	int opt;
	const char *opts = ":xdbXDBf:F:c:";
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
	int ret = elfdump(buf, (size_t)st.st_size);
	free(buf);
	return ret;
}
