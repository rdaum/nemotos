/*
 * elf.h - ELF32 m68k defines
 *
 * Copyright (C) 2017 The EmuTOS development team.
 *
 * Authors:
 *  RWD   Ryan Daum
 *
 * This file is distributed under the GPL, version 2 or at your
 * option any later version.  See doc/license.txt for details.
 */
#ifndef ELF_H
#define ELF_H

#include "config.h"
#include "portab.h"
#include "fs.h"
#include "pghdr.h"

enum SHT_Type {
    SHT_NULL = 0, // Null section
    SHT_PROGBITS = 1, // Program information
    SHT_SYMTAB = 2, // Symbol table
    SHT_STRTAB = 3, // String table
    SHT_RELA = 4, // Relocation (w/ addend)
    SHT_NOTE = 7, //
    SHT_NOBITS = 8, // Not present in file
    SHT_REL = 9, // Relocation (no addend)
};

enum SHT_Attr {
    SHF_WRITE = 0x01, // Writable section
    SHF_ALLOC = 0x02, // Exists in memory
    SHF_EXECINSTR = 0x04 // Executable
};

enum ELF_Ident {
    EI_MAG0 = 0, // 0x7F
    EI_MAG1 = 1, // 'E'
    EI_MAG2 = 2, // 'L'
    EI_MAG3 = 3, // 'F'
    EI_CLASS = 4, // Architecture (32/64)
    EI_DATA = 5, // Byte Order
    EI_VERSION = 6, // ELF Version
    EI_OSABI = 7, // OS Specific
    EI_ABIVERSION = 8, // OS Specific
    EI_PAD = 9 // Padding
};

#define EM_M68k 4 /* ELF for m68k id */
#define EV_CURRENT 1
#define ELFDATA2MSB (2) /* Big Endian */
#define ELFCLASS32 (1) /* 32-bit Architecture */

/* Magic number components for ELF header */
#define ELFMAG0 0x7F
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

enum ELF_Type {
    ET_NONE = 0, // Unkown Type
    ET_REL = 1, // Relocatable File
    ET_EXEC = 2 // Executable File
};

/* 32-bit ELF base types */
typedef ULONG Elf32_Addr;
typedef UWORD Elf32_Half;
typedef ULONG Elf32_Off;
typedef LONG Elf32_Sword;
typedef ULONG Elf32_Word;

#define SHN_UNDEF 0 /* Undefined section */
#define SHN_COMMON 0xfff2 /* Associated symbol is common */
#define SHN_ABS 0xfff1 /* Associated symbol is absolute */

#define ELF_NIDENT 16

typedef struct
{
    UBYTE e_ident[ELF_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct
{
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

/* Legal values for st_ subfield of st_info (symbol type).  */
enum STT_Type {
    STT_NOTYPE = 0,
    STT_OBJECT = 1,
    STT_FUNC = 2,
    STT_SECTION = 3,
    STT_FILE = 4,
    STT_COMMON = 5,
    STT_TLS = 6,
    STT_NUM = 7,
    STT_LOOS = 10,
    STT_HIOS = 12,
    STT_LOPROC = 13,
    STT_HIPROC = 15
};

typedef struct
{
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    UBYTE st_info;
    UBYTE st_other;
    Elf32_Half st_shndx;
} Elf32_Sym;

enum Elf32SectionType {
    ELF32_SECTION_BSS,
    ELF32_SECTION_DATA,
    ELF32_SECTION_TEXT,
    ELF32_SECTION_SYMTAB,
    ELF32_SECTION_STRTAB,
    ELF32_SECTION_SHTRTAB,
    ELF32_SECTION_OTHER,
};

#define ELF32_ST_BIND(INFO) ((INFO) >> 4)
#define ELF32_ST_TYPE(INFO) ((INFO)&0x0F)

#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x)&0xff)

enum StT_Bindings {
    STB_LOCAL = 0, // Local scope
    STB_GLOBAL = 1, // Global scope
    STB_WEAK = 2 // Weak, (ie. __attribute__((weak)))
};

typedef struct
{
    Elf32_Addr r_offset;
    Elf32_Word r_info;
} Elf32_Rel;

typedef struct
{
    Elf32_Addr r_offset;
    Elf32_Word r_info;
    Elf32_Sword r_addend;
} Elf32_Rela;

/* 68k ELF relocation types
  */
#define R_68K_NONE 0
#define R_68K_32 1
#define R_68K_PC32 4

/*
 * To avoid dynamic allocation for sections we statically allocate them up to N quantity.
 */
#define MAX_SECTIONS 64

typedef struct {
    enum Elf32SectionType section_type;

    Elf32_Half elf_section_number;
    Elf32_Shdr elf_section_header;

    /* the destination address in the process's memory */
    void *dest_addr;
} elf_section_decl ;

typedef struct {
    const PD* pd;

    Elf32_Ehdr elf_hdr;

    Elf32_Half num_sections;
    elf_section_decl sections[MAX_SECTIONS];

    Elf32_Shdr *symtab;
    Elf32_Shdr *strtab;
    Elf32_Shdr *shtrtab;

    /* Where we discovered __start */
    Elf32_Addr start_offset;
} elf_context ;

/* check for m68k ELF header and return 0 if found */
LONG elf_detect(FH h);

/* find bss, data, and text and symbol sections, put their info into context */
LONG elf_header_load(FH h, PGMHDR01 *pgm_hdr, elf_context* context);

/* actually load section data, relocate symbols, and populate the process descriptor */
LONG elf_do_load(PD* const pdptr, const PGMHDR01 *pgm_hdr, FH h, elf_context* const context);

#endif
