/*
 * elf.h - ELF32 m68k binary loading support
 *
 * Copyright (C) 2017 The EmuTOS development team.
 *
 * Authors:
 *  RWD   Ryan Daum
 *
 * This file is distributed under the GPL, version 2 or at your
 * option any later version.  See doc/license.txt for details.
 */

#define ENABLE_KDEBUG

#include "emutos.h"
#include "elf.h"
#include "gemerror.h"
#include "kprint.h"
#include "mem.h"
#include "portab.h"
#include "string.h"

typedef struct
{
    UBYTE jmp[2];
    void *start_addr;
} launch_thunk;

static LONG
elf_read_section(Elf32_Ehdr *hdr, FH h, Elf32_Word idx, Elf32_Shdr *shdr)
{
    LONG r;
    size_t n;

    // Seek into the file to the e_shoff and read it.
    n = hdr->e_shoff + (idx * hdr->e_shentsize);
    r = xlseek((LONG) n, h, 0);
    if (r < 0)
        return r;
    return xread(h, hdr->e_shentsize, shdr);
}

static Elf32_Shdr *elf_get_section(elf_context *elf, Elf32_Word idx)
{
    return &elf->sections[idx].elf_section_header;
}

static LONG elf_get_symbol(const Elf32_Shdr *symtabsection,
                           LONG sym_num, Elf32_Sym **out_symbol)
{
    Elf32_Off offset = (sym_num * sizeof(Elf32_Sym));

    *out_symbol = (void *) (symtabsection->sh_addr + offset);
    return 0;
}

static const char *elf_get_symname(const Elf32_Shdr *strtab, Elf32_Word offset)
{
    return (const char *) (strtab->sh_addr + offset);
}

static LONG
elf_find_symbol(const Elf32_Shdr *symtab_section,
                const Elf32_Shdr *strtab_section,
                const char *symbol, Elf32_Sym **const out_symbol)
{
    LONG num_syms;
    LONG sym_num;
    Elf32_Sym *cur_symbol;
    LONG r;

    num_syms = symtab_section->sh_size / symtab_section->sh_entsize;
    for (sym_num = 0; sym_num < num_syms; sym_num++) {
        r = elf_get_symbol(symtab_section, sym_num, &cur_symbol);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not get symbol #0x%08lx\n", sym_num));
            return r;
        }

        // Get the offset into the string table.
        Elf32_Addr name_addr = cur_symbol->st_name;

        const char *symname = elf_get_symname(strtab_section, name_addr);
        if (strcmp(symname, symbol) == 0) {
            *out_symbol = cur_symbol;
            return 0;
        }
    }
    return -1;
}

static LONG elf_get_symval(FH h, elf_context *elf, Elf32_Sym *sym, Elf32_Addr *out_value)
{
    LONG r;
    Elf32_Addr sym_sec_base;
    const Elf32_Shdr *strtab, *symtab;
    Elf32_Sym *target_symbol;
    const char *symname;

    switch (sym->st_shndx) {
        case SHN_UNDEF:
            symtab = elf->symtab;
            strtab = elf_get_section(elf, symtab->sh_link);
            symname = elf_get_symname(strtab, sym->st_name);
            if (!symname) {
                KDEBUG(("BDOS elf: SHN_UNDEF unable to symbol name\n"));
                return EPLFMT;
            }
            r = elf_find_symbol(symtab, elf_get_section(elf, symtab->sh_link), symname, &target_symbol);
            if (r < 0) {
                if (ELF32_ST_BIND(sym->st_info) & STB_WEAK) {
                    *out_value = 0;
                    return 0;
                }
                KDEBUG(("BDOS elf: SHN_UNDEF exported target symbol (%s) not found\n", symname));
                return r;
            }
            return target_symbol->st_value;
        case SHN_COMMON:KDEBUG(("BDOS elf: invalid symbol section SHN_COMMON; recompile with -fno-common\n"));
            return EPLFMT;
        case SHN_ABS:*out_value = sym->st_value;
            return 0;
        default:
            sym_sec_base = (Elf32_Addr) elf->sections[sym->st_shndx].dest_addr;
            if (!sym_sec_base) {
                KDEBUG(("BDOS elf: unmapped segment #%d sh_addr 0x%08lx\n", sym->st_shndx, elf->sections[sym->st_shndx]
                    .elf_section_header.sh_addr));
                return -1;
            }
            *out_value = sym->st_value + sym_sec_base
                - elf->sections[sym->st_shndx].elf_section_header.sh_addr;
            return 0;
    }
}

static LONG elf_find_sections(Elf32_Ehdr *hdr, FH h, elf_context *context)
{
    LONG r;
    Elf32_Half i;
    enum SHT_Type sht_type;

    KDEBUG(("BDOS elf: %d sections...\n", hdr->e_shnum));
    // Iterate over section headers.
    for (i = 0; i < hdr->e_shnum; i++) {
        elf_section_decl *context_section =
            &context->sections[context->num_sections++];

        context_section->dest_addr = NULL;

        r = elf_read_section(hdr, h, i, &context_section->elf_section_header);
        if (r < 0) {
            KDEBUG(("BDOS elf: unable to load section #%ud\n", i));
            return r;
        }
        context_section->elf_section_number = i;
        sht_type = (enum SHT_Type) context_section->elf_section_header.sh_type;
        Elf32_Word flags = context_section->elf_section_header.sh_flags;

        if (sht_type == SHT_NOBITS && flags & SHF_ALLOC
            && flags & SHF_WRITE) {
            context_section->section_type = ELF32_SECTION_BSS;
        } else if (sht_type == SHT_PROGBITS
            && flags == (SHF_ALLOC | SHF_EXECINSTR)) {
            context_section->section_type = ELF32_SECTION_TEXT;
        } else if (sht_type == SHT_PROGBITS && flags & SHF_ALLOC) {
            context_section->section_type = ELF32_SECTION_DATA;
        } else if (sht_type == SHT_STRTAB && i != hdr->e_shstrndx) {
            context_section->section_type = ELF32_SECTION_STRTAB;
        } else if (sht_type == SHT_SYMTAB) {
            context_section->section_type = ELF32_SECTION_SYMTAB;
        } else if (sht_type == SHT_STRTAB && i == hdr->e_shstrndx) {
            context_section->section_type = ELF32_SECTION_SHTRTAB;
        } else {
            context_section->section_type = ELF32_SECTION_OTHER;
        }
    }
    return 0;
}

static int
elf_check_header(Elf32_Ehdr *hdr)
{
    if (!hdr)
        return -1;
    if (hdr->e_ident[EI_MAG0] != ELFMAG0) {
        KDEBUG(("BDOS elf: ELF Header EI_MAG0 incorrect.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_MAG1] != ELFMAG1) {
        KDEBUG(("BDOS elf: ELF Header EI_MAG1 incorrect.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_MAG2] != ELFMAG2) {
        KDEBUG(("BDOS elf: ELF Header EI_MAG2 incorrect.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_MAG3] != ELFMAG3) {
        KDEBUG(("BDOS elf: ELF Header EI_MAG3 incorrect.\n"));
        return -1;
    }
    return 0;
}

static int
elf_check_supported(Elf32_Ehdr *hdr)
{
    if (elf_check_header(hdr) < 0) {
        KDEBUG(("BDOS elf: Invalid ELF File.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_CLASS] != ELFCLASS32) {
        KDEBUG(("BDOS elf: Unsupported ELF File Class.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_DATA] != ELFDATA2MSB) {
        KDEBUG(("BDOS elf: Unsupported ELF File UBYTE order.\n"));
        return -1;
    }
    if (hdr->e_machine != EM_M68k) {
        KDEBUG(("BDOS elf: Unsupported ELF File target.\n"));
        return -1;
    }
    if (hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        KDEBUG(("BDOS elf: Unsupported ELF File version.\n"));
        return -1;
    }
    if (hdr->e_type != ET_EXEC) {
        KDEBUG(("BDOS elf: Unsupported ELF File type.\n"));
        return -1;
    }
    return 0;
}

static LONG elf_read_header(FH h, Elf32_Ehdr *hdr)
{
    LONG r;

    /* Read the ELF header */
    r = xlseek(0, h, 0);
    if (r < 0) {
        KDEBUG(("BDOS elf: Cannot seek file begin\n"));

        return ERANGE;
    }
    r = xread(h, sizeof(Elf32_Ehdr), hdr); /* read elf header */
    if (r != sizeof(Elf32_Ehdr)) {
        KDEBUG(("BDOS elf: Cannot read elf header\n"));
        return ERANGE;
    }
    if (elf_check_supported(hdr) < 0) {
        KDEBUG(("BDOS elf: ELF File cannot be loaded.\n"));
        return EPLFMT;
    }
    switch (hdr->e_type) {
        case ET_EXEC:
            return 0;
        default:
            KDEBUG(("BDOS elf: Unsupported ELF type\n"));
            return EPLFMT;
    }
}

LONG elf_header_load(FH h, PGMHDR01 *pgm_hdr, elf_context *context)
{
    Elf32_Half i;
    LONG r;
    elf_section_decl *section;

    context->num_sections = 0;

    bzero(pgm_hdr, sizeof(PGMHDR01));
    context->strtab = NULL;
    context->shtrtab = NULL;
    context->symtab = NULL;

    /* Read the ELF header */
    r = elf_read_header(h, &context->elf_hdr);
    if (r < 0) {
        return r;
    }

    r = elf_find_sections(&context->elf_hdr, h, context);
    if (r < 0) {
        return r;
    }

    /* Verify that there's at least one text section, adjust size allocated for
     * text, data, and bss, and find the symtab and strtab sections */
    for (i = 0; i < context->num_sections; i++) {
        section = &context->sections[i];
        section->dest_addr = NULL;
        switch (section->section_type) {
        case ELF32_SECTION_BSS:
          pgm_hdr->h01_blen += section->elf_section_header.sh_size;;
          KDEBUG(("BDOS elf: found bss %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_DATA:
          pgm_hdr->h01_dlen += section->elf_section_header.sh_size;;
          KDEBUG(("BDOS elf: found data %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_TEXT:
          pgm_hdr->h01_tlen += section->elf_section_header.sh_size;
          KDEBUG(("BDOS elf: found text %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_SYMTAB:
          pgm_hdr->h01_slen += section->elf_section_header.sh_size;;
          KDEBUG(("BDOS elf: found symbol %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_STRTAB:
          pgm_hdr->h01_slen += section->elf_section_header.sh_size;;
          KDEBUG(("BDOS elf: found symbol %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_SHTRTAB:
          pgm_hdr->h01_slen += section->elf_section_header.sh_size;;
          KDEBUG(("BDOS elf: found symbol %d, sh_addr: 0x%08lx sh_offset 0x%08lx "
                  "sh_size: 0x%08lx\n",
                  i,
                  section->elf_section_header.sh_addr,
                  section->elf_section_header.sh_offset, section
                                                             ->elf_section_header.sh_size));
          break;
        case ELF32_SECTION_OTHER:
        default:
          KDEBUG(("BDOS elf: unhandled ELF32 section type: %d\n",
                  section->section_type));
          break;
        }
    }
    if (!pgm_hdr->h01_tlen) {
        KDEBUG(("BDOS elf: missing .text section\n"));
        return EPLFMT;
    }

    /* expand the text segment by enough to add our jmp instruction to __start */
    pgm_hdr->h01_tlen += sizeof(launch_thunk);

    return 0;
}

LONG elf_detect(FH h)
{
    Elf32_Ehdr hdr;

    return elf_read_header(h, &hdr);
}

static LONG elf_do_reloc_section(FH h, elf_context *elf, enum SHT_Type type,
                                 Elf32_Shdr *rels)
{
    LONG r;
    Elf32_Rela rel;
    Elf32_Sym *sym;
    Elf32_Addr dst_addr_base, dst_addr, value;
    Elf32_Word i;
    Elf32_Off offset;
    Elf32_Word r_sym;
    Elf32_Word r_type;
    Elf32_Word num_rels;
    const char *section_name, *symbol_name;
    elf_section_decl *dstsec;

    dstsec = &elf->sections[rels->sh_info];
    dst_addr_base = (Elf32_Addr) dstsec->dest_addr;

    // Get the reltabs for the section.
    num_rels = rels->sh_size / rels->sh_entsize;
    for (i = 0; i < num_rels; i++) {
        offset = rels->sh_offset + (i * rels->sh_entsize);

        r = xlseek(offset, h, 0);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not seek Elf32_Rela\n"));
            return r;
        }

        bzero(&rel, sizeof(rel));
        r = xread(h, type == SHT_REL ? sizeof(Elf32_Rel) : sizeof(Elf32_Rela), &rel);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not read rel\n"));
            return r;
        }

        r_type = ELF32_R_TYPE(rel.r_info);
        r_sym = ELF32_R_SYM(rel.r_info);

        r = elf_get_symbol(elf->symtab,
                           r_sym,
                           &sym);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not look up symbol\n"));
            return EPLFMT;
        }
        value = 0;
        r = elf_get_symval(h, elf, sym, &value);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not get symbol value\n"));
            return EPLFMT;
        }

        /* name for debugging purposes... */
        section_name = elf_get_symname(elf->shtrtab,
                                       elf->sections[sym->st_shndx].elf_section_header.sh_name);
        if (!section_name) {
            KDEBUG(("BDOS elf: could not get section name\n"));
            return EPLFMT;
        }

        Elf32_Shdr *symtab = &elf->sections[rels->sh_link].elf_section_header;
        Elf32_Shdr *strtab = &elf->sections[symtab->sh_link].elf_section_header;

        symbol_name = elf_get_symname(strtab, sym->st_name);
        if (r < 0) {
            KDEBUG(("BDOS elf: could not get symbol name\n"));
            return EPLFMT;
        }

        /* calculate the relocation address */
        if (dst_addr_base == 0x0) {
            KDEBUG(("BDOS elf: could not find mapped target address for section: %zd\n", rels
                ->sh_info));
            return EPLFMT;
        }
        dst_addr = dst_addr_base + rel.r_offset - dstsec->elf_section_header.sh_addr;

        /* verify the relocated section is inside our allocated address range */
        if (dst_addr < elf->pd->p_lowtpa || dst_addr > elf->pd->p_hitpa) {
            KDEBUG(("BDOS elf: invalid relocation destination address: 0x%08lx for %s.%s\n",
                dst_addr, section_name, symbol_name));
            return EPLFMT;
        }
        value += rel.r_addend;

        /* verify the relocated value itself is inside the address range */
        if (value < elf->pd->p_lowtpa || value > elf->pd->p_hitpa ) {
            KDEBUG(("BDOS elf: invalid relocation? for symbol %s.%s: %p %p %p\n",
                section_name, symbol_name, dst_addr, *((Elf32_Addr *) dst_addr),
                value));
        }
        switch (r_type) {
            case R_68K_32:
                *((Elf32_Addr *) dst_addr) = value;
                break;
            case R_68K_PC32:*((Elf32_Addr *) dst_addr) += value - dst_addr;
            default:
                KDEBUG(("BDOS elf: unhandled relocation of type %zd for %s.%s\n", r_type,
                    section_name, symbol_name));
                return EPLFMT;
        }
    }
    return 0;
}

/*
 * Iterate through all relocation sections in the file and attempt
 * to perform the relocations pointed to by them.
 */
static int elf_perform_relocations(FH h, elf_context *elf)
{
    Elf32_Shdr *rels, *strtab, *symtab;
    Elf32_Addr i, count;
    enum SHT_Type type;
    LONG r;
    count = elf->num_sections;
    for (i = 0; i < count; i++) {
        rels = elf_get_section(elf, i);
        type = (enum SHT_Type) rels->sh_type;
        if (type != SHT_REL && type != SHT_RELA) {
            continue;
        }
        strtab = elf_get_section(elf, rels->sh_info);
        symtab = elf_get_section(elf, rels->sh_link);
        if (NULL == strtab || NULL == symtab)
            continue;

        if (!(strtab->sh_flags & SHF_ALLOC)) {
            continue;
        }

        r = elf_do_reloc_section(h, elf, type, rels);
        if (r != 0) {
            KDEBUG(("BDOS elf: unable to complete relocations %ld\n", r));
            return EPLFMT;
        }
    }
    return 0;
}

static LONG elf_load_section(elf_section_decl *section, FH h, void *dest)
{
    LONG r;
    r = xlseek(section->elf_section_header.sh_offset, h, 0);
    if (r < 0) {
        KDEBUG(("BDOS elf: could not seek section data at offset: 0x%08lx with file: %d\n",
            section->elf_section_header.sh_offset, h));

        return r;
    }
    r = xread(h, section->elf_section_header.sh_size, dest);
    if (r != section->elf_section_header.sh_size) {
        KDEBUG(("BDOS elf: could not read section into memory\n"));

        return r;
    }
    section->dest_addr = dest;

    return r;
}

static LONG elf_load_symbol_tables(elf_context *const context,
                                   FH h, void *sbase)
{
    LONG r;
    ptrdiff_t offset = 0;
    Elf32_Off i;
    Elf32_Shdr *section_header;
    elf_section_decl *section;

    for (i = 0; i < context->num_sections; i++) {
        section = &context->sections[i];
        section_header = &section->elf_section_header;

        switch (section->section_type) {
        case ELF32_SECTION_SYMTAB:
          r = elf_load_section(section, h, sbase + offset);
          if (r < 0) {
            KDEBUG(("BDOS elf: could not load symtab\n"));
          }
          section_header->sh_addr = (Elf32_Addr) sbase + offset;
          offset += r;
          KDEBUG(("BDOS elf: loaded symtab to %p\n", sbase + offset));
          context->symtab = section_header;
          break;
        case ELF32_SECTION_STRTAB:
          r = elf_load_section(section, h, sbase + offset);
          if (r < 0) {
            KDEBUG(("BDOS elf: could not load strtab\n"));
          }
          section_header->sh_addr = (Elf32_Addr) sbase + offset;
          offset += r;
          KDEBUG(("BDOS elf: loaded strtab to %p\n", sbase + offset));
          context->strtab = section_header;
          break;
        case ELF32_SECTION_SHTRTAB:
          r = elf_load_section(section, h, sbase + offset);
          if (r < 0) {
            KDEBUG(("BDOS elf: could not load shtrtab\n"));
          }
          section_header->sh_addr = (Elf32_Addr) sbase + offset;
          offset += r;
          KDEBUG(("BDOS elf: loaded shtrtab to %p\n", sbase + offset));
          context->shtrtab = section_header;
          break;
        default:
          break;
        }
    }

    /* now look for __start and remember it. The program is invalid without it */
    Elf32_Sym *start_symbol;
    r = elf_find_symbol(context->symtab,
                        context->strtab,
                        "__start",
                        &start_symbol);
    if (r < 0) {
        KDEBUG(("BDOS elf: could not find __start symbol\n"));
        return EPLFMT;
    }
    context->start_offset = start_symbol->st_value;
    KDEBUG(("BDOS elf: _start found at: 0x%08lx\n", start_symbol->st_value));

    return r;
}

static LONG elf_load_sections_of_type(FH h, elf_context *context,
                               const enum Elf32SectionType section_type,
                               void *dest)
{
    Elf32_Half i, x;
    LONG r;
    for (i = 0; i < context->num_sections; i++) {
        elf_section_decl *section = &context->sections[i];
        if (section->section_type == section_type) {
            r = elf_load_section(section, h, dest);
            if (r < 0) {
                return r;
            }

            // Also mark all other sections that have the shame sh_addr as having this dest address.
            for (x = 0; x < context->num_sections; x++) {
                if (x != i
                    && context->sections[x].elf_section_header.sh_addr == section->elf_section_header.sh_addr) {
                    KDEBUG(("BDOS elf: setting dest_addr for %d: sh_addr(0x%08lx) => %p\n", x, context->sections[x]
                        .elf_section_header.sh_addr, dest));
                    context->sections[x].dest_addr = dest;
                }
            }

            dest += section->elf_section_header.sh_size;
        }
    }
    return 0;
}

static LONG
elf_load_exec(elf_context *const context,
              FH h,
              PD *const pdptr,
              const PGMHDR01 *pgmhdr)
{
    LONG r;
    UBYTE *sbase, *text_base, *data_base, *bss_base;
    size_t text_used;

    /* set initial PD fields from pgmhdr */
    pdptr->p_tlen = pgmhdr->h01_tlen;
    pdptr->p_dlen = pgmhdr->h01_dlen;
    pdptr->p_blen = pgmhdr->h01_blen;

    context->pd = pdptr;

    pdptr->p_tbase = ((void *) pdptr + sizeof(PD));   /*  1st UBYTE after PD   */
    pdptr->p_dbase = pdptr->p_tbase + pdptr->p_tlen;
    pdptr->p_bbase = pdptr->p_dbase + pdptr->p_dlen;
    sbase = pdptr->p_bbase + pdptr->p_blen;

    KDEBUG(("BDOS elf: p_tbase/len = 0x%08lx/0x%08lx, p_dbase/len = 0x%08lx/0x%08lx, "
        "p_bbase/len = 0x%08lx/0x%08lx sbase/len =  %p/0x%08lx\n",
        pdptr->p_tbase, pdptr->p_tlen,
        pdptr->p_dbase, pdptr->p_dlen,
        pdptr->p_bbase, pdptr->p_blen,
        sbase, pgmhdr->h01_slen));

    /* load symbol tables into allocated symbol area, and find __start */
    r = elf_load_symbol_tables(context, h, sbase);
    if (r < 0) {
        return r;
    }

    /* zero out the text segment */
    KDEBUG(("BDOS elf: zero text segment\n"));
    text_base = (UBYTE *) pdptr->p_tbase;
    bzero(text_base, (size_t) pdptr->p_tlen);

    KDEBUG(("BDOS elf: prepare thunk at %p to %p\n", text_base, text_base + sizeof(launch_thunk)));

    /* since ld can put our __start anywhere, but proc.c expects that the first thing
     * we execute be at the beginning of the text segment, we insert a JMP to __start
     * at the beginning of the text segment. */
    launch_thunk thunk = {
        .jmp = {0x4e, 0xf9},
        .start_addr = text_base + sizeof(launch_thunk) + context->start_offset
    };
    *((launch_thunk *) &text_base[0]) = thunk;
    text_used = sizeof(launch_thunk);

    /* now copy the actual text segments into our allocated area just beyond the thunk */
    KDEBUG(("BDOS elf: copy text segment from %p to %p\n", text_base + text_used,
        text_base + pdptr->p_tlen));
    r = elf_load_sections_of_type(h, context, ELF32_SECTION_TEXT,
                              text_base + text_used);
    if (r < 0) {
        return r;
    }

    /* copy data segments over */
    KDEBUG(("BDOS elf: zero data segment @ 0x%08lx size: 0x%08lx\n",
        pdptr->p_dbase, pdptr->p_dlen));
    data_base = (void *) pdptr->p_dbase;
    bzero(data_base, (size_t) pdptr->p_dlen);
    KDEBUG(("BDOS elf: copy data segment\n"));

    r = elf_load_sections_of_type(h, context,
                              ELF32_SECTION_DATA, data_base);
    if (r < 0) {
        return r;
    }

    /* zero the bss */
    KDEBUG(("BDOS elf: zero bss segment\n"));
    bss_base = (void *) pdptr->p_bbase;
    bzero(bss_base, (size_t) pdptr->p_blen);

    KDEBUG(("BDOS elf: segments loaded, now performing relocations...\n"));

    /* finally, perform all symbol relocations */
    r = elf_perform_relocations(h, context);
    if (r < 0) {
        return EPLFMT;
    }

    return 0;
}

LONG elf_do_load(PD *const pdptr, const PGMHDR01 *pgm_hdr,
                 FH h, elf_context *const context)
{
    LONG r;
    r = elf_load_exec(context, h, pdptr, pgm_hdr);

    xclose(h);

    return r;
}
