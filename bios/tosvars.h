/*
 * tosvars.h - name of low-memory variables
 *
 * Copyright (c) 2001 EmuTOS development team
 *
 * Authors:
 *  LVL   Laurent Vogel
 *
 * This file is distributed under the GPL, version 2 or at your
 * option any later version.  See doc/license.txt for details.
 */

/*
 * Put in this file only the low-mem vars actually used by
 * C code.
 */

#ifndef _TOSVARS_H
#define _TOSVARS_H

#include "portab.h"

extern LONG proc_lives;
extern LONG proc_dregs[];
extern LONG proc_aregs[];
extern LONG proc_enum;
extern LONG proc_usp;
extern WORD proc_stk[];

extern BYTE conterm;

extern UBYTE *v_bas_ad;
extern LONG kbdvecs[];

extern WORD *colorptr;
extern UBYTE *screenpt;
extern BYTE sshiftmod;

extern VOID *phystop;

extern WORD timer_ms;

extern LONG hz_200;
extern LONG dskbufp;  
extern WORD flock;
extern WORD nflops;
extern LONG drvbits;
extern WORD bootdev;
extern WORD fverify;
extern WORD seekrate;
extern BYTE diskbuf[];
extern WORD dumpflg;
extern WORD nvbls;
extern WORD vblsem;
extern LONG vbl_list[];
extern LONG *vblqueue;


extern LONG sysbase;
extern VOID os_entry(VOID);
extern LONG os_beg;
extern LONG exec_os;
extern LONG end_os;
extern LONG m_start;
extern LONG m_length;

extern LONG os_end;
extern LONG membot;
extern LONG memtop;
extern LONG themd;

extern LONG savptr;
extern WORD save_area[];

extern VOID (*prt_stat)(VOID);
extern VOID (*prt_vec)(VOID);
extern VOID (*aux_stat)(VOID);
extern VOID (*aux_vec)(VOID);
extern VOID (*dump_vec)(VOID);

/* indirect BIOS vectors */

LONG (*hdv_rw)(WORD rw, LONG buf, WORD cnt, WORD recnr, WORD dev);
LONG (*hdv_bpb)(WORD dev);
LONG (*hdv_mediach)(WORD dev);
LONG (*hdv_boot)(VOID);
VOID (*hdv_init)(VOID);

VOID (*etv_timer)(VOID);
VOID (*etv_critic)(VOID);
VOID (*etv_term)(VOID);
VOID (*etv_xtra)(VOID);


#endif /* _TOSVARS_H */
