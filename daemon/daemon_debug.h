/* Copyright (c) 2010
 * The Regents of the University of Michigan
 * All Rights Reserved
 *
 * Permission is granted to use, copy and redistribute this software
 * for noncommercial education and research purposes, so long as no
 * fee is charged, and so long as the name of the University of Michigan
 * is not used in any advertising or publicity pertaining to the use
 * or distribution of this software without specific, written prior
 * authorization.  Permission to modify or otherwise create derivative
 * works of this software is not granted.
 *
 * This software is provided as is, without representation or warranty
 * of any kind either express or implied, including without limitation
 * the implied warranties of merchantability, fitness for a particular
 * purpose, or noninfringement.  The Regents of the University of
 * Michigan shall not be liable for any damages, including special,
 * indirect, incidental, or consequential damages, with respect to any
 * claim arising out of or in connection with the use of the software,
 * even if it has been or is hereafter advised of the possibility of
 * such damages.
 */

#ifndef _DAEMON_DEBUG_
#define _DAEMON_DEBUG_

#ifdef _DEBUG
/* use visual studio's debug heap */
# define _CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h>
#else
# include <stdlib.h>
#endif

#define DEFAULT_DEBUG_LEVEL 1


/* daemon_debug.h */
void set_debug_level(int level);
void dprintf(int level, LPCSTR format, ...);
void eprintf(LPCSTR format, ...);

void print_hexbuf_no_asci(int on, unsigned char *title, unsigned char *buf, int len);
void print_hexbuf(int level, unsigned char *title, unsigned char *buf, int len);
void print_create_attributes(int level, DWORD create_opts);
void print_disposition(int level, DWORD disposition);
void print_access_mask(int level, DWORD access_mask);
void print_share_mode(int level, DWORD mode);
void print_file_id_both_dir_info(int level, FILE_ID_BOTH_DIR_INFO *p);
void print_opcode(int level, DWORD opcode);
const char* opcode2string(DWORD opcode);
const char* nfs_opnum_to_string(int opnum);
const char* nfs_error_string(int status);
void print_condwait_status(int level, int status);
void print_sr_status_flags(int level, int flags);
void open_log_files();
void close_log_files();
const char* secflavorop2name(DWORD sec_flavor);

/* pnfs_debug.c */
enum pnfs_status;
enum pnfs_layout_type;
enum pnfs_iomode;
struct __pnfs_file_layout;
struct __pnfs_file_device;

const char* pnfs_error_string(enum pnfs_status status);
const char* pnfs_layout_type_string(enum pnfs_layout_type type);
const char* pnfs_iomode_string(enum pnfs_iomode iomode);

void dprint_deviceid(int level, const char *title, const unsigned char *deviceid);
void dprint_layout(int level, const struct __pnfs_file_layout *layout);
void dprint_device(int level, const struct __pnfs_file_device *device);

#endif
