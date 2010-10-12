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

#ifndef __NFS41_DAEMON_UPCALL_H__
#define __NFS41_DAEMON_UPCALL_H__

#include "nfs41_ops.h"
#include "from_kernel.h"


/* structures for upcall arguments */
typedef struct __mount_upcall_args {
    char srv_name[UPCALL_BUF_SIZE];
    nfs41_abs_path path;
    nfs41_root *root;
} mount_upcall_args;

typedef struct __unmount_upcall_args {
    nfs41_root *root;
} unmount_upcall_args;

typedef struct __open_upcall_args {
    nfs41_abs_path path;
    FILE_BASIC_INFO basic_info;
    FILE_STANDARD_INFO std_info;
    nfs41_root *root;
    nfs41_open_state *state;
    ULONG access_mask;
    ULONG access_mode; 
    ULONG file_attrs;
    ULONG disposition;
    ULONG create_opts;
    ULONG open_owner_id;
    DWORD mode;
    LONGLONG changeattr;
    BOOLEAN created;
} open_upcall_args;

typedef struct __close_upcall_args {
    nfs41_abs_path path;
    nfs41_root *root;
    nfs41_open_state *state;
    BOOLEAN remove;
    BOOLEAN renamed;
} close_upcall_args;

typedef struct __readwrite_upcall_args {
    nfs41_root *root;
    nfs41_open_state *state;
    unsigned char *buffer;
    LONGLONG offset;
    ULONG len;
    ULONG out_len;
} readwrite_upcall_args;

typedef struct __lock_upcall_args {
    nfs41_open_state *state;
    nfs41_root *root;
    LONGLONG offset;
    LONGLONG length;
    BOOLEAN exclusive;
    BOOLEAN blocking;
} lock_upcall_args;

typedef struct __unlock_upcall_args {
    nfs41_open_state *state;
    nfs41_root *root;
    uint32_t count;
    unsigned char *buf;
    uint32_t buf_len;
} unlock_upcall_args;

typedef struct __getattr_upcall_args {
    FILE_BASIC_INFO basic_info;
    FILE_STANDARD_INFO std_info;
    FILE_ATTRIBUTE_TAG_INFO tag_info;
    nfs41_root *root;
    nfs41_open_state *state;
    int query_class;
    int buf_len;
    int query_reply_len;
} getattr_upcall_args;

typedef struct __setattr_upcall_args {
    nfs41_abs_path path;
    nfs41_root *root;
    nfs41_open_state *state;
    unsigned char *buf;
    uint32_t buf_len;
    int set_class;
    ULONG open_owner_id;
    ULONG access_mask;
    ULONG access_mode; 
} setattr_upcall_args;

typedef struct __setexattr_upcall_args {
    nfs41_root *root;
    nfs41_open_state *state;
    uint32_t mode;
} setexattr_upcall_args;

typedef struct __readdir_upcall_args {
    char filter[UPCALL_BUF_SIZE];
    nfs41_readdir_cookie *cookie;
    nfs41_root *root;
    nfs41_open_state *state;
    unsigned char *buf;
    int buf_len;
    int query_class;
    int query_reply_len;
    BOOLEAN initial;
    BOOLEAN restart;
    BOOLEAN single;
} readdir_upcall_args;

typedef struct __volume_upcall_args {
    nfs41_root *root;
    FS_INFORMATION_CLASS query;
    int len;
    union {
        FILE_FS_SIZE_INFORMATION size;
        FILE_FS_FULL_SIZE_INFORMATION fullsize;
        FILE_FS_ATTRIBUTE_INFORMATION attribute;
    } info;
} volume_upcall_args;

typedef union __upcall_args {
    mount_upcall_args       mount;
    unmount_upcall_args     unmount;
    open_upcall_args        open;
    close_upcall_args       close;
    readwrite_upcall_args   rw;
    lock_upcall_args        lock;
    unlock_upcall_args      unlock;
    getattr_upcall_args     getattr;
    setattr_upcall_args     setattr;
    setexattr_upcall_args   setexattr;
    readdir_upcall_args     readdir;
    volume_upcall_args      volume;
} upcall_args;

typedef struct __nfs41_upcall {
    uint32_t                xid;
    uint32_t                opcode;
    uint32_t                status;
    uint32_t                last_error;
    upcall_args             args;
    char                    sid[SECURITY_MAX_SID_SIZE];
} nfs41_upcall;


/* upcall operation interface */
typedef int (*upcall_parse_proc)(unsigned char*, uint32_t, nfs41_upcall*);
typedef int (*upcall_handle_proc)(nfs41_upcall*);
typedef int (*upcall_marshall_proc)(unsigned char*, uint32_t*, nfs41_upcall*);
typedef int (*upcall_cancel_proc)(nfs41_upcall*);

typedef struct __nfs41_upcall_op {
    upcall_parse_proc       parse;
    upcall_handle_proc      handle;
    upcall_marshall_proc    marshall;
    upcall_cancel_proc      cancel;
} nfs41_upcall_op;


/* upcall.c */
int upcall_parse(
    IN unsigned char *buffer,
    IN uint32_t length,
    OUT nfs41_upcall *upcall);

int upcall_handle(
    IN nfs41_upcall *upcall);

int upcall_marshall(
    IN nfs41_upcall *upcall,
    OUT unsigned char *buffer,
    IN uint32_t length,
    OUT uint32_t *length_out);

int upcall_cancel(
    IN nfs41_upcall *upcall);

#endif /* !__NFS41_DAEMON_UPCALL_H__ */
