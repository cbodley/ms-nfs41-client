/* Copyright (c) 2010, 2011
 * The Regents of the University of Michigan
 * All Rights Reserved
 * 
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
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

#define NFSD_VERSION_MISMATCH 116

/* structures for upcall arguments */
typedef struct __mount_upcall_args {
    const char *hostname;
    const char *path;
    DWORD       sec_flavor;
} mount_upcall_args;

typedef struct __open_upcall_args {
    nfs41_abs_path symlink;
    FILE_BASIC_INFO basic_info;
    FILE_STANDARD_INFO std_info;
    const char *path;
    ULONG access_mask;
    ULONG access_mode; 
    ULONG file_attrs;
    ULONG disposition;
    ULONG create_opts;
    ULONG open_owner_id;
    DWORD mode;
    LONGLONG changeattr;
    BOOLEAN created;
    BOOLEAN symlink_embedded;
} open_upcall_args;

typedef struct __close_upcall_args {
    const char *path;
    BOOLEAN remove;
    BOOLEAN renamed;
} close_upcall_args;

typedef struct __readwrite_upcall_args {
    unsigned char *buffer;
    LONGLONG offset;
    ULONG len;
    ULONG out_len;
} readwrite_upcall_args;

typedef struct __lock_upcall_args {
    uint64_t offset;
    uint64_t length;
    BOOLEAN exclusive;
    BOOLEAN blocking;
    BOOLEAN acquired;
} lock_upcall_args;

typedef struct __unlock_upcall_args {
    uint32_t count;
    unsigned char *buf;
    uint32_t buf_len;
} unlock_upcall_args;

typedef struct __getattr_upcall_args {
    FILE_BASIC_INFO basic_info;
    FILE_STANDARD_INFO std_info;
    FILE_ATTRIBUTE_TAG_INFO tag_info;
    FILE_INTERNAL_INFORMATION intr_info;
    int query_class;
    int buf_len;
    int query_reply_len;
} getattr_upcall_args;

typedef struct __setattr_upcall_args {
    const char *path;
    nfs41_root *root;
    nfs41_open_state *state;
    unsigned char *buf;
    uint32_t buf_len;
    int set_class;
} setattr_upcall_args;

typedef struct __getexattr_upcall_args {
    const char *path;
    unsigned char *buf;
    uint32_t buf_len;
    ULONG eaindex;
    unsigned char *ealist;
    uint32_t ealist_len;
    BOOLEAN single;
    BOOLEAN restart;
} getexattr_upcall_args;


typedef struct __setexattr_upcall_args {
    const char *path;
    unsigned char *buf;
    uint32_t buf_len;
    uint32_t mode;
} setexattr_upcall_args;

typedef struct __readdir_upcall_args {
    const char *filter;
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

typedef struct __symlink_upcall_args {
    nfs41_abs_path target_get;
    char *target_set;
    const char *path;
    BOOLEAN set;
} symlink_upcall_args;

typedef struct __volume_upcall_args {
    FS_INFORMATION_CLASS query;
    int len;
    union {
        FILE_FS_SIZE_INFORMATION size;
        FILE_FS_FULL_SIZE_INFORMATION fullsize;
        FILE_FS_ATTRIBUTE_INFORMATION attribute;
    } info;
} volume_upcall_args;

typedef struct __getacl_upcall_args {
    SECURITY_INFORMATION query;
    PSECURITY_DESCRIPTOR sec_desc;
    DWORD sec_desc_len;
} getacl_upcall_args;

typedef struct __setacl_upcall_args {
    SECURITY_INFORMATION query;
    PSECURITY_DESCRIPTOR sec_desc;
} setacl_upcall_args;

typedef union __upcall_args {
    mount_upcall_args       mount;
    open_upcall_args        open;
    close_upcall_args       close;
    readwrite_upcall_args   rw;
    lock_upcall_args        lock;
    unlock_upcall_args      unlock;
    getattr_upcall_args     getattr;
    getexattr_upcall_args   getexattr;
    setattr_upcall_args     setattr;
    setexattr_upcall_args   setexattr;
    readdir_upcall_args     readdir;
    symlink_upcall_args     symlink;
    volume_upcall_args      volume;
    getacl_upcall_args      getacl;
    setacl_upcall_args      setacl;
} upcall_args;

typedef struct __nfs41_upcall {
    uint32_t                xid;
    uint32_t                opcode;
    uint32_t                status;
    uint32_t                last_error;
    upcall_args             args;

    uid_t                   uid;
    gid_t                   gid;

    /* store referenced pointers with the upcall for
     * automatic dereferencing on upcall_cleanup();
     * see upcall_root_ref() and upcall_open_state_ref() */
    nfs41_root              *root_ref;
    nfs41_open_state        *state_ref;
} nfs41_upcall;


/* upcall operation interface */
typedef int (*upcall_parse_proc)(unsigned char*, uint32_t, nfs41_upcall*);
typedef int (*upcall_handle_proc)(nfs41_upcall*);
typedef int (*upcall_marshall_proc)(unsigned char*, uint32_t*, nfs41_upcall*);
typedef void (*upcall_cancel_proc)(nfs41_upcall*);
typedef void (*upcall_cleanup_proc)(nfs41_upcall*);

typedef struct __nfs41_upcall_op {
    upcall_parse_proc       parse;
    upcall_handle_proc      handle;
    upcall_marshall_proc    marshall;
    upcall_cancel_proc      cancel;
    upcall_cleanup_proc     cleanup;
} nfs41_upcall_op;


/* upcall.c */
int upcall_parse(
    IN unsigned char *buffer,
    IN uint32_t length,
    OUT nfs41_upcall *upcall);

int upcall_handle(
    IN nfs41_upcall *upcall);

void upcall_marshall(
    IN nfs41_upcall *upcall,
    OUT unsigned char *buffer,
    IN uint32_t length,
    OUT uint32_t *length_out);

void upcall_cancel(
    IN nfs41_upcall *upcall);

void upcall_cleanup(
    IN nfs41_upcall *upcall);

#endif /* !__NFS41_DAEMON_UPCALL_H__ */
