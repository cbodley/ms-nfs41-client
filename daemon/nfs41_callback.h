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

#ifndef __NFS41_CALLBACK_H__
#define __NFS41_CALLBACK_H__

#include "wintirpc.h"
#include "rpc/rpc.h"
#include "nfs41_types.h"


enum nfs41_callback_proc {
    CB_NULL                 = 0,
    CB_COMPOUND             = 1,
};

enum nfs41_callback_op {
    OP_CB_GETATTR           = 3,
    OP_CB_RECALL            = 4,
    OP_CB_LAYOUTRECALL      = 5,
    OP_CB_NOTIFY            = 6,
    OP_CB_PUSH_DELEG        = 7,
    OP_CB_RECALL_ANY        = 8,
    OP_CB_RECALLABLE_OBJ_AVAIL = 9,
    OP_CB_RECALL_SLOT       = 10,
    OP_CB_SEQUENCE          = 11,
    OP_CB_WANTS_CANCELLED   = 12,
    OP_CB_NOTIFY_LOCK       = 13,
    OP_CB_NOTIFY_DEVICEID   = 14,
    OP_CB_ILLEGAL           = 10044
};

int nfs41_handle_callback(void *, void *, void *);

/* OP_CB_LAYOUTRECALL */
struct cb_recall_file {
    nfs41_fh                fh;
    uint64_t                offset;
    uint64_t                length;
    stateid4                stateid;
};
union cb_recall_file_args {
    struct cb_recall_file   file;
    nfs41_fsid              fsid;
};
struct cb_recall {
    enum pnfs_return_type   type;
    union cb_recall_file_args args;
};
struct cb_layoutrecall_args {
    enum pnfs_layout_type   type;
    enum pnfs_iomode        iomode;
    bool_t                  changed;
    struct cb_recall        recall;
};

struct cb_layoutrecall_res {
    enum_t                  status;
};

/* OP_CB_RECALL_SLOT */
struct cb_recall_slot_args {
    uint32_t                target_highest_slotid;
};

struct cb_recall_slot_res {
    enum_t                  status;
};

/* OP_CB_SEQUENCE */
struct cb_sequence_ref {
    uint32_t                sequenceid;
    uint32_t                slotid;
};
struct cb_sequence_ref_list {
    char                    sessionid[NFS4_SESSIONID_SIZE];
    struct cb_sequence_ref  *calls;
    uint32_t                call_count;
};
struct cb_sequence_args {
    char                    sessionid[NFS4_SESSIONID_SIZE];
    uint32_t                sequenceid;
    uint32_t                slotid;
    uint32_t                highest_slotid;
    bool_t                  cachethis;
    struct cb_sequence_ref_list *ref_lists;
    uint32_t                ref_list_count;
};

struct cb_sequence_res_ok {
    char                    sessionid[NFS4_SESSIONID_SIZE];
    uint32_t                sequenceid;
    uint32_t                slotid;
    uint32_t                highest_slotid;
    uint32_t                target_highest_slotid;
};
struct cb_sequence_res {
    enum_t                  status;
    struct cb_sequence_res_ok ok;
};

/* OP_CB_GETATTR */
struct cb_getattr_args {
    nfs41_fh                fh;
    bitmap4                 attr_request;
};

struct cb_getattr_res {
    enum_t                  status;
    nfs41_file_info         info;
};

/* OP_CB_RECALL */
struct cb_recall_args {
    stateid4                stateid;
    bool_t                  truncate;
    nfs41_fh                fh;
};

struct cb_recall_res {
    enum_t                  status;
};

/* OP_CB_NOTIFY */
struct cb_notify_args {
    uint32_t                target_highest_slotid;
};

struct cb_notify_res {
    enum_t                  status;
};

/* OP_CB_PUSH_DELEG */
struct cb_push_deleg_args {
    uint32_t                target_highest_slotid;
};

struct cb_push_deleg_res {
    enum_t                  status;
};

/* OP_CB_RECALL_ANY */
struct cb_recall_any_args {
    uint32_t                target_highest_slotid;
};

struct cb_recall_any_res {
    enum_t                  status;
};

/* OP_CB_RECALLABLE_OBJ_AVAIL */
struct cb_recallable_obj_avail_args {
    uint32_t                target_highest_slotid;
};

struct cb_recallable_obj_avail_res {
    enum_t                  status;
};

/* OP_CB_WANTS_CANCELLED */
struct cb_wants_cancelled_args {
    uint32_t                target_highest_slotid;
};

struct cb_wants_cancelled_res {
    enum_t                  status;
};

/* OP_CB_NOTIFY_LOCK */
struct cb_notify_lock_args {
    uint32_t                target_highest_slotid;
};

struct cb_notify_lock_res {
    enum_t                  status;
};

/* OP_CB_NOTIFY_DEVICEID */
enum notify_deviceid_type4 {
    NOTIFY_DEVICEID4_CHANGE = 1,
    NOTIFY_DEVICEID4_DELETE = 2
};
struct notify_deviceid4 {
    unsigned char           deviceid[16];
    enum notify_deviceid_type4 type;
    enum pnfs_layout_type   layouttype;
    bool_t                  immediate;
};
struct notify4 {
    bitmap4                 mask;
    char                    *list;
    uint32_t                len;
};
struct cb_notify_deviceid_args {
    struct notify4          *notify_list;
    uint32_t                notify_count;
    struct notify_deviceid4 *change_list;
    uint32_t                change_count;
};

struct cb_notify_deviceid_res {
    enum_t                  status;
};

/* CB_COMPOUND */
#define CB_COMPOUND_MAX_TAG         64
#define CB_COMPOUND_MAX_OPERATIONS  16

union cb_op_args {
    struct cb_layoutrecall_args layoutrecall;
    struct cb_recall_slot_args recall_slot;
    struct cb_sequence_args sequence;
    struct cb_getattr_args  getattr;
    struct cb_recall_args   recall;
    struct cb_notify_deviceid_args notify_deviceid;
};
struct cb_argop {
    enum_t                  opnum;
    union cb_op_args        args;
};
struct cb_compound_tag {
    char                    str[CB_COMPOUND_MAX_TAG];
    uint32_t                len;
};
struct cb_compound_args {
    struct cb_compound_tag  tag;
    uint32_t                minorversion;
    uint32_t                callback_ident; /* client MUST ignore */
    struct cb_argop         *argarray;
    uint32_t                argarray_count; /* <= CB_COMPOUND_MAX_OPERATIONS */
};

union cb_op_res {
    enum_t                  status; /* all results start with status */ 
    struct cb_layoutrecall_res layoutrecall;
    struct cb_recall_slot_res recall_slot;
    struct cb_sequence_res  sequence;
    struct cb_getattr_res   getattr;
    struct cb_recall_res    recall;
    struct cb_notify_deviceid_res notify_deviceid;
};
struct cb_resop {
    enum_t                  opnum;
    union cb_op_res         res;
    bool_t                  xdr_ok;
};
struct cb_compound_res {
    enum_t                  status;
    struct cb_compound_tag  tag;
    struct cb_resop         *resarray;
    uint32_t                resarray_count; /* <= CB_COMPOUND_MAX_OPERATIONS */
};


/* callback_xdr.c */
bool_t proc_cb_compound_args(XDR *xdr, struct cb_compound_args *args);
bool_t proc_cb_compound_res(XDR *xdr, struct cb_compound_res *res);

/* callback_server.c */
struct __nfs41_session;
void nfs41_callback_session_init(
    IN struct __nfs41_session *session);

#endif /* !__NFS41_CALLBACK_H__ */
