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

#include <Windows.h>
#include <stdio.h>

#include "upcall.h"
#include "daemon_debug.h"
#include "util.h"


#define NFSD_VERSION_MISMATCH 116

extern const nfs41_upcall_op nfs41_op_mount;
extern const nfs41_upcall_op nfs41_op_unmount;
extern const nfs41_upcall_op nfs41_op_open;
extern const nfs41_upcall_op nfs41_op_close;
extern const nfs41_upcall_op nfs41_op_read;
extern const nfs41_upcall_op nfs41_op_write;
extern const nfs41_upcall_op nfs41_op_lock;
extern const nfs41_upcall_op nfs41_op_unlock;
extern const nfs41_upcall_op nfs41_op_readdir;
extern const nfs41_upcall_op nfs41_op_getattr;
extern const nfs41_upcall_op nfs41_op_setattr;
extern const nfs41_upcall_op nfs41_op_setexattr;
extern const nfs41_upcall_op nfs41_op_symlink;
extern const nfs41_upcall_op nfs41_op_volume;

static const nfs41_upcall_op *g_upcall_op_table[] = {
    &nfs41_op_mount,
    &nfs41_op_unmount,
    &nfs41_op_open,
    &nfs41_op_close,
    &nfs41_op_read,
    &nfs41_op_write,
    &nfs41_op_lock,
    &nfs41_op_unlock,
    &nfs41_op_readdir,
    &nfs41_op_getattr,
    &nfs41_op_setattr,
    &nfs41_op_setexattr,
    &nfs41_op_symlink,
    &nfs41_op_volume,
    NULL,
    NULL
};
static const uint32_t g_upcall_op_table_size = ARRAYSIZE(g_upcall_op_table);


int upcall_parse(
    IN unsigned char *buffer,
    IN uint32_t length,
    OUT nfs41_upcall *upcall)
{
    int status;
    const nfs41_upcall_op *op;
    DWORD version;

    ZeroMemory(upcall, sizeof(nfs41_upcall));
    if (!length) {
        eprintf("empty upcall\n");
        upcall->status = status = 102;
        goto out;
    }

    dprintf(2, "received %d bytes upcall data: processing upcall\n", length);
    print_hexbuf(4, (unsigned char *)"upcall buffer: ", buffer, length);

    /* parse common elements */
    status = safe_read(&buffer, &length, &version, sizeof(uint32_t));
    if (status) goto out;
    status = safe_read(&buffer, &length, &upcall->xid, sizeof(uint32_t));
    if (status) goto out;
    status = safe_read(&buffer, &length, &upcall->opcode, sizeof(uint32_t));
    if (status) goto out;

    dprintf(2, "version=%d xid=%d opcode=%s\n", version, upcall->xid, 
        opcode2string(upcall->opcode));
    if (version != NFS41D_VERSION) {
        eprintf("received version %d expecting version %d\n", version, NFS41D_VERSION);
        upcall->status = status = NFSD_VERSION_MISMATCH;
        goto out;
    }

    if (upcall->opcode >= g_upcall_op_table_size) {
        status = ERROR_NOT_SUPPORTED;
        eprintf("unrecognized upcall opcode %d!\n", upcall->opcode);
        goto out;
    }

    /* parse the operation's arguments */
    op = g_upcall_op_table[upcall->opcode];
    if (op && op->parse) {
        status = op->parse(buffer, length, upcall);
        if (status) {
            eprintf("parsing of upcall '%s' failed with %d.\n",
                opcode2string(upcall->opcode), status);
            goto out;
        }
    }
out:
    return status;
}

int upcall_handle(
    IN nfs41_upcall *upcall)
{
    int status = NO_ERROR;
    const nfs41_upcall_op *op;

    op = g_upcall_op_table[upcall->opcode];
    if (op == NULL || op->handle == NULL) {
        status = ERROR_NOT_SUPPORTED;
        eprintf("upcall '%s' missing handle function!\n",
            opcode2string(upcall->opcode));
        goto out;
    }

    upcall->status = op->handle(upcall);
out:
    return status;
}

void upcall_marshall(
    IN nfs41_upcall *upcall,
    OUT unsigned char *buffer,
    IN uint32_t length,
    OUT uint32_t *length_out)
{
    int status = NO_ERROR;
    const nfs41_upcall_op *op;
    unsigned char *orig_buf = buffer;
    const uint32_t total = length, orig_len = length;

    /* marshall common elements */
write_downcall:
    length = orig_len;
    buffer = orig_buf;
    safe_write(&buffer, &length, &upcall->xid, sizeof(upcall->xid));
    safe_write(&buffer, &length, &upcall->opcode, sizeof(upcall->opcode));
    safe_write(&buffer, &length, &upcall->status, sizeof(upcall->status));
    safe_write(&buffer, &length, &upcall->last_error, sizeof(upcall->last_error));

    if (upcall->status)
        goto out;

    /* marshall the operation's results */
    op = g_upcall_op_table[upcall->opcode];
    if (op && op->marshall) {
        status = op->marshall(buffer, &length, upcall);
        if (status) {
            upcall->status = status;
            goto write_downcall;
        }
    }
out:
    *length_out = total - length;
}

void upcall_cancel(
    IN nfs41_upcall *upcall)
{
    const nfs41_upcall_op *op = g_upcall_op_table[upcall->opcode];
    if (op && op->cancel)
        op->cancel(upcall);
}

void upcall_cleanup(
    IN nfs41_upcall *upcall)
{
    const nfs41_upcall_op *op = g_upcall_op_table[upcall->opcode];
    if (op && op->cleanup && upcall->status != NFSD_VERSION_MISMATCH)
        op->cleanup(upcall);

    if (upcall->state_ref) {
        nfs41_open_state_deref(upcall->state_ref);
        upcall->state_ref = NULL;
    }
    if (upcall->root_ref) {
        nfs41_root_deref(upcall->root_ref);
        upcall->root_ref = NULL;
    }
}
