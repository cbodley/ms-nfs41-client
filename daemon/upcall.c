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


int parse_mount(unsigned char*, uint32_t, nfs41_upcall*);
int handle_mount(nfs41_upcall*);
int marshall_mount(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_unmount(unsigned char*, uint32_t, nfs41_upcall*);
int handle_unmount(nfs41_upcall*);
int marshall_unmount(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_open(unsigned char*, uint32_t, nfs41_upcall*);
int handle_open(nfs41_upcall*);
int marshall_open(unsigned char*, uint32_t*, nfs41_upcall*);
int cancel_open(nfs41_upcall*);

int parse_close(unsigned char*, uint32_t, nfs41_upcall*);
int handle_close(nfs41_upcall*);
int marshall_close(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_rw(unsigned char*, uint32_t, nfs41_upcall*);
int handle_read(nfs41_upcall*);
int handle_write(nfs41_upcall*);
int marshall_rw(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_lock(unsigned char*, uint32_t, nfs41_upcall*);
int handle_lock(nfs41_upcall*);
int marshall_lock(unsigned char*, uint32_t*, nfs41_upcall*);
int cancel_lock(nfs41_upcall*);

int parse_unlock(unsigned char*, uint32_t, nfs41_upcall*);
int handle_unlock(nfs41_upcall*);
int marshall_unlock(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_readdir(unsigned char*, uint32_t, nfs41_upcall*);
int handle_readdir(nfs41_upcall*);
int marshall_readdir(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_getattr(unsigned char*, uint32_t, nfs41_upcall*);
int handle_getattr(nfs41_upcall*);
int marshall_getattr(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_setattr(unsigned char*, uint32_t, nfs41_upcall*);
int handle_setattr(nfs41_upcall*);
int marshall_setattr(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_setexattr(unsigned char*, uint32_t, nfs41_upcall*);
int handle_setexattr(nfs41_upcall*);
int marshall_setexattr(unsigned char*, uint32_t*, nfs41_upcall*);

int parse_volume(unsigned char*, uint32_t, nfs41_upcall*);
int handle_volume(nfs41_upcall*);
int marshall_volume(unsigned char*, uint32_t*, nfs41_upcall*);

static const nfs41_upcall_op g_upcall_op_table[] = {
    { parse_mount,      handle_mount,       marshall_mount,     NULL },
    { parse_unmount,    handle_unmount,     marshall_unmount,   NULL },
    { parse_open,       handle_open,        marshall_open,      cancel_open },
    { parse_close,      handle_close,       marshall_close,     NULL },
    { parse_rw,         handle_read,        marshall_rw,        NULL },
    { parse_rw,         handle_write,       marshall_rw,        NULL },
    { parse_lock,       handle_lock,        marshall_lock,      cancel_lock },
    { parse_unlock,     handle_unlock,      marshall_unlock,    NULL },
    { parse_readdir,    handle_readdir,     marshall_readdir,   NULL },
    { parse_getattr,    handle_getattr,     marshall_getattr,   NULL },
    { parse_setattr,    handle_setattr,     marshall_setattr,   NULL },
    { parse_setexattr,  handle_setexattr,   marshall_setexattr, NULL },
    { parse_volume,     handle_volume,      marshall_volume,    NULL },
    { NULL, NULL, NULL, NULL }, /* NFS41_SHUTDOWN */
    { NULL, NULL, NULL, NULL }, /* INVALID_OPCODE */
};
static const uint32_t g_upcall_op_table_size = ARRAYSIZE(g_upcall_op_table);


int upcall_parse(
    IN unsigned char *buffer,
    IN uint32_t length,
    OUT nfs41_upcall *upcall)
{
    int status;
    const nfs41_upcall_op *op;

    ZeroMemory(upcall, sizeof(nfs41_upcall));
    if (!length) {
        eprintf("empty upcall\n");
        upcall->status = status = 102;
        goto out;
    }

    dprintf(2, "received %d bytes upcall data: processing upcall\n", length);
    print_hexbuf(4, (unsigned char *)"upcall buffer: ", buffer, length);

    /* parse common elements */
    status = safe_read(&buffer, &length, &upcall->xid, sizeof(uint32_t));
    if (status) goto out;
    status = safe_read(&buffer, &length, &upcall->opcode, sizeof(uint32_t));
    if (status) goto out;
    status = get_name(&buffer, &length, upcall->sid);
    if (status) goto out;

    dprintf(2, "xid=%d opcode=%s SID=%s\n", upcall->xid, 
        opcode2string(upcall->opcode), upcall->sid);

    if (upcall->opcode >= g_upcall_op_table_size) {
        status = ERROR_NOT_SUPPORTED;
        eprintf("unrecognized upcall opcode %d!\n", upcall->opcode);
        goto out;
    }

    /* parse the operation's arguments */
    op = &g_upcall_op_table[upcall->opcode];
    if (op->parse) {
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

    op = &g_upcall_op_table[upcall->opcode];
    if (op->handle == NULL) {
        status = ERROR_NOT_SUPPORTED;
        eprintf("upcall '%s' missing handle function!\n",
            opcode2string(upcall->opcode));
        goto out;
    }

    upcall->status = op->handle(upcall);
out:
    return status;
}

int upcall_marshall(
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
    op = &g_upcall_op_table[upcall->opcode];
    if (op->marshall == NULL) {
        status = ERROR_NOT_SUPPORTED;
        eprintf("upcall '%s' missing marshall function!\n",
            opcode2string(upcall->opcode));
        upcall->status = status;
        goto write_downcall;
    }

    status = op->marshall(buffer, &length, upcall);
    if (status) {
        upcall->status = status;
        goto write_downcall;
    }
out:
    *length_out = total - length;
    return status;
}

int upcall_cancel(
    IN nfs41_upcall *upcall)
{
    int status = NO_ERROR;
    const nfs41_upcall_op *op;

    op = &g_upcall_op_table[upcall->opcode];
    if (op->cancel)
        status = op->cancel(upcall);

    return status;
}
