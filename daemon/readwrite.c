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

#include <Windows.h>
#include <stdio.h>

#include "nfs41_ops.h"
#include "name_cache.h"
#include "upcall.h"
#include "daemon_debug.h"
#include "util.h"


/* number of times to retry on write/commit verifier mismatch */
#define MAX_WRITE_RETRIES 6


const stateid4 special_read_stateid = {0xffffffff, 
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static int parse_rw(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    readwrite_upcall_args *args = &upcall->args.rw;

    status = safe_read(&buffer, &length, &args->len, sizeof(args->len));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->offset, sizeof(args->offset));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buffer, sizeof(args->buffer));
    if (status) goto out;

    dprintf(1, "parsing %s len=%ld offset=%ld buf=%p\n", 
            opcode2string(upcall->opcode), args->len, args->offset, args->buffer);
out:
    return status;
}

/* NFS41_READ */
static int read_from_mds(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    nfs41_session *session = upcall->state_ref->session;
    nfs41_path_fh *file = &upcall->state_ref->file;
    readwrite_upcall_args *args = &upcall->args.rw;
    int status = 0;
    bool_t eof;
    unsigned char *p = args->buffer;
    ULONG to_rcv = args->len, reloffset = 0, len = 0;
    const uint32_t maxreadsize = max_read_size(session, &file->fh);

    if (to_rcv > maxreadsize)
        dprintf(1, "handle_nfs41_read: reading %d in chunks of %d\n",
            to_rcv, maxreadsize);

    while(to_rcv > 0) {
        uint32_t bytes_read = 0, chunk = min(to_rcv, maxreadsize);

        status = nfs41_read(session, file, stateid, args->offset + reloffset, chunk, 
                p, &bytes_read, &eof);
        if (status == NFS4ERR_OPENMODE && !len) {
            stateid->type = STATEID_SPECIAL;
            memcpy(&stateid->stateid, &special_read_stateid, sizeof(stateid4));
            continue;
        } else if (status && !len) {
            status = nfs_to_windows_error(status, ERROR_NET_WRITE_FAULT);
            goto out;
        }

        p += bytes_read;
        to_rcv -= bytes_read;
        len += bytes_read;
        args->offset += bytes_read;
        if (status) {
            status = NO_ERROR;
            break;
        }
        if (eof) {
            if (!len)
                status = ERROR_HANDLE_EOF;
            break;
        }
    }
out:
    args->out_len = len;
    return status;
}

static int read_from_pnfs(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    pnfs_layout_state *layout;
    enum pnfs_status pnfsstat;
    int status = NO_ERROR;

    if (pnfs_layout_state_open(upcall->state_ref, PNFS_IOMODE_READ, 
            args->offset, args->len, &layout)) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    pnfsstat = pnfs_read(upcall->root_ref, upcall->state_ref, stateid, layout, 
        args->offset, args->len, args->buffer, &args->out_len);
    switch (pnfsstat) {
    case PNFS_SUCCESS:
        break;
    case PNFS_READ_EOF:
        status = ERROR_HANDLE_EOF;
        break;
    default:
        status = ERROR_READ_FAULT;
        break;
    }
out:
    return status;
}

static int handle_read(nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    stateid_arg stateid;
    ULONG pnfs_bytes_read = 0;
    int status = NO_ERROR;

    nfs41_open_stateid_arg(upcall->state_ref, &stateid);

#ifdef PNFS_ENABLE_READ
    status = read_from_pnfs(upcall, &stateid);

    if (status == NO_ERROR || status == ERROR_HANDLE_EOF)
        goto out;

    if (args->out_len) {
        pnfs_bytes_read = args->out_len;
        args->out_len = 0;

        args->offset += pnfs_bytes_read;
        args->buffer += pnfs_bytes_read;
        args->len -= pnfs_bytes_read;
    }
#endif

    status = read_from_mds(upcall, &stateid);

    args->out_len += pnfs_bytes_read;
out:
    return status;
}


/* NFS41_WRITE */
static int write_to_mds(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    nfs41_session *session = upcall->state_ref->session;
    nfs41_path_fh *file = &upcall->state_ref->file;
    readwrite_upcall_args *args = &upcall->args.rw;
    nfs41_write_verf verf;
    enum stable_how4 stable, committed;
    unsigned char *p;
    const uint32_t maxwritesize = max_write_size(session, &file->fh);
    uint32_t to_send, reloffset, len;
    int status = 0;
    /* on write verifier mismatch, retry N times before failing */
    uint32_t retries = MAX_WRITE_RETRIES;

retry_write:
    p = args->buffer;
    to_send = args->len;
    reloffset = 0;
    len = 0;
    stable = to_send <= maxwritesize ? FILE_SYNC4 : UNSTABLE4;
    committed = FILE_SYNC4;

    if (to_send > maxwritesize)
        dprintf(1, "handle_nfs41_write: writing %d in chunks of %d\n",
            to_send, maxwritesize);

    while(to_send > 0) {
        uint32_t bytes_written = 0, chunk = min(to_send, maxwritesize);

        status = nfs41_write(session, file, stateid, p, chunk,
            args->offset + reloffset, stable, &bytes_written, &verf);
        if (status && !len)
            goto out;
        p += bytes_written;
        to_send -= bytes_written;
        len += bytes_written;
        reloffset += bytes_written;
        if (status) {
            status = 0;
            break;
        }
        if (!verify_write(&verf, &committed)) {
            if (retries--) goto retry_write;
            goto out_verify_failed;
        }
    }
    if (committed != FILE_SYNC4) {
        dprintf(1, "sending COMMIT for offset=%d and len=%d\n", args->offset, len);
        status = nfs41_commit(session, file, args->offset, len, 1, &verf);
        if (status)
            goto out;

        if (!verify_commit(&verf)) {
            if (retries--) goto retry_write;
            goto out_verify_failed;
        }
    }
out:
    args->out_len = len;
    return nfs_to_windows_error(status, ERROR_NET_WRITE_FAULT);

out_verify_failed:
    len = 0;
    status = NFS4ERR_IO;
    goto out;
}

static int write_to_pnfs(
    IN nfs41_upcall *upcall,
    IN const stateid_arg *stateid)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    pnfs_layout_state *layout;
    int status = NO_ERROR;

    if (pnfs_layout_state_open(upcall->state_ref, PNFS_IOMODE_RW, args->offset, 
            args->len, &layout)) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    if (pnfs_write(upcall->root_ref, upcall->state_ref, stateid, layout, 
            args->offset, args->len, args->buffer, &args->out_len)) {
        status = ERROR_WRITE_FAULT;
        goto out;
    }
out:
    return status;
}

static int handle_write(nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    stateid_arg stateid;
    ULONG pnfs_bytes_written = 0;
    int status;

    nfs41_open_stateid_arg(upcall->state_ref, &stateid);

#ifdef PNFS_ENABLE_WRITE
    status = write_to_pnfs(upcall, &stateid);
    if (status == NO_ERROR)
        goto out;

    if (args->out_len) {
        pnfs_bytes_written = args->out_len;
        args->out_len = 0;

        args->offset += pnfs_bytes_written;
        args->buffer += pnfs_bytes_written;
        args->len -= pnfs_bytes_written;
    }
#endif

    status = write_to_mds(upcall, &stateid);

    args->out_len += pnfs_bytes_written;
out:
    return status;
}

static int marshall_rw(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    return safe_write(&buffer, length, &args->out_len, sizeof(args->out_len));
}


const nfs41_upcall_op nfs41_op_read = {
    parse_rw,
    handle_read,
    marshall_rw
};
const nfs41_upcall_op nfs41_op_write = {
    parse_rw,
    handle_write,
    marshall_rw
};
