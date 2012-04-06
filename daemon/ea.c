/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>

#include "from_kernel.h"
#include "nfs41_ops.h"
#include "delegation.h"
#include "upcall.h"
#include "daemon_debug.h"


/* NFS41_EA_SET */
static int parse_setexattr(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    setexattr_upcall_args *args = &upcall->args.setexattr;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->mode, sizeof(args->mode));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    args->buf = buffer;

    dprintf(1, "parsing NFS41_EA_SET: mode=%o\n", args->mode);
out:
    return status;
}

static int handle_setexattr(nfs41_upcall *upcall)
{
    int status;
    setexattr_upcall_args *args = &upcall->args.setexattr;
    nfs41_open_state *state = upcall->state_ref;
    stateid_arg stateid;
    nfs41_file_info createattrs, info = { 0 };
    PFILE_FULL_EA_INFORMATION eainfo = 
        (PFILE_FULL_EA_INFORMATION)args->buf, prev = NULL;
    nfs41_path_fh parent = { 0 }, file = { 0 };
    open_claim4 claim;
    stateid4 open_stateid;
    nfs41_write_verf verf;
    uint32_t bytes_written;
    UCHAR *buf;
    open_delegation4 delegation = { 0 };

    createattrs.attrmask.count = 2;
    createattrs.attrmask.arr[0] = FATTR4_WORD0_SIZE;
    createattrs.attrmask.arr[1] = FATTR4_WORD1_MODE;
    createattrs.size = 0;
    createattrs.mode = 0664;

    /* break read delegations before SETATTR */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_READ, FALSE);

    nfs41_open_stateid_arg(state, &stateid);
    
    if (strncmp("NfsV3Attributes", eainfo->EaName, eainfo->EaNameLength) == 0
            && sizeof("NfsV3Attributes")-1 == eainfo->EaNameLength) {
        info.mode = args->mode;
        info.attrmask.arr[1] |= FATTR4_WORD1_MODE;
        info.attrmask.count = 2;
        status = nfs41_setattr(state->session, &state->file, &stateid, &info);
        if (status) {
            dprintf(1, "nfs41_setattr() failed with error %s.\n",
                nfs_error_string(status));
            return nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
        }
        args->ctime = info.change;
    } else {
        status = nfs41_rpc_openattr(state->session, &state->file, TRUE, &parent.fh);
        if (status) {
            dprintf(1, "handle_setexattr: nfs41_rpc_openattr() failed with error %s.\n",
                nfs_error_string(status));
            return nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
        }

        while (eainfo != prev) {
            /* we don't allow for extended attribute values to be larger than NFS4_EASIZE.
             * thus, let's not allow setting such.
             */
            if (eainfo->EaValueLength > NFS4_EASIZE) {
                dprintf(1, "trying to write extended attribute value of size %d"
                    "max allowed %d\n", eainfo->EaValueLength, NFS4_EASIZE);
                status = ERROR_INVALID_DATA;
                goto out;
            }
            file.name.name = eainfo->EaName;
            file.name.len = eainfo->EaNameLength; 
            claim.claim = CLAIM_NULL;
            claim.u.null.filename = &file.name;
            status = nfs41_open(state->session, &parent, &file, &state->owner, &claim,
                OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_BOTH, OPEN4_CREATE, 
                UNCHECKED4, &createattrs, TRUE, &open_stateid, &delegation, NULL);
            if (status) {
                dprintf(1, "handle_setexattr: nfs41_rpc_open() failed with error %s.\n",
                    nfs_error_string(status));
                status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
                goto out;
            }

            stateid.stateid = open_stateid;
            stateid.stateid.seqid = 0;
            buf = (UCHAR *) eainfo->EaName + eainfo->EaNameLength + 1;
            status = nfs41_write(state->session, &file, &stateid, buf, 
                eainfo->EaValueLength, 0, FILE_SYNC4, &bytes_written, 
                &verf, NULL);
            if (status) {
                dprintf(1, "handle_setexattr: nfs41_write() failed w/error %s.\n",
                    nfs_error_string(status));
                status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
                nfs41_close(state->session, &file, &stateid);
                goto out;
            }

            status = nfs41_close(state->session, &file, &stateid);
            if (status) {
                dprintf(1, "handle_setexattr: nfs41_close() failed w/error %s.\n",
                    nfs_error_string(status));
                status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
                goto out;
            }

            bytes_written = 0;
            prev = eainfo;
            eainfo = (FILE_FULL_EA_INFORMATION *) ((ULONG_PTR) eainfo +
                eainfo->NextEntryOffset);
        }
    }
out:
    return status;
}

static int marshall_setexattr(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    setexattr_upcall_args *args = &upcall->args.setexattr;
    return safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
}


/* NFS41_EA_GET */
static int parse_getexattr(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    getexattr_upcall_args *args = &upcall->args.getexattr;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->eaindex, sizeof(args->eaindex));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->restart, sizeof(args->restart));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->single, sizeof(args->single));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->ealist_len, sizeof(args->ealist_len));
    if (status) goto out;
    args->ealist = buffer;

    dprintf(1, "parsing NFS41_EA_GET: buf_len=%d Initial %d Restart %d "
        "Single %d\n", args->buf_len,args->eaindex, args->restart, args->single);
out:
    return status;
}

static int handle_getexattr(nfs41_upcall *upcall)
{
    int status = 0;
    getexattr_upcall_args *args = &upcall->args.getexattr;
    PFILE_GET_EA_INFORMATION gea = 
        (PFILE_GET_EA_INFORMATION)args->ealist, prev = NULL;
    PFILE_FULL_EA_INFORMATION eainfo, entry_pos;
    unsigned char *entry_buf, buf[NFS4_EASIZE] = { 0 };
    nfs41_open_state *state = upcall->state_ref;
    nfs41_path_fh parent = { 0 }, file = { 0 };
    open_claim4 claim;
    stateid4 open_stateid;
    stateid_arg stateid;
    open_delegation4 delegation = { 0 };
    bool_t eof;
    uint32_t bytes_read = 0;
    ULONG buflen = 0, needed = 0;

    status = nfs41_rpc_openattr(state->session, &state->file, FALSE, &parent.fh);
    if (status){
        dprintf(1, "nfs41_rpc_openattr() failed with error %s.\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
        goto out;
    }

    entry_buf = malloc(UPCALL_BUF_SIZE);
    if (entry_buf == NULL) {
        status = GetLastError();
        goto out;
    }

    entry_pos = eainfo = (PFILE_FULL_EA_INFORMATION)entry_buf;

    while (gea != prev) {
        file.name.name = gea->EaName;
        file.name.len = gea->EaNameLength; 
        claim.claim = CLAIM_NULL;
        claim.u.null.filename = &file.name;
        status = nfs41_open(state->session, &parent, &file, &state->owner, 
            &claim, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_BOTH, 
            OPEN4_NOCREATE, UNCHECKED4, 0, TRUE, &open_stateid, 
            &delegation, NULL);
        if (status) {
            dprintf(1, "nfs41_open() failed with error %s.\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
            goto out_free;
        }

        stateid.stateid = open_stateid;
        stateid.stateid.seqid = 0;
        status = nfs41_read(state->session, &file, &stateid, 0, NFS4_EASIZE, 
                buf, &bytes_read, &eof);
        if (status) {
            dprintf(2, "nfs41_rpc_read EA attribute failed\n");
            status = nfs_to_windows_error(status, ERROR_NET_WRITE_FAULT);
            nfs41_close(state->session, &file, &stateid);
            goto out_free;
        }

        if (eof) {
            dprintf(1, "read thread reached eof: bytes_read %d\n", bytes_read);
            eainfo->EaNameLength = gea->EaNameLength;
            if (FAILED(StringCchCopy((LPSTR)eainfo->EaName, gea->EaNameLength + 1,
                    (LPCSTR)gea->EaName))) {
                status = ERROR_BUFFER_OVERFLOW;
                nfs41_close(state->session, &file, &stateid);
                goto out_free;
            }

            if (FAILED(StringCchCopy((LPSTR)eainfo->EaName + 
                    eainfo->EaNameLength + 1, bytes_read + 1, (LPCSTR)buf))) {
                status = ERROR_BUFFER_OVERFLOW;
                nfs41_close(state->session, &file, &stateid);
                goto out_free;
            }

            memset(buf, 0, NFS4_EASIZE);
            eainfo->EaValueLength = (USHORT) bytes_read;
            needed = (eainfo->EaNameLength + eainfo->EaValueLength) +
                FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);

            if (needed % 4)
                needed = needed + (4 - (needed % 4)); 

            eainfo->NextEntryOffset = needed;
            eainfo->Flags = 0;

            buflen = buflen + needed;
            prev = gea;

            if (gea->NextEntryOffset != 0) {
                gea = (PFILE_GET_EA_INFORMATION) 
                    ((PBYTE) gea + gea->NextEntryOffset); 
                eainfo = (PFILE_FULL_EA_INFORMATION) 
                    ((PBYTE) eainfo + eainfo->NextEntryOffset);
            }

            status = nfs41_close(state->session, &file, &stateid);
            if (status) {
                dprintf(1, "nfs41_close() failed with error %s.\n",
                    nfs_error_string(status));
                status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
                goto out_free;
            }
        } else {
            dprintf(2, "Size of the EA value is greater than %d\n", NFS4_EASIZE);
            status = nfs41_close(state->session, &file, &stateid);
            if (status) {
                dprintf(1, "nfs41_rpc_openattr() failed with error %s.\n",
                    nfs_error_string(status));
                status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
            }
            /* treating extended attribute values larger than NFS4_EASIZE as failure */
            status = ERROR_INVALID_DATA;
            goto out_free;
        }
    }

    eainfo->NextEntryOffset = 0;
    args->buf = (unsigned char *)entry_pos;
    args->buf_len = buflen;
    goto out;

out_free:
    free(entry_buf);
out:
    return status;
}

static int marshall_getexattr(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status = NO_ERROR;
    getexattr_upcall_args *args = &upcall->args.getexattr;
    uint32_t len = args->buf_len;

    status = safe_write(&buffer, length, &len, sizeof(len));
    if (status) goto out;
    status = safe_write(&buffer, length, args->buf, len);
    if (status) goto out;
out:
    free(args->buf);
    return status;
}


const nfs41_upcall_op nfs41_op_setexattr = {
    parse_setexattr,
    handle_setexattr,
    marshall_setexattr
};

const nfs41_upcall_op nfs41_op_getexattr = {
    parse_getexattr,
    handle_getexattr,
    marshall_getexattr
};
