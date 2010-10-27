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
#include "from_kernel.h"
#include "daemon_debug.h"
#include "nfs41_ops.h"
#include "name_cache.h"
#include "upcall.h"
#include "util.h"


int nfs41_cached_getattr(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    OUT nfs41_file_info *info)
{
    int status;

    /* first look for cached attributes */
    status = nfs41_attr_cache_lookup(session_name_cache(session),
        file->fh.fileid, info);

    if (status) {
        /* fetch attributes from the server */
        bitmap4 attr_request;
        init_getattr_request(&attr_request);

        status = nfs41_getattr(session, file, &attr_request, info);
        if (status) {
            eprintf("nfs41_getattr() failed with %s\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        }
    }
    return status;
}

/* NFS41_FILE_QUERY */
static int parse_getattr(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    getattr_upcall_args *args = &upcall->args.getattr;

    status = safe_read(&buffer, &length, &args->query_class, sizeof(args->query_class));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->state, sizeof(args->state));
    if (status) goto out;
    upcall_open_state_ref(upcall, args->state);

    dprintf(1, "parsing NFS41_FILE_QUERY: info_class=%d buf_len=%d "
        "root=0x%p open_state=0x%p\n",
        args->query_class, args->buf_len, args->root, args->state);
out:
    return status;
}

static int handle_getattr(nfs41_upcall *upcall)
{
    int status;
    getattr_upcall_args *args = &upcall->args.getattr;
    nfs41_open_state *state = args->state;
    nfs41_file_info info;

    ZeroMemory(&info, sizeof(info));

    status = nfs41_cached_getattr(state->session, &state->file, &info);
    if (status) {
        eprintf("nfs41_cached_getattr() failed with %d\n", status);
        goto out;
    }

    if (info.type == NF4LNK) {
        nfs41_file_info target_info;
        int target_status = nfs41_symlink_follow(args->root,
            state->session, &state->file, &target_info);
        if (target_status == NO_ERROR && target_info.type == NF4DIR)
            info.symlink_dir = TRUE;
    }

    switch (args->query_class) {
    case FileBasicInformation:
        nfs_to_basic_info(&info, &args->basic_info);
        break;
    case FileStandardInformation:
        nfs_to_standard_info(&info, &args->std_info);
        break;
    case FileAttributeTagInformation:
        args->tag_info.FileAttributes = nfs_file_info_to_attributes(&info);
        args->tag_info.ReparseTag = info.type == NF4LNK ?
            IO_REPARSE_TAG_SYMLINK : 0;
        break;
    default:
        eprintf("unhandled file query class %d\n", args->query_class);
        status = ERROR_INVALID_PARAMETER;
        break;
    }
out:
    return status;
}

static int marshall_getattr(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    getattr_upcall_args *args = &upcall->args.getattr;
    uint32_t info_len;

    switch (args->query_class) {
    case FileBasicInformation:
        info_len = sizeof(args->basic_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->basic_info, info_len);
        if (status) goto out;
        break;
    case FileStandardInformation:
        info_len = sizeof(args->std_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->std_info, info_len);
        if (status) goto out;
        break;
    case FileAttributeTagInformation:
        info_len = sizeof(args->tag_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->tag_info, info_len);
        if (status) goto out;
        break;
    default:
        eprintf("unknown file query class %d\n", args->query_class);
        status = 103;
        goto out;
    }
out:
    return status;
}


const nfs41_upcall_op nfs41_op_getattr = {
    parse_getattr,
    handle_getattr,
    marshall_getattr
};
