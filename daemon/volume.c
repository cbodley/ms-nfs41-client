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

#include "nfs41_ops.h"
#include "from_kernel.h"
#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"


int parse_volume(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status)
        eprintf("parsing NFS41_VOLUME_QUERY failed with %d\n",
            status);
    else
        dprintf(1, "parsing NFS41_VOLUME_QUERY: root=0x%p\n", args->root);
    return status;
}

int handle_volume(nfs41_upcall *upcall)
{
    nfs41_file_info info = { 0 };
    bitmap4 attr_request = { 2, { 0, FATTR4_WORD1_SPACE_AVAIL |
        FATTR4_WORD1_SPACE_FREE | FATTR4_WORD1_SPACE_TOTAL } };
    volume_upcall_args *args = &upcall->args.volume;
    int status;

    /* query the space_ attributes of the root filesystem */
    status = nfs41_getattr(nfs41_root_session(args->root),
        NULL, &attr_request, &info);
    if (status) {
        eprintf("nfs41_getattr() failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    args->total = info.space_total; /* total disk space in bytes */
    args->user = info.space_avail; /* bytes available to this user */
    args->avail = info.space_free; /* free disk space in bytes */
    dprintf(2, "Volume: %llu user, %llu free of %llu total\n",
        args->user, args->avail, args->total);
out:
    return status;
}

int marshall_volume(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;

    status = safe_write(&buffer, length, &args->total, sizeof(args->total));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->user, sizeof(args->user));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->avail, sizeof(args->avail));
out:
    return status;
}
