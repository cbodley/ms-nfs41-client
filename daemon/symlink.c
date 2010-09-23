/* Copyright (c) 2010
 * The Regents of the University of Michigan
 * All Rights Reserved
 *
 * Permission is granted to use, copy, create derivative works, and
 * redistribute this software and such derivative works for any purpose,
 * so long as the name of the University of Michigan is not used in
 * any advertising or publicity pertaining to the use or distribution
 * of this software without specific, written prior authorization. If
 * the above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any portion of
 * this software, then the disclaimer below must also be included.
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
#include <strsafe.h>

#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"


/* NFS41_SYMLINK */
int parse_symlink(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    symlink_upcall_args *args = &upcall->args.symlink;
    int status;

    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->state, sizeof(nfs41_open_state *));
    if (status) goto out;
    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->set, sizeof(BOOLEAN));
    if (status) goto out;

    if (args->set)
        status = get_name(&buffer, &length, &args->target_set);
    else
        args->target_set = NULL;

    dprintf(1, "parsing NFS41_SYMLINK: root=0x%p open_state=0x%p "
        "path='%s' set=%u target='%s'\n", args->root, args->state,
        args->path, args->set, args->target_set);
out:
    return status;
}

int handle_symlink(nfs41_upcall *upcall)
{
    return NO_ERROR;
}

int marshall_symlink(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    symlink_upcall_args *args = &upcall->args.symlink;
    unsigned short len = (args->target_get.len + 1) * sizeof(WCHAR);
    int status = NO_ERROR;

    if (args->set)
        goto out;

    status = safe_write(&buffer, length, &len, sizeof(len));
    if (status) goto out;

    if (*length <= len || !MultiByteToWideChar(CP_UTF8, 0,
        args->target_get.path, args->target_get.len,
        (LPWSTR)buffer, len / sizeof(WCHAR))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
out:
    return status;
}
