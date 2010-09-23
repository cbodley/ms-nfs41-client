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

#include "nfs41_ops.h"
#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"


static int abs_path_link(
    OUT nfs41_abs_path *path,
    IN char *path_pos,
    IN const char *link,
    IN uint32_t link_len)
{
    nfs41_component name;
    const char *path_max = path->path + NFS41_MAX_PATH_LEN;
    const char *link_pos = link;
    const char *link_end = link + link_len;
    int status = NO_ERROR;

    dprintf(2, "--> abs_path_link('%s', '%s')\n", path->path, link);

    /* if link is an absolute path, start path_pos at the beginning */
    if (is_delimiter(*link))
        path_pos = path->path;

    /* copy each component of link into the path */
    while (next_component(link_pos, link_end, &name)) {
        link_pos = name.name + name.len;

        if (is_delimiter(*path_pos))
            path_pos++;

        /* handle special components . and .. */
        if (name.len == 1 && name.name[0] == '.')
            continue;
        if (name.len == 2 && name.name[0] == '.' && name.name[1] == '.') {
            /* back path_pos up by one component */
            if (!last_component(path->path, path_pos, &name)) {
                eprintf("symlink with .. that points below server root!\n");
                status = ERROR_BAD_NETPATH;
                goto out;
            }
            path_pos = (char*)prev_delimiter(name.name, path->path);
            continue;
        }

        /* copy the component and add a \ */
        if (FAILED(StringCchCopyNA(path_pos,
            path_max-path_pos, name.name, name.len))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
        path_pos += name.len;
        if (FAILED(StringCchCopyNA(path_pos,
            path_max-path_pos, "\\", 1))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
    }

    /* make sure the path is null terminated */
    if (path_pos == path_max) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    *path_pos = '\0';
out:
    path->len = (unsigned short)(path_pos - path->path);
    dprintf(2, "<-- abs_path_link('%s') returning %d\n", path->path, status);
    return status;
}

int nfs41_symlink_follow(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    OUT nfs41_abs_path *target)
{
    char link[NFS41_MAX_PATH_LEN];
    const nfs41_abs_path *path = file->path;
    ptrdiff_t path_offset;
    uint32_t link_len;
    int status;

    /* read the link */
    status = nfs41_readlink(session, file, NFS41_MAX_PATH_LEN, link, &link_len);
    if (status) {
        eprintf("nfs41_readlink() failed with %s\n", nfs_error_string(status));
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }

    /* overwrite the last component of the path; get the starting offset */
    path_offset = file->name.name - path->path;

    /* copy the path and update it with the results from link */
    target->len = path->len;
    if (FAILED(StringCchCopyNA(target->path, NFS41_MAX_PATH_LEN,
        path->path, path->len))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    status = abs_path_link(target, target->path + path_offset, link, link_len);
    if (status) {
        eprintf("abs_path_link() failed with %d\n", status);
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }

    /* append any components after the symlink */
    if (FAILED(StringCchCopyA(target->path + target->len,
        NFS41_MAX_PATH_LEN - target->len, file->name.name + file->name.len))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    target->len = (unsigned short)strlen(target->path);
out:
    return status;
}


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

static int map_symlink_errors(int status)
{
    switch (status) {
    case NFS4ERR_BADCHAR:
    case NFS4ERR_BADNAME:       return ERROR_INVALID_REPARSE_DATA;
    case NFS4ERR_WRONG_TYPE:    return ERROR_NOT_A_REPARSE_POINT;
    default: return nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
    }
}

int handle_symlink(nfs41_upcall *upcall)
{
    symlink_upcall_args *args = &upcall->args.symlink;
    nfs41_open_state *state = args->state;
    int status = NO_ERROR;

    if (args->set) {
        /* create the symlink */
        status = nfs41_create(state->session, NF4LNK, 0777,
            args->target_set, &state->parent, &state->file);
        if (status) {
            eprintf("nfs41_create() failed with %s\n",
                nfs_error_string(status));
            status = map_symlink_errors(status);
            goto out;
        }
    } else {
        uint32_t len;

        /* read the link */
        status = nfs41_readlink(state->session, &state->file,
            NFS41_MAX_PATH_LEN, args->target_get.path, &len);
        if (status) {
            eprintf("nfs41_readlink() failed with %s\n",
                nfs_error_string(status));
            status = map_symlink_errors(status);
            goto out;
        }
        args->target_get.len = (unsigned short)len;
        dprintf(2, "returning symlink target '%s'\n", args->target_get.path);
    }
out:
    return status;
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
