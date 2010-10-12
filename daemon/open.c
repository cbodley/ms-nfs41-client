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
#include <strsafe.h>

#include "nfs41_ops.h"
#include "from_kernel.h"
#include "daemon_debug.h"
#include "upcall.h"
#include "util.h"


static int create_open_state(
    IN const char *path,
    IN uint32_t open_owner_id,
    OUT nfs41_open_state **state_out)
{
    int status;
    nfs41_open_state *state;

    state = calloc(1, sizeof(nfs41_open_state));
    if (state == NULL) {
        status = GetLastError();
        goto out;
    }

    InitializeSRWLock(&state->path.lock);
    if (FAILED(StringCchCopyA(state->path.path, NFS41_MAX_PATH_LEN, path))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out_free;
    }
    state->path.len = (unsigned short)strlen(state->path.path);
    path_fh_init(&state->file, &state->path);
    path_fh_init(&state->parent, &state->path);
    last_component(state->path.path, state->file.name.name,
        &state->parent.name);

    StringCchPrintfA((LPSTR)state->owner.owner, NFS4_OPAQUE_LIMIT,
        "%u", open_owner_id);
    state->owner.owner_len = (uint32_t)strlen(
        (const char*)state->owner.owner);

    *state_out = state;
    status = NO_ERROR;
out:
    return status;

out_free:
    free(state);
    goto out;
}

static void free_open_state(
    IN nfs41_session *session,
    IN nfs41_open_state *state)
{
    free(state);
}


/* NFS41_OPEN */
int parse_open(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    open_upcall_args *args = &upcall->args.open;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->access_mask, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->access_mode, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->file_attrs, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->create_opts, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->disposition, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->open_owner_id, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->mode, sizeof(DWORD));
    if (status) goto out;

    dprintf(1, "parsing NFS41_OPEN: filename='%s' access mask=%d "
        "access mode=%d\n\tfile attrs=0x%x create attrs=0x%x "
        "(kernel) disposition=%d\n\tsession=%p open_owner_id=%d mode=%o\n", 
        args->path, args->access_mask, args->access_mode, args->file_attrs,
        args->create_opts, args->disposition, args->root, args->open_owner_id,
        args->mode);
    print_disposition(2, args->disposition);
    print_access_mask(2, args->access_mask);
    print_share_mode(2, args->access_mode);
    print_create_attributes(2, args->create_opts);
out:
    return status;
}

static BOOLEAN do_lookup(uint32_t type, ULONG access_mask, ULONG disposition) 
{
    if (type == NF4DIR) {
        if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE) {
            dprintf(1, "Opening a directory\n");
            return TRUE;
        } else {
            dprintf(1, "Creating a directory\n");
            return FALSE;
        }
    }

    if ((access_mask & FILE_READ_DATA) ||
         (access_mask & FILE_WRITE_DATA) ||
         (access_mask & FILE_APPEND_DATA) ||
         (access_mask & FILE_EXECUTE))
         return FALSE;
    else {
        dprintf(1, "Open call that wants to manage attributes\n");
        return TRUE;
    }
}

static int map_disposition_2_nfsopen(ULONG disposition, int in_status, 
                                     uint32_t *create, uint32_t *last_error)
{
    int status = NO_ERROR;
    if (disposition == FILE_SUPERSEDE) {
        if (in_status == NFS4ERR_NOENT) {
            *create = OPEN4_CREATE;
            *last_error = ERROR_FILE_NOT_FOUND;
        }
        else // we need to truncate the file file then open it
            *create = OPEN4_NOCREATE;
    } else if (disposition == FILE_CREATE) {
        // if lookup succeeded which means the file exist, return an error
        if (!in_status)
            status = ERROR_FILE_EXISTS;
        else
            *create = OPEN4_CREATE;
    } else if (disposition == FILE_OPEN) {
        if (in_status == NFS4ERR_NOENT)
            status = ERROR_FILE_NOT_FOUND;
        else
            *create = OPEN4_NOCREATE;
    } else if (disposition == FILE_OPEN_IF) {
        if (in_status == NFS4ERR_NOENT) {
            dprintf(1, "creating new file\n");
            *create = OPEN4_CREATE;
            *last_error = ERROR_FILE_NOT_FOUND;
        } else {
            dprintf(1, "opening existing file\n");
            *create = OPEN4_NOCREATE;
        }
    } else if (disposition == FILE_OVERWRITE) {
        if (in_status == NFS4ERR_NOENT)
            status = ERROR_FILE_NOT_FOUND;
        //truncate file
        *create = OPEN4_CREATE;
    } else if (disposition == FILE_OVERWRITE_IF) {
        if (in_status == NFS4ERR_NOENT)
            *last_error = ERROR_FILE_NOT_FOUND;
        //truncate file
        *create = OPEN4_CREATE;
    }
    return status;
}

static int check_execute_access(nfs41_open_state *state)
{
    uint32_t supported, access;
    int status = nfs41_access(state->session, &state->file,
        ACCESS4_EXECUTE | ACCESS4_READ, &supported, &access);
    if (status) {
        dprintf(1, "nfs41_access() failed with %s\n",
            nfs_error_string(status));
        status = ERROR_ACCESS_DENIED;
    } else if ((supported & ACCESS4_EXECUTE) == 0) {
        /* server can't verify execute access;
         * for now, assume that read access is good enough */
        if ((supported & ACCESS4_READ) == 0 || (access & ACCESS4_READ) == 0) {
            dprintf(2, "server can't verify execute access, and user does "
                "not have read access\n");
            status = ERROR_ACCESS_DENIED;
        }
    } else if ((access & ACCESS4_EXECUTE) == 0) {
        dprintf(2, "user does not have execute access to file\n");
        status = ERROR_ACCESS_DENIED;
    } else
        dprintf(2, "user has execute access to file\n");
    return status;
}

int abs_path_link(
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

    /* eat trailing slashes from the path */
    path_pos = (char*)prev_non_delimiter(path_pos, path->path);
    if (path_pos > path->path)
        path_pos = (char*)next_delimiter(path_pos, path_pos);

    /* copy each component of link into the path */
    while (next_component(link_pos, link_end, &name)) {
        link_pos = name.name + name.len;

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

        /* add a \ and copy the component */
        if (FAILED(StringCchCopyNA(path_pos,
            path_max-path_pos, "\\", 1))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
        path_pos++;
        if (FAILED(StringCchCopyNA(path_pos,
            path_max-path_pos, name.name, name.len))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
        path_pos += name.len;
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

static int follow_link(
    IN open_upcall_args *args,
    IN nfs41_open_state *state)
{
    char link[NFS41_MAX_PATH_LEN];
    ptrdiff_t path_offset;
    uint32_t link_len;
    int status;

    /* read the link */
    status = nfs41_readlink(state->session, &state->file,
        NFS41_MAX_PATH_LEN, link, &link_len);
    if (status) {
        eprintf("nfs41_readlink() failed with %s\n",
            nfs_error_string(status));
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }

    /* overwrite the last component of the path; get the starting offset */
    path_offset = (state->parent.name.name + state->parent.name.len) -
        state->path.path;

    /* update the path with the results from link */
    status = abs_path_link(&args->path,
        args->path.path + path_offset, link, link_len);
    if (status) {
        eprintf("abs_path_link() failed with %d\n", status);
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }
out:
    return status;
}

int handle_open(nfs41_upcall *upcall)
{
    int status = 0;
    open_upcall_args *args = &upcall->args.open;
    nfs41_open_state *state;
    nfs41_file_info info;

    status = create_open_state(args->path, args->open_owner_id, &state);
    if (status) {
        eprintf("create_open_state(%u) failed with %d\n",
            args->open_owner_id, status);
        goto out;
    }

    // first check if windows told us it's a directory
    if (args->create_opts & FILE_DIRECTORY_FILE)
        state->type = NF4DIR;
    else
        state->type = NF4REG;

    // always do a lookup
    status = nfs41_lookup(args->root, nfs41_root_session(args->root),
        &state->path, &state->parent, &state->file, &info, &state->session);

    // now if file/dir exists, use type returned by lookup
    if (status == NO_ERROR) {
        if (info.type == NF4DIR) {
            dprintf(2, "handle_nfs41_open: DIRECTORY\n");
            if (args->create_opts & FILE_NON_DIRECTORY_FILE) {
                eprintf("trying to open directory %s as a file\n", 
                    state->path.path);
                status = ERROR_ACCESS_DENIED;
                goto out_free_state;
            }
        } else if (info.type == NF4REG) {
            dprintf(2, "handle nfs41_open: FILE\n");
            if (args->create_opts & FILE_DIRECTORY_FILE) {
                eprintf("trying to open file %s as a directory\n",
                    state->path.path);
#ifdef NOTEPAD_OPEN_FILE_AS_DIRFILE_FIXED
                status = ERROR_ACCESS_DENIED;
                goto out_free_state;
#endif
            }
        } else if (info.type == NF4LNK) {
            dprintf(2, "handle nfs41_open: SYMLINK\n");
            if (args->create_opts & FILE_OPEN_REPARSE_POINT) {
                /* continue and open the symlink itself */
            } else {
                /* tell the driver to call RxPrepareToReparseSymbolicLink() */
                upcall->last_error = ERROR_REPARSE;

                /* replace the path with the symlink target */
                status = follow_link(args, state);
                goto out_free_state;
            }
        } else
            dprintf(2, "handle_open(): unsupported type=%d\n", info.type);
        state->type = info.type;
    } else if (status != ERROR_FILE_NOT_FOUND)
        goto out_free_state;
    if (do_lookup(state->type, args->access_mask, args->disposition)) {
        if (status) {
            dprintf(1, "nfs41_lookup failed with %d\n", status);
            goto out_free_state;
        }

        nfs_to_basic_info(&info, &args->basic_info);
        nfs_to_standard_info(&info, &args->std_info);
        args->mode = info.mode;
        args->changeattr = info.change;
    } else {
        uint32_t allow = 0, deny = 0, create = 0;

        map_access_2_allowdeny(args->access_mask, args->access_mode, &allow, &deny);
        status = map_disposition_2_nfsopen(args->disposition, status, &create, &upcall->last_error);
        if (status)
            goto out_free_state;

        if (args->access_mask & FILE_EXECUTE && state->file.fh.len) {
            status = check_execute_access(state);
            if (status)
                goto out_free_state;
        }

        if (create == OPEN4_CREATE && (args->create_opts & FILE_DIRECTORY_FILE)) {
            status = nfs41_create(state->session, NF4DIR, args->mode,
                &state->parent, &state->file);
            args->std_info.Directory = 1;
            args->created = status == NFS4_OK;
        } else {
            status = nfs41_open(state->session, allow, deny, create,
                args->mode, state, &info);

            if (status == NFS4_OK) {
                nfs_to_basic_info(&info, &args->basic_info);
                nfs_to_standard_info(&info, &args->std_info);
                state->do_close = 1;
                args->mode = info.mode;
            }
        }
        if (status) {
            dprintf(1, "%s failed with %s\n", (create == OPEN4_CREATE && 
                (args->create_opts & FILE_DIRECTORY_FILE))?"nfs41_create":"nfs41_open",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_FILE_NOT_FOUND);
            goto out_free_state;
        }
    }
    args->state = state;
out:
    return status;
out_free_state:
    free(state);
    goto out;
}

int marshall_open(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    open_upcall_args *args = &upcall->args.open;

    status = safe_write(&buffer, length, &args->basic_info, sizeof(args->basic_info));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->std_info, sizeof(args->std_info));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->state, sizeof(args->state));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->mode, sizeof(args->mode));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->changeattr, sizeof(args->changeattr));
    if (status) goto out;
    if (upcall->last_error == ERROR_REPARSE) {
        /* convert args->path to wchar */
        WCHAR wpath[NFS41_MAX_PATH_LEN];
        unsigned short len = (unsigned short)MultiByteToWideChar(
            CP_UTF8, 0, args->path.path, args->path.len, wpath, NFS41_MAX_PATH_LEN);
        if (len == 0) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
        wpath[len++] = L'\0';
        len *= sizeof(WCHAR);
        dprintf(2, "ERROR_REPARSE -> '%S' [%u]\n", wpath, len);
        status = safe_write(&buffer, length, &len, sizeof(len));
        if (status) goto out;
        status = safe_write(&buffer, length, wpath, len);
    }
    dprintf(2, "NFS41_OPEN: passing open_state=0x%p mode %o changeattr 0x%x\n", 
        args->state, args->mode, args->changeattr);
out:
    return status;
}

int cancel_open(IN nfs41_upcall *upcall)
{
    int status = NFS4_OK;
    open_upcall_args *args = &upcall->args.open;
    nfs41_open_state *state = args->state;

    dprintf(1, "--> cancel_open('%s')\n", args->path);

    if (upcall->status)
        goto out; /* if handle_open() failed, the state was already freed */

    if (state->do_close) {
        status = nfs41_close(state->session, state);
        if (status)
            dprintf(1, "cancel_open: nfs41_close() failed with %s\n",
                nfs_error_string(status));
    } else if (args->created) {
        const nfs41_component *name = &state->file.name;
        status = nfs41_remove(state->session, &state->parent, name);
        if (status)
            dprintf(1, "cancel_open: nfs41_remove() failed with %s\n",
                nfs_error_string(status));
    }

    free_open_state(state->session, state);
out:
    status = nfs_to_windows_error(status, ERROR_INTERNAL_ERROR);
    dprintf(1, "<-- cancel_open() returning %d\n", status);
    return status;
}


/* NFS41_CLOSE */
int parse_close(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    close_upcall_args *args = &upcall->args.close;

    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->state, sizeof(nfs41_open_state *));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->remove, sizeof(BOOLEAN));
    if (status) goto out;
    if (args->remove) {
        status = get_name(&buffer, &length, &args->path);
        if (status) goto out;
        status = safe_read(&buffer, &length, &args->renamed, sizeof(BOOLEAN));
        if (status) goto out;
    }

    dprintf(1, "parsing NFS41_CLOSE: close root=0x%p "
        "open_state=0x%p remove=%d renamed=%d filename='%s'\n",
        args->root, args->state, args->remove, args->renamed,
        args->remove ? args->path : "");
out:
    return status;
}

int handle_close(nfs41_upcall *upcall)
{
    int status = NFS4_OK, rm_status = NFS4_OK;
    close_upcall_args *args = &upcall->args.close;
    nfs41_open_state *state = args->state;

    /* return associated file layouts if necessary */
    if (state->type == NF4REG)
        pnfs_open_state_close(state->session, state, args->remove);

    if (args->remove) {
        nfs41_component *name = &state->file.name;

        if (args->renamed) {
            dprintf(1, "removing a renamed file %s\n", name->name);
            create_silly_rename(&state->path, &state->file.fh, name);
        }

        dprintf(1, "calling nfs41_remove for %s\n", name->name);
        rm_status = nfs41_remove(state->session, &state->parent, name);
        if (rm_status) {
            dprintf(1, "nfs41_remove() failed with error %s.\n",
                nfs_error_string(rm_status));
            rm_status = nfs_to_windows_error(rm_status, ERROR_INTERNAL_ERROR);
        }
    }

    if (state->do_close) {
        status = nfs41_close(state->session, state);
        if (status) {
            dprintf(1, "nfs41_close() failed with error %s.\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_INTERNAL_ERROR);
        }
    }

    free_open_state(state->session, state);
    if (status || !rm_status)
        return status;
    else
        return rm_status;
}

int marshall_close(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    return NO_ERROR;
}
