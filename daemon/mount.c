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
#include <strsafe.h>
#include <stdio.h>

#include "daemon_debug.h"
#include "nfs41_ops.h"
#include "upcall.h"
#include "util.h"


/* NFS41_MOUNT */
static int parse_mount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall) 
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;

    status = get_name(&buffer, &length, &args->hostname);
    if(status) goto out;
    status = get_name(&buffer, &length, &args->path);
    if(status) goto out;
    status = safe_read(&buffer, &length, &args->sec_flavor, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->rsize, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->wsize, sizeof(DWORD));
    if (status) goto out;

    dprintf(1, "parsing NFS14_MOUNT: srv_name=%s root=%s sec_flavor=%s "
        "rsize=%d wsize=%d\n", args->hostname, args->path, 
        secflavorop2name(args->sec_flavor), args->rsize, args->wsize);
out:
    return status;
}

static int handle_mount(nfs41_upcall *upcall)
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;
    nfs41_abs_path path;
    multi_addr4 addrs;
    nfs41_root *root;
    nfs41_client *client;

    // resolve hostname,port
    status = nfs41_server_resolve(args->hostname, 2049, &addrs);
    if (status) {
        eprintf("nfs41_server_resolve() failed with %d\n", status);
        goto out;
    }
    // create root
    status = nfs41_root_create(args->hostname, args->sec_flavor,
        args->wsize + WRITE_OVERHEAD, args->rsize + READ_OVERHEAD, &root);
    if (status) {
        eprintf("nfs41_root_create() failed %d\n", status);
        goto out;
    }
    // add a mount
    root->uid = upcall->uid;
    root->gid = upcall->gid;

    status = nfs41_root_mount_addrs(root, &addrs, 0, 0, &client);
    if (status) {
        eprintf("nfs41_root_mount_addrs() failed with %d\n", status);
        goto out_err;
    }

    // make a copy of the path for nfs41_lookup()
    InitializeSRWLock(&path.lock);
    if (FAILED(StringCchCopyA(path.path, NFS41_MAX_PATH_LEN, args->path))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out_err;
    }
    path.len = (unsigned short)strlen(path.path);

    // look up the mount path, and fail if it doesn't exist
    status = nfs41_lookup(root, client->session,
        &path, NULL, NULL, NULL, NULL);
    if (status) {
        eprintf("nfs41_lookup('%s') failed with %d\n", path.path, status);
        status = ERROR_BAD_NETPATH;
        goto out_err;
    }

    upcall->root_ref = root;
    nfs41_root_ref(upcall->root_ref);
out:
    return status;

out_err:
    nfs41_root_deref(root);
    goto out;
}

static int marshall_mount(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    dprintf(2, "NFS41_MOUNT: writing pointer to nfs41_root %p and version %d\n", 
        upcall->root_ref, NFS41D_VERSION);
    status = safe_write(&buffer, length, &upcall->root_ref, sizeof(HANDLE));
    if (status) goto out;
    status = safe_write(&buffer, length, &NFS41D_VERSION, sizeof(DWORD));
out:
    return status;
}

static void cancel_mount(IN nfs41_upcall *upcall)
{
    if (upcall->root_ref != INVALID_HANDLE_VALUE)
        nfs41_root_deref(upcall->root_ref);
}

const nfs41_upcall_op nfs41_op_mount = {
    parse_mount,
    handle_mount,
    marshall_mount,
    cancel_mount
};


/* NFS41_UNMOUNT */
static int parse_unmount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall) 
{
    dprintf(1, "parsing NFS41_UNMOUNT: root=%p\n", upcall->root_ref);
    return ERROR_SUCCESS;
}

static int handle_unmount(nfs41_upcall *upcall)
{
    /* release the original reference from nfs41_root_create() */
    nfs41_root_deref(upcall->root_ref);
    return ERROR_SUCCESS;
}

const nfs41_upcall_op nfs41_op_unmount = {
    parse_unmount,
    handle_unmount
};
