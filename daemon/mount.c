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

#include "daemon_debug.h"
#include "nfs41_ops.h"
#include "upcall.h"
#include "util.h"

/* NFS41_MOUNT */
int parse_mount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall) 
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;

    status = get_name(&buffer, &length, args->srv_name);
    if(status) goto out;
    ZeroMemory(&args->path, sizeof(nfs41_abs_path));
    status = get_abs_path(&buffer, &length, &args->path);
    if(status) goto out;

    dprintf(1, "parsing NFS14_MOUNT: srv_name=%s root=%s\n",
        args->srv_name, args->path.path);
out:
    return status;
}

int handle_mount(nfs41_upcall *upcall)
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;
    multi_addr4 addrs;
    const unsigned short port = 2049;
    nfs41_root *root;
    nfs41_client *client;

    // resolve hostname,port
    status = nfs41_server_resolve(args->srv_name, port, &addrs);
    if (status) {
        eprintf("nfs41_server_resolve() failed with %d\n", status);
        goto out;
    }
    // create root
    status = nfs41_root_create(args->srv_name, port, &args->path,
        NFS41_MAX_FILEIO_SIZE + WRITE_OVERHEAD,
        NFS41_MAX_FILEIO_SIZE + READ_OVERHEAD, &root);
    if (status) {
        eprintf("nfs41_rpc_clnt_create failed %d\n", status);
        goto out;
    }
    // add a mount
    status = nfs41_root_mount_addrs(root, &addrs, 0, 0, &client);
    if (status) {
        eprintf("nfs41_root_mount() failed with %d\n", status);
        goto out_err;
    }
    // look up the mount path, and fail if it doesn't exist
    status = nfs41_lookup(root, client->session,
        &args->path, NULL, NULL, NULL, NULL);
    if (status) {
        eprintf("nfs41_lookup('%s') failed with %d\n",
            args->path.path, status);
        goto out_err;
    }

    args->root = root;
out:
    return status;

out_err:
    nfs41_root_free(root);
    goto out;
}

int marshall_mount(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    mount_upcall_args *args = &upcall->args.mount;
    dprintf(2, "NFS41_MOUNT: writing pointer to nfs41_root %p\n", args->root);
    return safe_write(&buffer, length, &args->root, sizeof(args->root));
}


/* NFS41_UNMOUNT */
int parse_unmount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall) 
{
    int status;
    unmount_upcall_args *args = &upcall->args.unmount;

    status = safe_read(&buffer, &length, &args->root, sizeof(nfs41_session *));
    if (status) goto out;

    dprintf(1, "parsing NFS41_UNMOUNT: unmount root=%p\n", args->root);
out:
    return status;
}

int handle_unmount(nfs41_upcall *upcall)
{
    int status = NO_ERROR;
    unmount_upcall_args *args = &upcall->args.unmount;
    nfs41_root_free(args->root);
    return status;
}

int marshall_unmount(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    return NO_ERROR;
}
