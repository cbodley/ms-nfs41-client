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

#include "nfs41_ops.h"
#include "daemon_debug.h"
#include "nfs41_xdr.h"
#include "nfs41_callback.h"
#include "nfs41_driver.h" /* for AUTH_SYS, AUTHGSS_KRB5s defines */

#include "rpc/rpc.h"
#define SECURITY_WIN32
#include <security.h>
#include "rpc/auth_sspi.h"

static enum clnt_stat send_null(CLIENT *client)
{
    struct timeval timeout = {10, 0};

    return clnt_call(client, 0,
                     (xdrproc_t)xdr_void, NULL,
                     (xdrproc_t)xdr_void, NULL, timeout);
}

static int get_client_for_netaddr(
    IN const netaddr4 *netaddr,
    IN uint32_t wsize,
    IN uint32_t rsize,
    IN nfs41_rpc_clnt *rpc,
    OUT OPTIONAL char *server_name,
    OUT CLIENT **client_out)
{
    int status = ERROR_NETWORK_UNREACHABLE;
    struct netconfig *nconf;
    struct netbuf *addr;
    CLIENT *client;

    nconf = getnetconfigent(netaddr->netid);
    if (nconf == NULL)
        goto out;

    addr = uaddr2taddr(nconf, netaddr->uaddr);
    if (addr == NULL)
        goto out_free_conf;

    if (server_name) {
        getnameinfo(addr->buf, addr->len, server_name, NI_MAXHOST, NULL, 0, 0);
        dprintf(1, "servername is %s\n", server_name);
    }
    dprintf(1, "callback function %p args %p\n", nfs41_handle_callback, rpc);
    client = clnt_tli_create(RPC_ANYFD, nconf, addr,
        NFS41_RPC_PROGRAM, NFS41_RPC_VERSION, wsize, rsize, 
        rpc?proc_cb_compound_res:NULL, rpc?nfs41_handle_callback:NULL, rpc?rpc:NULL);
    if (client) {
        *client_out = client;
        status = NO_ERROR;
        goto out_free_addr;
    }
out_free_addr:
    freenetbuf(addr);
out_free_conf:
    freenetconfigent(nconf);
out:
    return status;
}

static int get_client_for_multi_addr(
    IN const multi_addr4 *addrs,
    IN uint32_t wsize,
    IN uint32_t rsize,
    IN nfs41_rpc_clnt *rpc,
    OUT OPTIONAL char *server_name,
    OUT CLIENT **client_out,
    OUT uint32_t *addr_index)
{
    int status = ERROR_NETWORK_UNREACHABLE;
    uint32_t i;
    for (i = 0; i < addrs->count; i++) {
        status = get_client_for_netaddr(&addrs->arr[i],
            wsize, rsize, rpc, server_name, client_out);
        if (status == NO_ERROR) {
            *addr_index = i;
            break;
        }
    }
    return status;
}

/* Returns a client structure and an associated lock */
int nfs41_rpc_clnt_create(
    IN const multi_addr4 *addrs,
    IN uint32_t wsize,
    IN uint32_t rsize,
    bool_t needcb,
    IN uint32_t uid,
    IN uint32_t gid,
    IN uint32_t sec_flavor,
    OUT nfs41_rpc_clnt **rpc_out)
{
    CLIENT *client;
    nfs41_rpc_clnt *rpc;
    uint32_t addr_index;
    int status;
    char machname[MAXHOSTNAMELEN + 1];
    char server_name[NI_MAXHOST];
    gid_t gids[1];

    rpc = calloc(1, sizeof(nfs41_rpc_clnt));
    if (rpc == NULL) {
        status = GetLastError();
        goto out;
    }
#ifdef NO_CB_4_KRB5P
    if (sec_flavor == RPCSEC_AUTHGSS_KRB5P)
        needcb = 0;
#endif
    rpc->needcb = needcb;
    rpc->cond = CreateEvent(NULL, TRUE, FALSE, "rpc_recovery_cond");
    if (rpc->cond == NULL) {
        status = GetLastError();
        eprintf("CreateEvent failed %d\n", status);
        goto out_free_rpc_clnt;
    }
    status = get_client_for_multi_addr(addrs, wsize, rsize, needcb?rpc:NULL, 
                server_name, &client, &addr_index);
    if (status) {
        clnt_pcreateerror("connecting failed");
        goto out_free_rpc_cond;
    }
    if (send_null(client) != RPC_SUCCESS) {
        // XXX Do what here?
        eprintf("nfs41_rpc_clnt_create: send_null failed\n");
        status = ERROR_NETWORK_UNREACHABLE;
        goto out_err_client;
    }

    switch (sec_flavor) {
    case RPCSEC_AUTH_SYS:
        if (gethostname(machname, sizeof(machname)) == -1) {
            eprintf("nfs41_rpc_clnt_create: gethostname failed\n");
            goto out_err_client;
        }
        machname[sizeof(machname) - 1] = '\0';
        client->cl_auth = authsys_create(machname, uid, gid, 0, gids);
        break;
    case RPCSEC_AUTHGSS_KRB5:
        client->cl_auth = authsspi_create_default(client, server_name, 
            RPCSEC_SSPI_SVC_NONE);
        break;
    case RPCSEC_AUTHGSS_KRB5I:
        client->cl_auth = authsspi_create_default(client, server_name, 
            RPCSEC_SSPI_SVC_INTEGRITY);
        break;
    case RPCSEC_AUTHGSS_KRB5P:
        client->cl_auth = authsspi_create_default(client, server_name, 
            RPCSEC_SSPI_SVC_PRIVACY);
        break;
    default:
        eprintf("nfs41_rpc_clnt_create: unknown rpcsec flavor %d\n", 
                sec_flavor);
        client->cl_auth = NULL;
    }

    if (client->cl_auth == NULL) {
        // XXX log failure in auth creation somewhere
        // XXX Better error return
        eprintf("nfs41_rpc_clnt_create: failed to create %s\n", 
                secflavorop2name(sec_flavor));
        status = ERROR_NETWORK_UNREACHABLE;
        goto out_err_client;
    } else 
        dprintf(1, "nfs41_rpc_clnt_create: successfully created %s\n", 
            secflavorop2name(sec_flavor));

    rpc->rpc = client;

    /* keep a copy of the address and buffer sizes for reconnect */
    memcpy(&rpc->addrs, addrs, sizeof(multi_addr4));
    /* save the index of the address we connected to */
    rpc->addr_index = addr_index;
    rpc->wsize = wsize;
    rpc->rsize = rsize;
    rpc->is_valid_session = TRUE;

    //initialize rpc client lock
    InitializeSRWLock(&rpc->lock);

    *rpc_out = rpc;
out:
    return status;
out_err_client:
    clnt_destroy(client);
out_free_rpc_cond:
    CloseHandle(rpc->cond);
out_free_rpc_clnt:
    free(rpc);
    goto out;
}

/* Frees resources allocated in clnt_create */
void nfs41_rpc_clnt_free(
    IN nfs41_rpc_clnt *rpc)
{
    auth_destroy(rpc->rpc->cl_auth);
    clnt_destroy(rpc->rpc);
    CloseHandle(rpc->cond);
    free(rpc);
}

static bool_t rpc_renew_in_progress(nfs41_rpc_clnt *rpc, int *value)
{
    bool_t status = FALSE;
    AcquireSRWLockExclusive(&rpc->lock);
    if (value) {
        dprintf(1, "nfs41_rpc_renew_in_progress: setting value %d\n", *value);
        rpc->in_recovery = *value;
        if (!rpc->in_recovery) 
            SetEvent(rpc->cond);
    } else {
        status = rpc->in_recovery;
        dprintf(1, "nfs41_rpc_renew_in_progress: returning value %d\n", status);
    }
    ReleaseSRWLockExclusive(&rpc->lock);
    return status;
}

static bool_t rpc_should_retry(nfs41_rpc_clnt *rpc, uint32_t version)
{
    bool_t status = 0;
    AcquireSRWLockExclusive(&rpc->lock);
    if (rpc->version > version)
        status = 1;
    ReleaseSRWLockExclusive(&rpc->lock);
    return status;
}

static int rpc_reconnect(
    IN nfs41_rpc_clnt *rpc)
{
    CLIENT *client = NULL;
    uint32_t addr_index;
    int status;

    AcquireSRWLockExclusive(&rpc->lock);

    status = get_client_for_multi_addr(&rpc->addrs, rpc->wsize, rpc->rsize, 
                rpc, NULL, &client, &addr_index);
    if (status)
        goto out_unlock;

    client->cl_auth = rpc->rpc->cl_auth;
    if (send_null(client) != RPC_SUCCESS) {
        eprintf("rpc_reconnect: send_null failed\n");
        status = ERROR_NETWORK_UNREACHABLE;
        goto out_err_client;
    }

    clnt_destroy(rpc->rpc);
    rpc->rpc = client;
    rpc->addr_index = addr_index;
    rpc->version++;
    dprintf(1, "nfs41_send_compound: reestablished RPC connection\n");

out_unlock:
    ReleaseSRWLockExclusive(&rpc->lock);

    /* after releasing the rpc lock, send a BIND_CONN_TO_SESSION if
     * we need to associate the connection with the backchannel */
    if (status == NO_ERROR && rpc->needcb && 
            rpc->client && rpc->client->session) {
        status = nfs41_bind_conn_to_session(rpc,
            rpc->client->session->session_id, CDFC4_BACK_OR_BOTH);
        if (status)
            eprintf("nfs41_bind_conn_to_session() failed with %s\n",
                nfs_error_string(status));
        status = NFS4_OK;
    }
    return status;

out_err_client:
    clnt_destroy(client);
    goto out_unlock;
}

int nfs41_send_compound(
    IN nfs41_rpc_clnt *rpc,
    IN char *inbuf,
    OUT char *outbuf)
{
    struct timeval timeout = {90, 0};
    enum clnt_stat rpc_status;
    int status, count = 0, one = 1, zero = 0;
    uint32_t version;

 try_again:
    AcquireSRWLockShared(&rpc->lock);
    version = rpc->version;
    rpc_status = clnt_call(rpc->rpc, 1,
                           (xdrproc_t)nfs_encode_compound, inbuf,
                           (xdrproc_t)nfs_decode_compound, outbuf,
                           timeout);
    ReleaseSRWLockShared(&rpc->lock);

    if (rpc_status != RPC_SUCCESS) {
        eprintf("clnt_call returned rpc_status=%i\n", rpc_status);
        switch(rpc_status) {
        case RPC_CANTRECV:
        case RPC_CANTSEND:
        case RPC_TIMEDOUT:
            if (!rpc->is_valid_session && ++count > 3) {
                status = ERROR_NETWORK_UNREACHABLE;
                break;
            }
            if (rpc_should_retry(rpc, version))
                goto try_again;
            while (rpc_renew_in_progress(rpc, NULL)) {
                status = WaitForSingleObject(rpc->cond, INFINITE);
                if (status != WAIT_OBJECT_0) {
                    dprintf(1, "nfs41_rpc_renew_in_progress: WaitForSingleObject failed\n");
                    print_condwait_status(1, status);
                    status = ERROR_LOCK_VIOLATION;
                    goto out;
                }
                rpc_renew_in_progress(rpc, &zero);
                goto try_again;
            }
            rpc_renew_in_progress(rpc, &one);
            if (rpc_reconnect(rpc))
                eprintf("Failed to reconnect!\n");
            rpc_renew_in_progress(rpc, &zero);
            goto try_again;
        default:
            eprintf("UNHANDLED RPC_ERROR: %d\n", rpc_status);
			status = ERROR_NETWORK_UNREACHABLE;
            break;
        }
        goto out;
    }

    status = 0;
out:
    return status;
}
