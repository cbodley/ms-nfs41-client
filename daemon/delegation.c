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

#include "delegation.h"
#include "nfs41_ops.h"
#include "util.h"
#include "daemon_debug.h"


#define DGLVL 2 /* dprintf level for delegation logging */


/* allocation and reference counting */
static int delegation_create(
    IN const nfs41_path_fh *file,
    IN const open_delegation4 *delegation,
    OUT nfs41_delegation_state **deleg_out)
{
    nfs41_delegation_state *state;
    int status = NO_ERROR;

    state = calloc(1, sizeof(nfs41_delegation_state));
    if (state == NULL) {
        status = GetLastError();
        goto out;
    }

    memcpy(&state->state, delegation, sizeof(open_delegation4));
    fh_copy(&state->fh, &file->fh);
    list_init(&state->client_entry);
    state->ref_count = 1;
    *deleg_out = state;
out:
    return status;
}

void nfs41_delegation_ref(
    IN nfs41_delegation_state *state)
{
    const LONG count = InterlockedIncrement(&state->ref_count);
    dprintf(DGLVL, "nfs41_delegation_ref() count %d\n", count);
}

void nfs41_delegation_deref(
    IN nfs41_delegation_state *state)
{
    const LONG count = InterlockedDecrement(&state->ref_count);
    dprintf(DGLVL, "nfs41_delegation_deref() count %d\n", count);
    if (count == 0)
        free(state);
}


/* open delegation */
int nfs41_delegation_granted(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN open_delegation4 *delegation,
    OUT nfs41_delegation_state **deleg_out)
{
    nfs41_client *client = session->client;
    nfs41_delegation_state *state;
    int status = NO_ERROR;

    if (delegation->recalled ||
        delegation->type == OPEN_DELEGATE_NONE ||
        delegation->type == OPEN_DELEGATE_NONE_EXT)
        goto out;

    /* allocate the delegation state */
    status = delegation_create(file, delegation, &state);
    if (status)
        goto out_return;

    /* register the delegation with the client */
    EnterCriticalSection(&client->state.lock);
    /* XXX: check for duplicates by fh and stateid? */
    list_add_tail(&client->state.delegations, &state->client_entry);
    LeaveCriticalSection(&client->state.lock);

    nfs41_delegation_ref(state); /* return a reference */
    *deleg_out = state;
out:
    return status;

out_return: /* return the delegation on failure */
    nfs41_delegreturn(session, file, &delegation->stateid);
    goto out;
}

#define deleg_entry(pos) list_container(pos, nfs41_delegation_state, client_entry)

static int deleg_fh_cmp(const struct list_entry *entry, const void *value)
{
    const nfs41_fh *lhs = &deleg_entry(entry)->fh;
    const nfs41_fh *rhs = (const nfs41_fh*)value;
    if (lhs->superblock != rhs->superblock) return -1;
    if (lhs->fileid != rhs->fileid) return -1;
    return 0;
}

static bool_t delegation_compatible(
    IN enum open_delegation_type4 type,
    IN uint32_t create,
    IN uint32_t access,
    IN uint32_t deny)
{
    /* TODO: allow write delegation to handle OPEN4_CREATE */
    if (create == OPEN4_CREATE)
        return FALSE;

    switch (type) {
    case OPEN_DELEGATE_WRITE:
        /* An OPEN_DELEGATE_WRITE delegation allows the client to handle,
         * on its own, all opens. */
        return TRUE;

    case OPEN_DELEGATE_READ:
        /* An OPEN_DELEGATE_READ delegation allows a client to handle,
         * on its own, requests to open a file for reading that do not
         * deny OPEN4_SHARE_ACCESS_READ access to others. */
        if (access & OPEN4_SHARE_ACCESS_WRITE || deny & OPEN4_SHARE_DENY_READ)
            return FALSE;
        return TRUE;

    default:
        return FALSE;
    }
}

static int delegation_find(
    IN nfs41_client *client,
    IN const void *value,
    IN list_compare_fn cmp,
    OUT nfs41_delegation_state **deleg_out)
{
    struct list_entry *entry;
    int status = NFS4ERR_BADHANDLE;

    EnterCriticalSection(&client->state.lock);
    entry = list_search(&client->state.delegations, value, cmp);
    if (entry) {
        *deleg_out = deleg_entry(entry);
        nfs41_delegation_ref(*deleg_out);
        status = NFS4_OK;
    }
    LeaveCriticalSection(&client->state.lock);
    return status;
}

int nfs41_delegate_open(
    IN nfs41_client *client,
    IN nfs41_path_fh *file,
    IN uint32_t create,
    IN uint32_t access,
    IN uint32_t deny,
    OUT nfs41_delegation_state **deleg_out,
    OUT nfs41_file_info *info)
{
    nfs41_delegation_state *deleg;
    int status;

    /* search for a delegation with this filehandle */
    status = delegation_find(client, &file->fh, deleg_fh_cmp, &deleg);
    if (status)
        goto out;

    if (!delegation_compatible(deleg->state.type, create, access, deny)) {
        status = NFS4ERR_BADHANDLE;
        goto out_deleg;
    }

    /* TODO: check access against deleg->state.permissions or send ACCESS */

    *deleg_out = deleg;
    status = NFS4_OK;
out:
    return status;

out_deleg:
    nfs41_delegation_deref(deleg);
    goto out;
}

void nfs41_client_delegation_free(
    IN nfs41_client *client)
{
    struct list_entry *entry, *tmp;

    EnterCriticalSection(&client->state.lock);
    list_for_each_tmp (entry, tmp, &client->state.delegations) {
        list_remove(entry);
        nfs41_delegation_deref(deleg_entry(entry));
    }
    LeaveCriticalSection(&client->state.lock);
}
