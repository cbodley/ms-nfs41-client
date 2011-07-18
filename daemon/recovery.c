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

#include "recovery.h"
#include "nfs41_callback.h"
#include "nfs41_compound.h"
#include "nfs41_ops.h"
#include "daemon_debug.h"


/* session/client recovery uses a lock and condition variable in nfs41_client
 * to prevent multiple threads from attempting to recover at the same time */
bool_t nfs41_recovery_start_or_wait(
    IN nfs41_client *client)
{
    bool_t status = TRUE;

    EnterCriticalSection(&client->recovery.lock);

    if (!client->recovery.in_recovery) {
        dprintf(1, "Entering recovery mode for client %llu\n", client->clnt_id);
        client->recovery.in_recovery = TRUE;
    } else {
        status = FALSE;
        dprintf(1, "Waiting for recovery of client %llu\n", client->clnt_id);
        while (client->recovery.in_recovery)
            SleepConditionVariableCS(&client->recovery.cond,
                &client->recovery.lock, INFINITE);
        dprintf(1, "Woke up after recovery of client %llu\n", client->clnt_id);
    }

    LeaveCriticalSection(&client->recovery.lock);
    return status;
}

void nfs41_recovery_finish(
    IN nfs41_client *client)
{
    EnterCriticalSection(&client->recovery.lock);
    dprintf(1, "Finished recovery for client %llu\n", client->clnt_id);
    client->recovery.in_recovery = FALSE;
    WakeAllConditionVariable(&client->recovery.cond);
    LeaveCriticalSection(&client->recovery.lock);
}

static int recover_open(
    IN nfs41_session *session,
    IN nfs41_open_state *open)
{
    open_claim4 claim;
    open_delegation4 delegation;
    stateid4 stateid;
    int status;

    /* reclaim the open stateid */
    claim.claim = CLAIM_PREVIOUS;
    claim.u.prev.delegate_type = OPEN_DELEGATE_NONE;

    status = nfs41_open(session, &open->parent, &open->file,
        &open->owner, &claim, open->share_access, open->share_deny,
        OPEN4_NOCREATE, 0, 0, FALSE, &stateid, &delegation, NULL);

    if (status == NFS4ERR_NO_GRACE) {
        /* attempt out-of-grace recovery with CLAIM_NULL */
        claim.claim = CLAIM_NULL;
        claim.u.null.filename = &open->file.name;

        status = nfs41_open(session, &open->parent, &open->file,
            &open->owner, &claim, open->share_access, open->share_deny,
            OPEN4_NOCREATE, 0, 0, FALSE, &stateid, &delegation, NULL);
    }
    if (status)
        goto out;

    /* update the open stateid on success */
    AcquireSRWLockExclusive(&open->lock);
    memcpy(&open->stateid, &stateid, sizeof(stateid4));
    open->layout = NULL;
    ReleaseSRWLockExclusive(&open->lock);
out:
    return status;
}

static int recover_locks(
    IN nfs41_session *session,
    IN nfs41_open_state *open)
{
    stateid_arg stateid;
    struct list_entry *entry;
    nfs41_lock_state *lock;
    int status = NFS4_OK;

    AcquireSRWLockExclusive(&open->lock);

    /* initialize the open stateid for the first lock request */
    memcpy(&stateid.stateid, &open->stateid, sizeof(stateid4));
    stateid.type = STATEID_OPEN;
    stateid.open = open;

    /* recover any locks for this open */
    list_for_each(entry, &open->locks.list) {
        lock = list_container(entry, nfs41_lock_state, open_entry);
        status = nfs41_lock(session, &open->file, &open->owner,
            lock->type, lock->offset, lock->length, TRUE, FALSE, &stateid);
        if (status == NFS4ERR_NO_GRACE) {
            /* attempt out-of-grace recovery with a normal LOCK */
            status = nfs41_lock(session, &open->file, &open->owner,
                lock->type, lock->offset, lock->length, FALSE, FALSE, &stateid);
        }
        if (status == NFS4ERR_BADSESSION)
            break;
    }

    if (status != NFS4ERR_BADSESSION) {
        /* if we got a lock stateid back, save the lock with the open */
        if (stateid.type == STATEID_LOCK)
            memcpy(&open->locks.stateid, &stateid.stateid, sizeof(stateid4));
        else
            open->locks.stateid.seqid = 0;
    }

    ReleaseSRWLockExclusive(&open->lock);
    return status;
}

int nfs41_recover_client_state(
    IN nfs41_session *session,
    IN nfs41_client *client)
{
    const struct cb_layoutrecall_args recall = { PNFS_LAYOUTTYPE_FILE,
        PNFS_IOMODE_ANY, TRUE, { PNFS_RETURN_ALL } };
    struct client_state *state = &session->client->state;
    struct list_entry *entry;
    nfs41_open_state *open;
    int status = NFS4_OK;

    /* recover each of the client's opens */
    EnterCriticalSection(&state->lock);
    list_for_each(entry, &state->opens) {
        open = list_container(entry, nfs41_open_state, client_entry);
        status = recover_open(session, open);
        if (status == NFS4_OK)
            status = recover_locks(session, open);
        if (status == NFS4ERR_BADSESSION)
            break;
    }
    LeaveCriticalSection(&state->lock);

    /* revoke all of the client's layouts */
    pnfs_file_layout_recall(client, &recall);

    if (status != NFS4ERR_BADSESSION) {
        /* send reclaim_complete, but don't fail on errors */
        status = nfs41_reclaim_complete(session);
        if (status && status == NFS4ERR_NOTSUPP)
            eprintf("nfs41_reclaim_complete() failed with %s\n",
                nfs_error_string(status));
    }
    return status;
}

static bool_t recover_stateid_open(
    IN nfs_argop4 *argop,
    IN stateid_arg *stateid)
{
    bool_t retry = FALSE;

    if (stateid->open) {
        stateid4 *source = &stateid->open->stateid;

        /* if the source stateid is different, update and retry */
        AcquireSRWLockShared(&stateid->open->lock);
        if (memcmp(&stateid->stateid, source, sizeof(stateid4))) {
            memcpy(&stateid->stateid, source, sizeof(stateid4));
            retry = TRUE;
        }
        ReleaseSRWLockShared(&stateid->open->lock);
    }
    return retry;
}

static bool_t recover_stateid_lock(
    IN nfs_argop4 *argop,
    IN stateid_arg *stateid)
{
    bool_t retry = FALSE;

    if (stateid->open) {
        stateid4 *source = &stateid->open->locks.stateid;

        /* if the source stateid is different, update and retry */
        AcquireSRWLockShared(&stateid->open->lock);
        if (memcmp(&stateid->stateid, source, sizeof(stateid4))) {
            if (argop->op == OP_LOCK && source->seqid == 0) {
                /* resend LOCK with an open stateid */
                nfs41_lock_args *lock = (nfs41_lock_args*)argop->arg;
                lock->locker.new_lock_owner = 1;
                lock->locker.u.open_owner.open_stateid = stateid;
                lock->locker.u.open_owner.lock_owner = &stateid->open->owner;
                source = &stateid->open->stateid;
            }

            memcpy(&stateid->stateid, source, sizeof(stateid4));
            retry = TRUE;
        }
        ReleaseSRWLockShared(&stateid->open->lock);
    }
    return retry;
}

bool_t nfs41_recover_stateid(
    IN nfs41_session *session,
    IN nfs_argop4 *argop)
{
    stateid_arg *stateid = NULL;

    if (argop->op == OP_CLOSE) {
        nfs41_op_close_args *close = (nfs41_op_close_args*)argop->arg;
        stateid = close->stateid;
    } else if (argop->op == OP_READ) {
        nfs41_read_args *read = (nfs41_read_args*)argop->arg;
        stateid = read->stateid;
    } else if (argop->op == OP_WRITE) {
        nfs41_write_args *write = (nfs41_write_args*)argop->arg;
        stateid = write->stateid;
    } else if (argop->op == OP_LOCK) {
        nfs41_lock_args *lock = (nfs41_lock_args*)argop->arg;
        if (lock->locker.new_lock_owner)
            stateid = lock->locker.u.open_owner.open_stateid;
        else
            stateid = lock->locker.u.lock_owner.lock_stateid;
    } else if (argop->op == OP_LOCKU) {
        nfs41_locku_args *locku = (nfs41_locku_args*)argop->arg;
        stateid = locku->lock_stateid;
    } else if (argop->op == OP_SETATTR) {
        nfs41_setattr_args *setattr = (nfs41_setattr_args*)argop->arg;
        stateid = setattr->stateid;
    } else if (argop->op == OP_LAYOUTGET) {
        pnfs_layoutget_args *lget = (pnfs_layoutget_args*)argop->arg;
        stateid = lget->stateid;
    }
    if (stateid == NULL)
        return FALSE;

    /* if there's recovery in progress, wait for it to finish */
    EnterCriticalSection(&session->client->recovery.lock);
    while (session->client->recovery.in_recovery)
        SleepConditionVariableCS(&session->client->recovery.cond,
            &session->client->recovery.lock, INFINITE);
    LeaveCriticalSection(&session->client->recovery.lock);

    switch (stateid->type) {
    case STATEID_OPEN:
        return recover_stateid_open(argop, stateid);

    case STATEID_LOCK:
        return recover_stateid_lock(argop, stateid);

    default:
        eprintf("%s can't recover stateid type %u\n",
            nfs_opnum_to_string(argop->op), stateid->type);
        break;
    }
    return FALSE;
}
