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

#include <stdio.h>
#include <stdlib.h>

#include "nfs41_compound.h"
#include "nfs41_xdr.h"
#include "nfs41_ops.h"
#include "nfs41_callback.h"
#include "name_cache.h"
#include "daemon_debug.h"

#define BUF_SIZE 1024


int compound_error(int status)
{
    if (status != NFS4_OK)
        dprintf(1, "COMPOUND failed with status %d.\n", status);
    return status;
}

void compound_init(
    nfs41_compound *compound,
    nfs_argop4 *argops,
    nfs_resop4 *resops,
    const char *tag)
{
    /* initialize args */
    compound->args.tag_len = (uint32_t)strlen(tag);
    memcpy(compound->args.tag, tag, compound->args.tag_len);
    compound->args.minorversion = 1;
    compound->args.argarray_count = 0;
    compound->args.argarray = argops;

    /* initialize results */
    ZeroMemory(&compound->res, sizeof(nfs41_compound_res));
    compound->res.tag_len = NFS4_OPAQUE_LIMIT;
    compound->res.resarray_count = 0;
    compound->res.resarray = resops;
}

void compound_add_op(
    nfs41_compound *compound,
    uint32_t opnum,
    void *arg,
    void *res)
{
    const uint32_t i = compound->args.argarray_count++;
    const uint32_t j = compound->res.resarray_count++;
    compound->args.argarray[i].op = opnum;
    compound->args.argarray[i].arg = arg;
    compound->res.resarray[j].op = opnum;
    compound->res.resarray[j].res = res;
}

/* Due to the possibility of replays, we might get a response to a different
 * call than the one we're expecting.  If we don't have a way to check for
 * this, we'll likely crash trying to decode into the wrong structures.
 * This function copies the number of operations and all of the operation
 * numbers from the compound arguments into the response, so we can verify
 * them on decode and fail before doing any damage. */
static void set_expected_res(
    nfs41_compound *compound)
{
    uint32_t i;
    compound->res.resarray_count = compound->args.argarray_count;
    for (i = 0; i < compound->res.resarray_count; i++)
        compound->res.resarray[i].op = compound->args.argarray[i].op;
}

/* session/client recovery uses a lock and condition variable in nfs41_client
 * to prevent multiple threads from attempting to recover at the same time */
static bool_t recovery_start_or_wait(
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

static void recovery_finish(
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
    stateid_arg stateid;
    struct list_entry *entry;
    nfs41_lock_state *lock;
    int status;

    /* reclaim the open stateid */
    status = nfs41_open_reclaim(session, &open->parent, &open->file,
        &open->owner, open->share_access, open->share_deny, &stateid.stateid);

    if (status == NFS4_OK) {
        /* update the open stateid on success */
        memcpy(&open->stateid, &stateid.stateid, sizeof(stateid4));

    } else if (status == NFS4ERR_NO_GRACE) {
        dprintf(1, "not in grace period, retrying a normal open\n");
        status = nfs41_open(session, open->share_access,
            open->share_deny, OPEN4_NOCREATE, 0, FALSE, open, NULL);

        /* update the stateid arg with the new open->stateid */
        memcpy(&stateid.stateid, &open->stateid, sizeof(stateid4));
    }
    if (status)
        goto out;

    AcquireSRWLockExclusive(&open->lock);

    open->layout = NULL;
    stateid.type = STATEID_OPEN;
    stateid.open = open;

    /* recover any locks for this open */
    list_for_each(entry, &open->locks.list) {
        lock = list_container(entry, nfs41_lock_state, open_entry);
        status = nfs41_lock(session, &open->file, &open->owner,
            lock->type, lock->offset, lock->length, TRUE, FALSE, &stateid);
        if (status == NFS4ERR_NO_GRACE) {
            dprintf(1, "not in grace period, retrying a normal lock\n");
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
out:
    return status;
}

static int recover_client_state(
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

static bool_t recover_stateid(nfs_argop4 *argop, nfs41_session *session)
{
    stateid_arg *stateid = NULL;
    stateid4 *source = NULL;
    bool_t retry = FALSE;

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

    if (stateid) {
        switch (stateid->type) {
        case STATEID_OPEN:
        case STATEID_LOCK:
            /* if there's recovery in progress, wait for it to finish */
            EnterCriticalSection(&session->client->recovery.lock);
            while (session->client->recovery.in_recovery)
                SleepConditionVariableCS(&session->client->recovery.cond,
                    &session->client->recovery.lock, INFINITE);
            LeaveCriticalSection(&session->client->recovery.lock);

            if (stateid->type == STATEID_OPEN)
                source = &stateid->open->stateid;
            else
                source = &stateid->open->locks.stateid;

            /* if the source stateid is different, update and retry */
            AcquireSRWLockShared(&stateid->open->lock);
            if (memcmp(&stateid->stateid, source, sizeof(stateid4))) {
                /* if it was a lock stateid that was cleared, resend it with an open stateid */
                if (argop->op == OP_LOCK && stateid->type == STATEID_LOCK && source->seqid == 0) {
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
            break;

        default:
            eprintf("%s can't recover stateid type %u\n",
                nfs_opnum_to_string(argop->op), stateid->type);
            break;
        }
    }
    return retry;
}

int compound_encode_send_decode(
    nfs41_session *session,
    nfs41_compound *compound,
    bool_t try_recovery)
{
    int status, retry_count = 0, delayby = 0;
    nfs41_sequence_args *args =
        (nfs41_sequence_args *)compound->args.argarray[0].arg;
    bool_t client_state_lost = FALSE;

retry:
    /* send compound */
    retry_count++;
    set_expected_res(compound);
    status = nfs41_send_compound(session->client->rpc,
        (char *)&compound->args, (char *)&compound->res);
    // bump sequence number if sequence op succeeded.
    if (compound->res.resarray_count > 0 && 
            compound->res.resarray[0].op == OP_SEQUENCE) {
        nfs41_sequence_res *seq = 
            (nfs41_sequence_res *)compound->res.resarray[0].res;
        if (seq->sr_status == NFS4_OK) {
            // returned slotid must be the same we sent
            status = NFS4ERR_IO;
            if (seq->sr_resok4.sr_slotid != args->sa_slotid) {
                eprintf("[session] sr_slotid=%d != sa_slotid=%d\n",
                    seq->sr_resok4.sr_slotid, args->sa_slotid);
                goto out_free_slot;
            }
            // returned sessionid must be the same we sent
            if (memcmp(seq->sr_resok4.sr_sessionid, args->sa_sessionid, 
                    NFS4_SESSIONID_SIZE)) {
                eprintf("[session] sr_sessionid != sa_sessionid\n");
                print_hexbuf(1, (unsigned char *)"sr_sessionid", 
                    seq->sr_resok4.sr_sessionid, NFS4_SESSIONID_SIZE);
                print_hexbuf(1, (unsigned char *)"sa_sessionid", 
                    args->sa_sessionid, NFS4_SESSIONID_SIZE);
                goto out_free_slot;
            }
            if (seq->sr_resok4.sr_status_flags) 
                print_sr_status_flags(1, seq->sr_resok4.sr_status_flags);

            status = nfs41_session_bump_seq(session, args->sa_slotid);
            if (status)
                goto out_free_slot;
        }
    }

    if (status) {
        eprintf("nfs41_send_compound failed %d for seqid=%d, slotid=%d\n", 
            status, args->sa_sequenceid, args->sa_slotid);
        status = NFS4ERR_IO;
        goto out_free_slot;
    }

    if (compound->res.status != NFS4_OK)
        dprintf(1, "\n################ %s ################\n\n",
            nfs_error_string(compound->res.status));

    switch (compound->res.status) {
    case NFS4_OK:
        break;

    case NFS4ERR_STALE_CLIENTID:
        if (!try_recovery)
            goto out;
        if (!recovery_start_or_wait(session->client))
            goto do_retry;
        //try to create a new client
        status = nfs41_client_renew(session->client);

        recovery_finish(session->client);
        if (status) {
            eprintf("nfs41_exchange_id() failed with %d\n", status);
            status = ERROR_BAD_NET_RESP;
            goto out;
        }
        goto do_retry;

    case NFS4ERR_BADSESSION:
        if (!try_recovery)
            goto out;
        if (!recovery_start_or_wait(session->client))
            goto do_retry;
restart_recovery:
        //try to create a new session
        status = nfs41_session_renew(session);
        if (status == NFS4ERR_STALE_CLIENTID) {
            client_state_lost = TRUE;
            status = nfs41_client_renew(session->client);
            if (status) {
                eprintf("nfs41_exchange_id() failed with %d\n", status);
                status = ERROR_BAD_NET_RESP;
                recovery_finish(session->client);
                goto out;
            }
            goto restart_recovery;
        } else if (status) {
            eprintf("nfs41_session_renew: failed with %d\n", status);
            recovery_finish(session->client);
            goto out;
        }
        if (client_state_lost) {
            /* do client state recovery */
            status = recover_client_state(session, session->client);
            if (status == NFS4ERR_BADSESSION)
                goto restart_recovery;
        }
        recovery_finish(session->client);
        goto do_retry;

    case NFS4ERR_EXPIRED: /* revoked by lease expiration */
    case NFS4ERR_BAD_STATEID:
    case NFS4ERR_STALE_STATEID: /* server reboot */
        if (compound->args.argarray[0].op == OP_SEQUENCE) {
            nfs41_sequence_args *seq = (nfs41_sequence_args*)
                compound->args.argarray[0].arg;
            nfs41_session_free_slot(session, seq->sa_slotid);
        }
        if (!try_recovery)
            goto out;

        if (recover_stateid(&compound->args.argarray[compound->res.resarray_count-1], 
                        session)) 
            goto do_retry;
        goto out;

    case NFS4ERR_GRACE:
    case NFS4ERR_DELAY:
#define RETRY_INDEFINITELY
#ifndef RETRY_INDEFINITELY
#define NUMBER_2_RETRY 19
#endif

#ifndef RETRY_INDEFINITELY
        if (retry_count < NUMBER_2_RETRY) {
#endif
            if (compound->args.argarray[0].op == OP_SEQUENCE) {
                nfs41_sequence_args *seq = (nfs41_sequence_args*)
                    compound->args.argarray[0].arg;
                nfs41_session_free_slot(session, seq->sa_slotid);
            }
            if (compound->res.status == NFS4ERR_GRACE)
                delayby = 5000;
            else
                delayby = 500*retry_count;
            dprintf(1, "Compound returned %s: sleeping for %ums..\n", 
                (compound->res.status==NFS4ERR_GRACE)?"NFS4ERR_GRACE":"NFS4ERR_DELAY",
                delayby);
            Sleep(delayby);
            dprintf(1, "Attempting to resend compound.\n");
            goto do_retry;
#ifndef RETRY_INDEFINITELY
        }
#endif
        break;

    case NFS4ERR_FHEXPIRED: /* TODO: recover expired volatile filehandles */
        status = NFS4ERR_STALE; /* for now, treat them as ERR_STALE */
        /* no break */
    case NFS4ERR_STALE:
        {
            nfs_argop4 *argarray = compound->args.argarray;
            struct nfs41_name_cache *name_cache =
                session_name_cache(session);
            nfs41_putfh_args *putfh;
            uint32_t i, start = 0;

            /* NFS4ERR_STALE generally comes from a PUTFH operation. in
             * this case, remove its filehandle from the name cache. but
             * because COMPOUNDs are not atomic, a file can be removed
             * between PUTFH and the operation that uses it. in this
             * case, we can't tell which PUTFH operation is to blame, so
             * we must invalidate filehandles of all PUTFH operations in
             * the COMPOUND */

            if (argarray[compound->res.resarray_count-1].op == OP_PUTFH)
                start = compound->res.resarray_count-1;

            for (i = start; i < compound->res.resarray_count; i++) {
                if (argarray[i].op == OP_PUTFH) {
                    putfh = (nfs41_putfh_args*)argarray[i].arg;

                    if (!putfh->in_recovery && putfh->file->path)
                        nfs41_name_cache_remove_stale(name_cache,
                            session, putfh->file->path);
                }
            }
        }
        break;
    }
out_free_slot:
    if (compound->args.argarray[0].op == OP_SEQUENCE) {
        nfs41_sequence_args *seq = (nfs41_sequence_args *)compound->args.argarray[0].arg;
        nfs41_session_free_slot(session, seq->sa_slotid);
    }
out:
    return status;

do_retry:
    if (compound->res.resarray[0].op == OP_SEQUENCE) {
        nfs41_sequence_args *seq = (nfs41_sequence_args*)
            compound->args.argarray[0].arg;
        status = nfs41_session_get_slot(session, &seq->sa_slotid, 
            &seq->sa_sequenceid, &seq->sa_highest_slotid);
        if (status)
            goto out;
    }
    goto retry;
}
