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
#include "name_cache.h"
#include "daemon_debug.h"

#define BUF_SIZE 1024


int compound_error(int status)
{
    if (status != NFS4_OK)
        dprintf(1, "COMPOUND failed with status %d.\n", status);
    return status;
}

static void compound_args_init(
    nfs41_compound_args *compound,
    nfs_argop4 *argarray)
{
    compound->tag_len = 8;
    memcpy(compound->tag, "ms-nfs41", 8);
    compound->minorversion = 1;
    compound->argarray_count = 0;
    compound->argarray = argarray;
}

static void compound_args_add_op(
    nfs41_compound_args *compound,
    uint32_t opnum,
    void *arg)
{
    const uint32_t i = compound->argarray_count++;
    compound->argarray[i].op = opnum;
    compound->argarray[i].arg = arg;
}

static void compound_res_init(
    nfs41_compound_res *compound,
    nfs_resop4 *resarray)
{
    ZeroMemory(compound, sizeof(nfs41_compound_res));
    compound->tag_len = NFS4_OPAQUE_LIMIT;
    compound->resarray_count = 0;
    compound->resarray = resarray;
}

static void compound_res_add_op(
    nfs41_compound_res *compound,
    void *res)
{
    compound->resarray[compound->resarray_count++].res = res;
}

void compound_init(
    nfs41_compound *compound,
    nfs_argop4 *argops,
    nfs_resop4 *resops)
{
    compound_args_init(&compound->args, argops);
    compound_res_init(&compound->res, resops);
}

void compound_add_op(
    nfs41_compound *compound,
    uint32_t opnum,
    void *arg,
    void *res)
{
    compound_args_add_op(&compound->args, opnum, arg);
    compound_res_add_op(&compound->res, res);
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

int check_renew_in_progress(
    IN nfs41_session *session)
{
    int status = 0;
    bool_t one = 1, zero = 0;;
    while (nfs41_renew_in_progress(session->client, NULL)) {
        status = WaitForSingleObject(session->client->cond, INFINITE);
        if (status != WAIT_OBJECT_0) {
            dprintf(1, "nfs41_renew_in_progress: WaitForSingleObject failed\n");
            print_condwait_status(1, status);
            status = ERROR_LOCK_VIOLATION;
            goto out;
        }
        nfs41_renew_in_progress(session->client, &zero);
        status = 1;
    }
    nfs41_renew_in_progress(session->client, &one);
out:
    return status;
}
int compound_encode_send_decode(
    nfs41_session *session,
    nfs41_compound *compound,
    uint32_t bufsize_in,
    uint32_t bufsize_out)
{
    int status, retry_count = 0, delayby = 0;
    nfs41_sequence_args *args =
        (nfs41_sequence_args *)compound->args.argarray[0].arg;
    bool_t zero = 0;

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
    if (compound->res.status != NFS4_OK && 
        compound->args.argarray[0].op == OP_DESTROY_SESSION) {
            dprintf(1, "OP_DESTROY_SESSION ignoring errors\n");
            compound->res.status = NFS4_OK;
    }

    switch (compound->res.status) {
    case NFS4_OK:
        break;

    case NFS4ERR_STALE_CLIENTID:
        //try to create a new client
        status = check_renew_in_progress(session);
        if (status == ERROR_LOCK_VIOLATION)
            goto out_free_slot;
        else if (status == 1)
            goto do_retry;
        status = nfs41_client_renew(session->client);
        if (status) {
            eprintf("nfs41_exchange_id() failed with %d\n", status);
            status = ERROR_BAD_NET_RESP;
            goto out;
        }
        //fallthru and reestablish the session
    case NFS4ERR_BADSESSION:
        //try to create a new session
        if (compound->res.status == NFS4ERR_BADSESSION) {
            status = check_renew_in_progress(session);
            if (status == ERROR_LOCK_VIOLATION)
                goto out_free_slot;
            else if (status == 1)
                goto do_retry;
        }
        status = nfs41_session_renew(session);
        if (status == NFS4ERR_STALE_CLIENTID) {
            status = nfs41_client_renew(session->client);
            if (status) {
                eprintf("nfs41_exchange_id() failed with %d\n", status);
                status = ERROR_BAD_NET_RESP;
                goto out;
            }
            status = nfs41_session_renew(session);
            if (status) {
                eprintf("after reestablishing clientid: nfs41_session_renew() "
                    "failed with %d\n", status);
                status = ERROR_BAD_NET_RESP;
                goto out;
            }
        } else if (status && status != NFS4ERR_STALE_CLIENTID) {
            eprintf("nfs41_session_renew: failed with %d\n", status);
            goto out;
        }
        if (nfs41_renew_in_progress(session->client, NULL))
            nfs41_renew_in_progress(session->client, &zero);
        goto do_retry;

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
