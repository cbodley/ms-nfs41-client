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
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nfs41_ops.h"
#include "nfs41_compound.h"
#include "nfs41_xdr.h"
#include "name_cache.h"
#include "daemon_debug.h"
#include "util.h"

#define BUF_SIZE 1024


int nfs41_exchange_id(
    IN nfs41_rpc_clnt *rpc,
    IN client_owner4 *owner,
    IN uint32_t flags_in,
    OUT nfs41_exchange_id_res *res_out)
{
    int status = 0;
    nfs41_compound compound;
    nfs_argop4 argop;
    nfs_resop4 resop;
    nfs41_exchange_id_args ex_id;

    compound_init(&compound, &argop, &resop, "exchange_id");

    compound_add_op(&compound, OP_EXCHANGE_ID, &ex_id, res_out);
    ex_id.eia_clientowner = owner;
    ex_id.eia_flags = flags_in;
    ex_id.eia_state_protect.spa_how = SP4_NONE;
    ex_id.eia_client_impl_id = NULL;

    res_out->server_owner.so_major_id_len = NFS4_OPAQUE_LIMIT;
    res_out->server_scope_len = NFS4_OPAQUE_LIMIT;

    status = nfs41_send_compound(rpc, (char *)&compound.args,
        (char *)&compound.res);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

// AGLO: 10/07/2009 we might want lookup these values from the registry
static int set_fore_channel_attrs(
    IN nfs41_rpc_clnt *rpc,
    IN uint32_t max_req,
    OUT nfs41_channel_attrs *attrs)
{
    attrs->ca_headerpadsize = 0;
    attrs->ca_maxrequestsize = rpc->wsize;
    attrs->ca_maxresponsesize = rpc->rsize;
    attrs->ca_maxresponsesize_cached = NFS41_MAX_SERVER_CACHE;
    attrs->ca_maxoperations = 0xffffffff;
    attrs->ca_maxrequests = max_req;
    attrs->ca_rdma_ird = NULL;
    return 0;
}

// AGLO: 10/07/2009 we might want lookup these values from the registry
static int set_back_channel_attrs(
    IN nfs41_rpc_clnt *rpc,
    IN uint32_t max_req,
    OUT nfs41_channel_attrs *attrs)
{
    attrs->ca_headerpadsize = 0;
    attrs->ca_maxrequestsize = rpc->wsize;
    attrs->ca_maxresponsesize = rpc->rsize;
    attrs->ca_maxresponsesize_cached = NFS41_MAX_SERVER_CACHE;
    attrs->ca_maxoperations = 0xffffffff;
    attrs->ca_maxrequests = max_req;
    attrs->ca_rdma_ird = NULL;
    return 0;
}

int nfs41_create_session(nfs41_client *clnt, nfs41_session *session, bool_t try_recovery)
{
    int status = 0;
    nfs41_compound compound;
    nfs_argop4 argop;
    nfs_resop4 resop;
    nfs41_create_session_args req;
    nfs41_create_session_res reply;

    compound_init(&compound, &argop, &resop, "create_session");

    compound_add_op(&compound, OP_CREATE_SESSION, &req, &reply);

    ZeroMemory(&req, sizeof(req));
    AcquireSRWLockShared(&clnt->exid_lock);
    req.csa_clientid = clnt->clnt_id;
    req.csa_sequence = clnt->seq_id;
    ReleaseSRWLockShared(&clnt->exid_lock);
    req.csa_flags = session->flags;
    req.csa_cb_program = NFS41_RPC_CBPROGRAM;

    // ca_maxrequests should be gotten from the rpc layer
    set_fore_channel_attrs(clnt->rpc,
        NFS41_MAX_RPC_REQS, &req.csa_fore_chan_attrs);
    set_back_channel_attrs(clnt->rpc,
        1, &req.csa_back_chan_attrs);
    
    ZeroMemory(&reply, sizeof(nfs41_create_session_res));
    reply.csr_sessionid = session->session_id;
    reply.csr_fore_chan_attrs = &session->fore_chan_attrs;
    reply.csr_back_chan_attrs = &session->back_chan_attrs;

    status = compound_encode_send_decode(session, &compound, try_recovery);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    print_hexbuf(1, (unsigned char *)"session id: ", session->session_id, NFS4_SESSIONID_SIZE);
    // check that csa_sequence is same as csr_sequence
    if (reply.csr_sequence != clnt->seq_id) {
        eprintf("ERROR: CREATE_SESSION: csa_sequence %d != "
            "csr_sequence %d\n", clnt->seq_id, reply.csr_sequence);
        status = NFS4ERR_SEQ_MISORDERED;
        goto out;
    } else clnt->seq_id++;

    if (reply.csr_flags != req.csa_flags) {
        eprintf("WARNING: requested session flags %x received %x\n",
            req.csa_flags, reply.csr_flags);
        if ((session->flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN) &&
                !(reply.csr_flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN))
            eprintf("WARNING: we asked to use this session for callbacks but "
                    "server refused\n");
        if ((session->flags & CREATE_SESSION4_FLAG_PERSIST) &&
            !(reply.csr_flags & CREATE_SESSION4_FLAG_PERSIST))
            eprintf("WARNING: we asked for persistent session but "
                    "server refused\n");
        session->flags = reply.csr_flags;
    }
    else
        dprintf(1, "session flags %x\n", reply.csr_flags);

    dprintf(1, "session fore_chan_attrs:\n"
        "  %-32s%d\n  %-32s%d\n  %-32s%d\n  %-32s%d\n  %-32s%d\n  %-32s%d\n",
        "headerpadsize", session->fore_chan_attrs.ca_headerpadsize,
        "maxrequestsize", session->fore_chan_attrs.ca_maxrequestsize,
        "maxresponsesize", session->fore_chan_attrs.ca_maxresponsesize,
        "maxresponsesize_cached", session->fore_chan_attrs.ca_maxresponsesize_cached,
        "maxoperations", session->fore_chan_attrs.ca_maxoperations,
        "maxrequests", session->fore_chan_attrs.ca_maxrequests);
    dprintf(1, "client supports %d max rpc slots, but server has %d\n", 
        session->table.max_slots, session->fore_chan_attrs.ca_maxrequests);
    /* use the server's ca_maxrequests unless it's bigger than our array */
    session->table.max_slots = min(session->table.max_slots,
        session->fore_chan_attrs.ca_maxrequests);
    status = 0;
out:
    return status;
}

enum nfsstat4 nfs41_bind_conn_to_session(
    IN nfs41_rpc_clnt *rpc,
    IN const unsigned char *sessionid,
    IN enum channel_dir_from_client4 dir)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argop;
    nfs_resop4 resop;
    nfs41_bind_conn_to_session_args bind_args;
    nfs41_bind_conn_to_session_res bind_res;

    compound_init(&compound, &argop, &resop, "bind_conn_to_session");

    compound_add_op(&compound, OP_BIND_CONN_TO_SESSION, &bind_args, &bind_res);
    bind_args.sessionid = (unsigned char *)sessionid;
    bind_args.dir = dir;
    ZeroMemory(&bind_res, sizeof(bind_res));

    status = nfs41_send_compound(rpc,
        (char*)&compound.args, (char*)&compound.res);
    if (status)
        goto out;

    compound_error(status = compound.res.status);

out:
    return status;
}

int nfs41_destroy_session(
    IN nfs41_session *session)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argop;
    nfs_resop4 resop;
    nfs41_destroy_session_args ds_args;
    nfs41_destroy_session_res ds_res;

    compound_init(&compound, &argop, &resop, "destroy_session");

    compound_add_op(&compound, OP_DESTROY_SESSION, &ds_args, &ds_res);
    ds_args.dsa_sessionid = session->session_id;

    /* don't attempt to recover from BADSESSION/STALE_CLIENTID */
    status = compound_encode_send_decode(session, &compound, FALSE);
    if (status)
        goto out;

    status = compound.res.status;
    if (status)
        eprintf("%s failed with status %d.\n",
            nfs_opnum_to_string(OP_DESTROY_SESSION), status);
out:
    return status;
}

int nfs41_destroy_clientid(
    IN nfs41_rpc_clnt *rpc,
    IN uint64_t clientid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops;
    nfs_resop4 resops;
    nfs41_destroy_clientid_args dc_args;
    nfs41_destroy_clientid_res dc_res;

    compound_init(&compound, &argops, &resops, "destroy_clientid");

    compound_add_op(&compound, OP_DESTROY_CLIENTID, &dc_args, &dc_res);
    dc_args.dca_clientid = clientid;

    status = nfs41_send_compound(rpc, (char *)&compound.args,
        (char *)&compound.res);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

enum nfsstat4 nfs41_reclaim_complete(
    IN nfs41_session *session)
{
    enum nfsstat4 status = NFS4_OK;
    nfs41_compound compound;
    nfs_argop4 argops[2];
    nfs_resop4 resops[2];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_reclaim_complete_res reclaim_res;

    compound_init(&compound, argops, resops, "reclaim_complete");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_RECLAIM_COMPLETE, NULL, &reclaim_res);

    /* don't attempt to recover from BADSESSION */
    status = compound_encode_send_decode(session, &compound, FALSE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

int nfs41_open(
    IN nfs41_session *session,
    IN uint32_t allow,
    IN uint32_t deny,
    IN uint32_t create,
    IN uint32_t how_mode,
    IN uint32_t mode,
    IN bool_t try_recovery,
    IN OUT nfs41_open_state *state,
    OUT OPTIONAL nfs41_file_info *info)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[8];
    nfs_resop4 resops[8];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_op_open_args open_args;
    nfs41_op_open_res open_res;
    nfs41_getfh_res getfh_res;
    bitmap4 attr_request;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res, pgetattr_res;
    nfs41_savefh_res savefh_res;
    nfs41_restorefh_res restorefh_res;
    nfs41_file_info tmp_info, dir_info;
    unsigned char createverf[NFS4_VERIFIER_SIZE];

    if (info == NULL)
        info = &tmp_info;

    init_getattr_request(&attr_request);
    attr_request.arr[0] |= FATTR4_WORD0_FSID;

    compound_init(&compound, argops, resops, "open");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = &state->parent;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SAVEFH, NULL, &savefh_res);

    compound_add_op(&compound, OP_OPEN, &open_args, &open_res);
    open_args.seqid = 0;
#ifdef DISABLE_FILE_DELEGATIONS
    open_args.share_access = allow | OPEN4_SHARE_ACCESS_WANT_NO_DELEG;
#else
    open_args.share_access = allow;
#endif
    open_args.share_deny = deny; 
    open_args.owner = &state->owner;
    open_args.openhow.opentype = create;
    open_args.openhow.how.mode = how_mode;
    open_args.openhow.how.createattrs.info.attrmask.count = 2;
    open_args.openhow.how.createattrs.info.attrmask.arr[0] = FATTR4_WORD0_SIZE;
    open_args.openhow.how.createattrs.info.attrmask.arr[1] = FATTR4_WORD1_MODE;
    open_args.openhow.how.createattrs.info.mode = mode;
    open_args.openhow.how.createattrs.info.size = 0;
    if (how_mode == EXCLUSIVE4_1) {
        DWORD tid = GetCurrentThreadId();
        open_args.openhow.how.createverf = createverf;
        time((time_t*)open_args.openhow.how.createverf);
        memcpy(open_args.openhow.how.createverf+4, &tid, sizeof(tid)); 
    }
    open_args.claim.claim = CLAIM_NULL;
    open_args.claim.u.null.filename = &state->file.name;
    open_res.resok4.stateid = &state->stateid;

    compound_add_op(&compound, OP_GETFH, NULL, &getfh_res);
    getfh_res.fh = &state->file.fh;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = info;

    compound_add_op(&compound, OP_RESTOREFH, NULL, &restorefh_res);

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &pgetattr_res);
    getattr_args.attr_request = &attr_request;
    pgetattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    pgetattr_res.info = &dir_info;

    status = compound_encode_send_decode(session, &compound, try_recovery);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* fill in the file handle's fileid and superblock */
    state->file.fh.fileid = info->fileid;
    status = nfs41_superblock_for_fh(session,
        &info->fsid, &state->parent.fh, &state->file);
    if (status)
        goto out;

    /* update the attributes of the parent directory */
    memcpy(&dir_info.attrmask, &pgetattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        state->parent.fh.fileid, &dir_info);

    /* add the file handle and attributes to the name cache */
    memcpy(&info->attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    AcquireSRWLockShared(&state->path.lock);
    nfs41_name_cache_insert(session_name_cache(session),
        state->path.path, &state->file.name, &state->file.fh,
        info, &open_res.resok4.cinfo);
    ReleaseSRWLockShared(&state->path.lock);

#define RETURN_DELEG_ON_OPEN
#ifdef RETURN_DELEG_ON_OPEN
    /* if the server gave us a delegation, return it immediately */
    if (open_res.resok4.delegation_type == OPEN_DELEGATE_READ ||
        open_res.resok4.delegation_type == OPEN_DELEGATE_WRITE) {
        nfs41_delegreturn(session, &state->file,
            &open_res.resok4.deleg_stateid);
    }
#endif
out:
    return status;
}

int nfs41_open_reclaim(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN nfs41_path_fh *file,
    IN state_owner4 *owner,
    IN uint32_t allow,
    IN uint32_t deny,
    OUT stateid4 *stateid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[6];
    nfs_resop4 resops[6];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args[2];
    nfs41_putfh_res putfh_res[2];
    nfs41_op_open_args open_args;
    nfs41_op_open_res open_res;
    bitmap4 attr_request;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res, pgetattr_res;
    nfs41_file_info info, dir_info;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "open reclaim");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args[0], &putfh_res[0]);
    putfh_args[0].file = file;
    putfh_args[0].in_recovery = 0;

    compound_add_op(&compound, OP_OPEN, &open_args, &open_res);
    open_args.seqid = 0;
    open_args.share_access = allow | OPEN4_SHARE_ACCESS_WANT_NO_DELEG;
    open_args.share_deny = deny; 
    open_args.owner = owner;
    open_args.openhow.opentype = OPEN4_NOCREATE;
    open_args.claim.claim = CLAIM_PREVIOUS;
    open_args.claim.u.prev.delegate_type = OPEN_DELEGATE_NONE;
    open_res.resok4.stateid = stateid;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &info;

    compound_add_op(&compound, OP_PUTFH, &putfh_args[1], &putfh_res[1]);
    putfh_args[1].file = parent;
    putfh_args[1].in_recovery = 0;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &pgetattr_res);
    getattr_args.attr_request = &attr_request;
    pgetattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    pgetattr_res.info = &dir_info;

    /* don't attempt to recover from BADSESSION errors */
    status = compound_encode_send_decode(session, &compound, FALSE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attributes of the parent directory */
    memcpy(&dir_info.attrmask, &pgetattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        parent->fh.fileid, &dir_info);

    /* update the attributes of the file */
    memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, &info);
out:
    return status;
}

int nfs41_create(
    IN nfs41_session *session,
    IN uint32_t type,
    IN uint32_t mode,
    IN OPTIONAL const char *symlink,
    IN nfs41_path_fh *parent,
    OUT nfs41_path_fh *file)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[8];
    nfs_resop4 resops[8];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_create_args create_args;
    nfs41_create_res create_res;
    nfs41_getfh_res getfh_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res, pgetattr_res;
    bitmap4 attr_request;
    nfs41_file_info file_info, dir_info;
    nfs41_savefh_res savefh_res;
    nfs41_restorefh_res restorefh_res;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "create");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = parent;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SAVEFH, NULL, &savefh_res);

    compound_add_op(&compound, OP_CREATE, &create_args, &create_res);
    create_args.objtype.type = type;
    if (type == NF4LNK) {
        create_args.objtype.u.lnk.linkdata = symlink;
        create_args.objtype.u.lnk.linkdata_len = (uint32_t)strlen(symlink);
    }
    create_args.name = &file->name;
    create_args.createattrs.info.attrmask.count = 2;
    create_args.createattrs.info.attrmask.arr[0] = 0;
    create_args.createattrs.info.attrmask.arr[1] = FATTR4_WORD1_MODE;
    create_args.createattrs.info.mode = mode; //511; // 0777

    compound_add_op(&compound, OP_GETFH, NULL, &getfh_res);
    getfh_res.fh = &file->fh;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &file_info;

    compound_add_op(&compound, OP_RESTOREFH, NULL, &restorefh_res);

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &pgetattr_res);
    getattr_args.attr_request = &attr_request;
    pgetattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    pgetattr_res.info = &dir_info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* fill in the file handle's fileid and superblock */
    file->fh.fileid = file_info.fileid;
    file->fh.superblock = parent->fh.superblock;

    /* update the attributes of the parent directory */
    memcpy(&dir_info.attrmask, &pgetattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        parent->fh.fileid, &dir_info);

    /* add the new file handle and attributes to the name cache */
    memcpy(&file_info.attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    AcquireSRWLockShared(&file->path->lock);
    nfs41_name_cache_insert(session_name_cache(session),
        file->path->path, &file->name, &file->fh,
        &file_info, &create_res.cinfo);
    ReleaseSRWLockShared(&file->path->lock);
out:
    return status;
}

int nfs41_close(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_op_close_args close_args;
    nfs41_op_close_res close_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res;
    bitmap4 attr_request;
    nfs41_file_info info;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "close");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_CLOSE, &close_args, &close_res);
    close_args.stateid = stateid;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attributes of the parent directory */
    memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, &info);

out:
    return status;
}

int nfs41_write(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN unsigned char *data,
    IN uint32_t data_len,
    IN uint64_t offset,
    IN enum stable_how4 stable,
    OUT uint32_t *bytes_written,
    OUT nfs41_write_verf *verf)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_write_args write_args;
    nfs41_write_res write_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res = {0};
    bitmap4 attr_request;
    nfs41_file_info info;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "write");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_WRITE, &write_args, &write_res);
    write_args.stateid = stateid;
    write_args.offset = offset;
    write_args.stable = stable;
    write_args.data_len = data_len;
    write_args.data = data;
    write_res.resok4.verf = verf;

    if (stable != UNSTABLE4) {
        /* if the write is stable, we can't rely on COMMIT to update
         * the attribute cache, so we do the GETATTR here */
        compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
        getattr_args.attr_request = &attr_request;
        getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
        getattr_res.info = &info;
    }

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    if (stable != UNSTABLE4) {
        /* update the attribute cache */
        memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
            sizeof(bitmap4));
        nfs41_attr_cache_update(session_name_cache(session),
            file->fh.fileid, &info);
    }

    *bytes_written = write_res.resok4.count;

    /* we shouldn't ever see this, but a buggy server could
     * send us into an infinite loop. return NFS4ERR_IO */
    if (!write_res.resok4.count) {
        status = NFS4ERR_IO;
        eprintf("WRITE succeeded with count=0; returning %s\n",
            nfs_error_string(status));
    }
out:
    return status;
}

int nfs41_read(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN uint64_t offset,
    IN uint32_t count,
    OUT unsigned char *data_out,
    OUT uint32_t *data_len_out,
    OUT bool_t *eof_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_read_args read_args;
    nfs41_read_res read_res;

    compound_init(&compound, argops, resops, "read");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_READ, &read_args, &read_res);
    read_args.stateid = stateid;
    read_args.offset = offset;
    read_args.count = count;
    read_res.resok4.data_len = count;
    read_res.resok4.data = data_out;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    *data_len_out = read_res.resok4.data_len;
    *eof_out = read_res.resok4.eof;

    /* we shouldn't ever see this, but a buggy server could
     * send us into an infinite loop. return NFS4ERR_IO */
    if (!read_res.resok4.data_len && !read_res.resok4.eof) {
        status = NFS4ERR_IO;
        eprintf("READ succeeded with len=0 and eof=0; returning %s\n",
            nfs_error_string(status));
    }
out:
    return status;
}

int nfs41_commit(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN uint64_t offset,
    IN uint32_t count,
    IN bool_t do_getattr)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_commit_args commit_args;
    nfs41_commit_res commit_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res = {0};
    bitmap4 attr_request;
    nfs41_file_info info;

    compound_init(&compound, argops, resops, "commit");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_COMMIT, &commit_args, &commit_res);
    commit_args.offset = offset;
    commit_args.count = count;

    /* send a GETATTR request to update the attribute cache,
     * but not if we're talking to a data server! */
    if (do_getattr) {
        init_getattr_request(&attr_request);

        compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
        getattr_args.attr_request = &attr_request;
        getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
        getattr_res.info = &info;
    }

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    if (do_getattr) {
        /* update the attribute cache */
        memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
            sizeof(bitmap4));
        nfs41_attr_cache_update(session_name_cache(session),
            file->fh.fileid, &info);
    }
out:
    return status;
}

int nfs41_lock(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN state_owner4 *owner,
    IN uint32_t type,
    IN uint64_t offset,
    IN uint64_t length,
    IN bool_t reclaim,
    IN bool_t try_recovery,
    IN OUT stateid_arg *stateid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_lock_args lock_args;
    nfs41_lock_res lock_res;

    compound_init(&compound, argops, resops, "lock");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LOCK, &lock_args, &lock_res);
    lock_args.locktype = type;
    lock_args.reclaim = reclaim;
    lock_args.offset = offset;
    lock_args.length = length;
    if (stateid->type == STATEID_LOCK) {
        lock_args.locker.new_lock_owner = 0;
        lock_args.locker.u.lock_owner.lock_stateid = stateid;
        lock_args.locker.u.lock_owner.lock_seqid = 0; /* ignored */
    } else {
        lock_args.locker.new_lock_owner = 1;
        lock_args.locker.u.open_owner.open_seqid = 0; /* ignored */
        lock_args.locker.u.open_owner.open_stateid = stateid;
        lock_args.locker.u.open_owner.lock_seqid = 0; /* ignored */
        lock_args.locker.u.open_owner.lock_owner = owner;
    }
    lock_res.u.resok4.lock_stateid = &stateid->stateid;
    lock_res.u.denied.owner.owner_len = NFS4_OPAQUE_LIMIT;

    status = compound_encode_send_decode(session, &compound, try_recovery);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    stateid->type = STATEID_LOCK; /* returning a lock stateid */
out:
    return status;
}

int nfs41_unlock(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN uint64_t offset,
    IN uint64_t length,
    IN OUT stateid_arg *stateid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_locku_args locku_args;
    nfs41_locku_res locku_res;

    compound_init(&compound, argops, resops, "unlock");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LOCKU, &locku_args, &locku_res);
    /* 18.12.3: the server MUST accept any legal value for locktype */
    locku_args.locktype = READ_LT;
    locku_args.offset = offset;
    locku_args.length = length;
    locku_args.lock_stateid = stateid;
    locku_res.lock_stateid = &stateid->stateid;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

int nfs41_readdir(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN bitmap4 *attr_request,
    IN nfs41_readdir_cookie *cookie,
    OUT unsigned char *entries,
    IN OUT uint32_t *entries_len,
    OUT bool_t *eof_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_readdir_args readdir_args;
    nfs41_readdir_res readdir_res;

    compound_init(&compound, argops, resops, "readdir");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_READDIR, &readdir_args, &readdir_res);
    readdir_args.cookie.cookie = cookie->cookie;
    memcpy(readdir_args.cookie.verf, cookie->verf, NFS4_VERIFIER_SIZE);
    readdir_args.dircount = *entries_len;
    readdir_args.maxcount = *entries_len + sizeof(nfs41_readdir_res);
    readdir_args.attr_request = attr_request;
    readdir_res.reply.entries_len = *entries_len;
    readdir_res.reply.entries = entries;
    ZeroMemory(entries, readdir_args.dircount);

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    *entries_len = readdir_res.reply.entries_len;
    *eof_out = readdir_res.reply.eof;
    memcpy(cookie->verf, readdir_res.cookieverf, NFS4_VERIFIER_SIZE);
out:
    return status;
}

void init_getattr_request(bitmap4 *attr_request)
{
    attr_request->count = 2;
    attr_request->arr[0] = FATTR4_WORD0_TYPE |
        FATTR4_WORD0_CHANGE | FATTR4_WORD0_SIZE | FATTR4_WORD0_FILEID;
    attr_request->arr[1] = FATTR4_WORD1_NUMLINKS |
        FATTR4_WORD1_TIME_ACCESS | FATTR4_WORD1_TIME_CREATE |
        FATTR4_WORD1_TIME_MODIFY | FATTR4_WORD1_MODE |
        FATTR4_WORD1_OWNER | FATTR4_WORD1_OWNER_GROUP;
    attr_request->arr[2] = 0;
}

int nfs41_getattr(
    IN nfs41_session *session,
    IN OPTIONAL nfs41_path_fh *file,
    IN bitmap4 *attr_request,
    OUT nfs41_file_info *info)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res;

    compound_init(&compound, argops, resops, "getattr");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    if (file) {
        compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
        putfh_args.file = file;
        putfh_args.in_recovery = 0;
    } else {
        compound_add_op(&compound, OP_PUTROOTFH, NULL, &putfh_res);
    }

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    if (file) {
        /* update the name cache with whatever attributes we got */
        memcpy(&info->attrmask, &getattr_res.obj_attributes.attrmask,
            sizeof(bitmap4));
        nfs41_attr_cache_update(session_name_cache(session),
            file->fh.fileid, info);
    }
out:
    return status;
}

int nfs41_remove(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN const nfs41_component *target)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_remove_args remove_args;
    nfs41_remove_res remove_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res;
    bitmap4 attr_request;
    nfs41_file_info info;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "remove");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = parent;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_REMOVE, &remove_args, &remove_res);
    remove_args.target = target;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attributes of the parent directory */
    memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        parent->fh.fileid, &info);

    /* remove the target file from the cache */
    AcquireSRWLockShared(&parent->path->lock);
    nfs41_name_cache_remove(session_name_cache(session),
        parent->path->path, target, &remove_res.cinfo);
    ReleaseSRWLockShared(&parent->path->lock);
out:
    return status;
}

int nfs41_rename(
    IN nfs41_session *session,
    IN nfs41_path_fh *src_dir,
    IN const nfs41_component *src_name,
    IN nfs41_path_fh *dst_dir,
    IN const nfs41_component *dst_name)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[8];
    nfs_resop4 resops[8];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args src_putfh_args;
    nfs41_putfh_res src_putfh_res;
    nfs41_savefh_res savefh_res;
    nfs41_putfh_args dst_putfh_args;
    nfs41_putfh_res dst_putfh_res;
    nfs41_rename_args rename_args;
    nfs41_rename_res rename_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res src_getattr_res, dst_getattr_res;
    nfs41_file_info src_info, dst_info;
    bitmap4 attr_request;
    nfs41_restorefh_res restorefh_res;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "rename");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &src_putfh_args, &src_putfh_res);
    src_putfh_args.file = src_dir;
    src_putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SAVEFH, NULL, &savefh_res);

    compound_add_op(&compound, OP_PUTFH, &dst_putfh_args, &dst_putfh_res);
    dst_putfh_args.file = dst_dir;
    dst_putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_RENAME, &rename_args, &rename_res);
    rename_args.oldname = src_name;
    rename_args.newname = dst_name;
    
    compound_add_op(&compound, OP_GETATTR, &getattr_args, &dst_getattr_res);
    getattr_args.attr_request = &attr_request;
    dst_getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    dst_getattr_res.info = &dst_info;

    compound_add_op(&compound, OP_RESTOREFH, NULL, &restorefh_res);

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &src_getattr_res);
    src_getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    src_getattr_res.info = &src_info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attributes of the source directory */
    memcpy(&src_info.attrmask, &src_getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        src_dir->fh.fileid, &src_info);

    /* update the attributes of the destination directory */
    memcpy(&dst_info.attrmask, &dst_getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        dst_dir->fh.fileid, &dst_info);

    if (src_dir->path == dst_dir->path) {
        /* source and destination are the same, only lock it once */
        AcquireSRWLockShared(&src_dir->path->lock);
    } else if (src_dir->path < dst_dir->path) {
        /* lock the lowest memory address first */
        AcquireSRWLockShared(&src_dir->path->lock);
        AcquireSRWLockShared(&dst_dir->path->lock);
    } else {
        AcquireSRWLockShared(&dst_dir->path->lock);
        AcquireSRWLockShared(&src_dir->path->lock);
    }

    /* move/rename the target file's name cache entry */
    nfs41_name_cache_rename(session_name_cache(session),
        src_dir->path->path, src_name, &rename_res.source_cinfo,
        dst_dir->path->path, dst_name, &rename_res.target_cinfo);

    if (src_dir->path == dst_dir->path) {
        ReleaseSRWLockShared(&src_dir->path->lock);
    } else {
        ReleaseSRWLockShared(&src_dir->path->lock);
        ReleaseSRWLockShared(&dst_dir->path->lock);
    }
out:
    return status;
}

int nfs41_setattr(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN nfs41_file_info *info)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_setattr_args setattr_args;
    nfs41_setattr_res setattr_res;

    compound_init(&compound, argops, resops, "setattr");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SETATTR, &setattr_args, &setattr_res);
    setattr_args.stateid = stateid;
    setattr_args.info = info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    memcpy(&info->attrmask, &setattr_res.attrsset, sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, info);
out:
    return status;
}

int nfs41_link(
    IN nfs41_session *session,
    IN nfs41_path_fh *src,
    IN nfs41_path_fh *dst_dir,
    IN const nfs41_component *target,
    OUT OPTIONAL nfs41_path_fh *link_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[9];
    nfs_resop4 resops[9];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args[2];
    nfs41_putfh_res putfh_res[2];
    nfs41_savefh_res savefh_res;
    nfs41_link_args link_args;
    nfs41_link_res link_res;
    nfs41_lookup_args lookup_args;
    nfs41_lookup_res lookup_res;
    nfs41_getfh_res getfh_res;
    nfs41_getattr_args getattr_args[2];
    nfs41_getattr_res getattr_res[2];
    nfs41_file_info info[2];
    nfs41_path_fh file;

    if (link_out == NULL)
        link_out = &file;

    ZeroMemory(&info, sizeof(info));
    init_getattr_request(&info[0].attrmask);
    init_getattr_request(&info[1].attrmask);
    info[1].attrmask.arr[0] |= FATTR4_WORD0_FSID;

    compound_init(&compound, argops, resops, "link");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 1);
    if (status)
        goto out;

    /* PUTFH(src) */
    compound_add_op(&compound, OP_PUTFH, &putfh_args[0], &putfh_res[0]);
    putfh_args[0].file = src;
    putfh_args[0].in_recovery = 0;

    compound_add_op(&compound, OP_SAVEFH, NULL, &savefh_res);

    /* PUTFH(dst_dir) */
    compound_add_op(&compound, OP_PUTFH, &putfh_args[1], &putfh_res[1]);
    putfh_args[1].file = dst_dir;
    putfh_args[1].in_recovery = 0;

    compound_add_op(&compound, OP_LINK, &link_args, &link_res);
    link_args.newname = target;

    /* GETATTR(dst_dir) */
    compound_add_op(&compound, OP_GETATTR, &getattr_args[0], &getattr_res[0]);
    getattr_args[0].attr_request = &info[0].attrmask;
    getattr_res[0].obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res[0].info = &info[0];

    /* LOOKUP(target) */
    compound_add_op(&compound, OP_LOOKUP, &lookup_args, &lookup_res);
    lookup_args.name = target;

    /* GETATTR(target) */
    compound_add_op(&compound, OP_GETATTR, &getattr_args[1], &getattr_res[1]);
    getattr_args[1].attr_request = &info[1].attrmask;
    getattr_res[1].obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res[1].info = &info[1];

    /* GETFH(target) */
    compound_add_op(&compound, OP_GETFH, NULL, &getfh_res);
    getfh_res.fh = &link_out->fh;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* fill in the file handle's fileid and superblock */
    link_out->fh.fileid = info[1].fileid;
    status = nfs41_superblock_for_fh(session,
        &info[1].fsid, &dst_dir->fh, link_out);
    if (status)
        goto out;

    /* update the attributes of the destination directory */
    memcpy(&info[0].attrmask, &getattr_res[0].obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        info[0].fileid, &info[0]);

    /* add the new file handle and attributes to the name cache */
    memcpy(&info[1].attrmask, &getattr_res[1].obj_attributes.attrmask,
        sizeof(bitmap4));
    AcquireSRWLockShared(&dst_dir->path->lock);
    nfs41_name_cache_insert(session_name_cache(session),
        dst_dir->path->path, target, &link_out->fh,
        &info[1], &link_res.cinfo);
    ReleaseSRWLockShared(&dst_dir->path->lock);
out:
    return status;
}

int nfs41_readlink(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN uint32_t max_len,
    OUT char *link_out,
    OUT uint32_t *len_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_readlink_res readlink_res;

    compound_init(&compound, argops, resops, "readlink");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_READLINK, NULL, &readlink_res);
    readlink_res.link_len = max_len - 1;
    readlink_res.link = link_out;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    link_out[readlink_res.link_len] = '\0';
    *len_out = readlink_res.link_len;
out:
    return status;
}

int nfs41_access(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN uint32_t requested,
    OUT uint32_t *supported OPTIONAL,
    OUT uint32_t *access OPTIONAL)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_access_args access_args;
    nfs41_access_res access_res;

    compound_init(&compound, argops, resops, "access");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_ACCESS, &access_args, &access_res);
    access_args.access = requested;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    if (supported)
        *supported = access_res.supported;
    if (access)
        *access = access_res.access;
out:
    return status;
}

int nfs41_send_sequence(
    IN nfs41_session *session)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[1];
    nfs_resop4 resops[1];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;

    compound_init(&compound, argops, resops, "sequence");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;
out:
    return status;
}

int nfs41_delegreturn(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid4 *stateid)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_delegreturn_args dr_args;
    nfs41_delegreturn_res dr_res;

    compound_init(&compound, argops, resops, "delegreturn");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_DELEGRETURN, &dr_args, &dr_res);
    dr_args.stateid = stateid;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

enum nfsstat4 nfs41_fs_locations(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN const nfs41_component *name,
    OUT fs_locations4 *locations)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_lookup_args lookup_args;
    nfs41_lookup_res lookup_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res;
    bitmap4 attr_request = { 1, { FATTR4_WORD0_FS_LOCATIONS } };
    nfs41_file_info info;

    compound_init(&compound, argops, resops, "fs_locations");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = parent;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LOOKUP, &lookup_args, &lookup_res);
    lookup_args.name = name;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    info.fs_locations = locations;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

int nfs41_secinfo(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN const nfs41_component *name,
    OUT nfs41_secinfo_info *secinfo)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_secinfo_args secinfo_args;
    nfs41_secinfo_noname_res secinfo_res;

    compound_init(&compound, argops, resops, "secinfo");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SECINFO, &secinfo_args, &secinfo_res);
    secinfo_args.name = name;
    secinfo_res.secinfo = secinfo;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

int nfs41_secinfo_noname(
    IN nfs41_session *session,
    OUT nfs41_secinfo_info *secinfo)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_res putfh_res;
    nfs41_secinfo_noname_args noname_args;
    nfs41_secinfo_noname_res noname_res;

    compound_init(&compound, argops, resops, "secinfo_no_name");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTROOTFH, NULL, &putfh_res);

    compound_add_op(&compound, OP_SECINFO_NO_NAME, &noname_args, &noname_res);
    noname_args.type = SECINFO_STYLE4_CURRENT_FH;
    noname_res.secinfo = secinfo;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

enum nfsstat4 pnfs_rpc_layoutget(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length,
    OUT pnfs_layoutget_res_ok *layoutget_res_ok)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    pnfs_layoutget_args layoutget_args;
    pnfs_layoutget_res layoutget_res;
    uint32_t i;
    struct list_entry *entry;

    compound_init(&compound, argops, resops, "layoutget");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LAYOUTGET, &layoutget_args, &layoutget_res);
    layoutget_args.signal_layout_avail = 0;
    layoutget_args.layout_type = PNFS_LAYOUTTYPE_FILE;
    layoutget_args.iomode = iomode;
    layoutget_args.offset = offset;
    layoutget_args.minlength = layoutget_args.length = length;
    layoutget_args.stateid = stateid;
    layoutget_args.maxcount = session->fore_chan_attrs.ca_maxresponsesize - READ_OVERHEAD;
    ZeroMemory(&layoutget_res, sizeof(layoutget_res));
    layoutget_res.u.res_ok = layoutget_res_ok;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* point each file handle to the meta server's superblock */
    list_for_each(entry, &layoutget_res_ok->layouts) {
        pnfs_layout *base = list_container(entry, pnfs_layout, entry);
        if (base->type == PNFS_LAYOUTTYPE_FILE) {
            pnfs_file_layout *layout = (pnfs_file_layout*)base;
            for (i = 0; i < layout->filehandles.count; i++)
                layout->filehandles.arr[i].fh.superblock = file->fh.superblock;
        }
    }
out:
    return status;
}

enum nfsstat4 pnfs_rpc_layoutcommit(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid4 *stateid,
    IN uint64_t offset,
    IN uint64_t length,
    IN OPTIONAL uint64_t *new_last_offset,
    IN OPTIONAL nfstime4 *new_time_modify)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    pnfs_layoutcommit_args lc_args;
    pnfs_layoutcommit_res lc_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res;
    nfs41_file_info info;
    bitmap4 attr_request;

    init_getattr_request(&attr_request);

    compound_init(&compound, argops, resops, "layoutcommit");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LAYOUTCOMMIT, &lc_args, &lc_res);
    lc_args.offset = offset;
    lc_args.length = length;
    lc_args.stateid = stateid;
    lc_args.new_time = new_time_modify;
    lc_args.new_offset = new_last_offset;

    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = &info;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attribute cache */
    memcpy(&info.attrmask, &getattr_res.obj_attributes.attrmask,
        sizeof(bitmap4));
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, &info);
out:
    return status;
}

enum nfsstat4 pnfs_rpc_layoutreturn(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN enum pnfs_layout_type type,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length,
    IN stateid4 *stateid,
    OUT pnfs_layoutreturn_res *layoutreturn_res)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[3];
    nfs_resop4 resops[3];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    pnfs_layoutreturn_args layoutreturn_args;

    compound_init(&compound, argops, resops, "layoutreturn");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_LAYOUTRETURN, &layoutreturn_args, layoutreturn_res);
    layoutreturn_args.reclaim = 0;
    layoutreturn_args.type = type;
    layoutreturn_args.iomode = iomode;
    layoutreturn_args.return_type = PNFS_RETURN_FILE;
    layoutreturn_args.offset = offset;
    layoutreturn_args.length = length;
    layoutreturn_args.stateid = stateid;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

enum nfsstat4 pnfs_rpc_getdeviceinfo(
    IN nfs41_session *session,
    IN unsigned char *deviceid,
    OUT pnfs_file_device *device)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[2];
    nfs_resop4 resops[2];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    pnfs_getdeviceinfo_args getdeviceinfo_args;
    pnfs_getdeviceinfo_res getdeviceinfo_res;

    compound_init(&compound, argops, resops, "get_deviceinfo");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_GETDEVICEINFO,
        &getdeviceinfo_args, &getdeviceinfo_res);
    getdeviceinfo_args.deviceid = deviceid;
    getdeviceinfo_args.layout_type = PNFS_LAYOUTTYPE_FILE;
    getdeviceinfo_args.maxcount = NFS41_MAX_SERVER_CACHE; /* XXX */
    getdeviceinfo_args.notify_types.count = 0;
    getdeviceinfo_res.u.res_ok.device = device;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}

enum nfsstat4 nfs41_rpc_openattr(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN bool_t createdir,
    OUT nfs41_fh *fh_out)
{
    enum nfsstat4 status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs41_openattr_args openattr_args;
    nfs41_openattr_res openattr_res;
    nfs41_getfh_res getfh_res;

    compound_init(&compound, argops, resops, "openattr");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = FALSE;

    compound_add_op(&compound, OP_OPENATTR, &openattr_args, &openattr_res);
    openattr_args.createdir = createdir;

    compound_add_op(&compound, OP_GETFH, NULL, &getfh_res);
    getfh_res.fh = fh_out;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    compound_error(status = compound.res.status);
out:
    return status;
}
