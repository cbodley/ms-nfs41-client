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

#ifndef DELEGATION_H
#define DELEGATION_H

#include "nfs41.h"


/* option to avoid conflicts by returning the delegation */
#define DELEGATION_RETURN_ON_CONFLICT


/* reference counting and cleanup */
void nfs41_delegation_ref(
    IN nfs41_delegation_state *state);

void nfs41_delegation_deref(
    IN nfs41_delegation_state *state);

void nfs41_client_delegation_free(
    IN nfs41_client *client);


/* open delegation */
int nfs41_delegation_granted(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN nfs41_path_fh *file,
    IN open_delegation4 *delegation,
    IN bool_t try_recovery,
    OUT nfs41_delegation_state **deleg_out);

int nfs41_delegate_open(
    IN nfs41_client *client,
    IN nfs41_path_fh *file,
    IN uint32_t create,
    IN uint32_t mode,
    IN uint32_t access,
    IN uint32_t deny,
    OUT nfs41_delegation_state **deleg_out,
    OUT nfs41_file_info *info);

int nfs41_delegation_to_open(
    IN nfs41_open_state *open,
    IN bool_t try_recovery);


/* synchronous delegation return */
#ifdef DELEGATION_RETURN_ON_CONFLICT
int nfs41_delegation_return(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN enum open_delegation_type4 access,
    IN bool_t truncate);
#else
static int nfs41_delegation_return(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN enum open_delegation_type4 access,
    IN bool_t truncate)
{
    return NFS4_OK;
}
#endif


/* asynchronous delegation recall */
int nfs41_delegation_recall(
    IN nfs41_client *client,
    IN nfs41_fh *fh,
    IN const stateid4 *stateid,
    IN bool_t truncate);


/* after client state recovery, return any 'recalled' delegations;
 * must be called under the client's state lock */
int nfs41_client_delegation_recovery(
    IN nfs41_client *client);

#endif /* DELEGATION_H */
