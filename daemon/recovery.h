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

#ifndef RECOVERY_H
#define RECOVERY_H

#include "nfs41.h"


/* session/client recovery uses a lock and condition variable in nfs41_client
 * to prevent multiple threads from attempting to recover at the same time */
bool_t nfs41_recovery_start_or_wait(
    IN nfs41_client *client);

void nfs41_recovery_finish(
    IN nfs41_client *client);


void nfs41_recover_sequence_flags(
    IN nfs41_session *session,
    IN uint32_t flags);

int nfs41_recover_client_state(
    IN nfs41_session *session,
    IN nfs41_client *client);

void nfs41_client_state_revoked(
    IN nfs41_session *session,
    IN nfs41_client *client,
    IN uint32_t revoked);

struct __nfs_argop4;
bool_t nfs41_recover_stateid(
    IN nfs41_session *session,
    IN struct __nfs_argop4 *argop);

#endif /* RECOVERY_H */
