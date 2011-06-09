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

#ifndef DELEGATION_H
#define DELEGATION_H

#include "nfs41.h"


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
    IN nfs41_path_fh *file,
    IN open_delegation4 *delegation,
    OUT nfs41_delegation_state **deleg_out);

int nfs41_delegate_open(
    IN nfs41_client *client,
    IN nfs41_path_fh *file,
    IN uint32_t create,
    IN uint32_t access,
    IN uint32_t deny,
    OUT nfs41_delegation_state **deleg_out,
    OUT nfs41_file_info *info);

#endif /* DELEGATION_H */
