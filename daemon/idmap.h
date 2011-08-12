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

#ifndef IDMAP_H
#define IDMAP_H

#include "nfs41_types.h"


/* idmap.c */
typedef struct idmap_context nfs41_idmapper;

int nfs41_idmap_create(
    nfs41_idmapper **context_out);

void nfs41_idmap_free(
    nfs41_idmapper *context);


int nfs41_idmap_name_to_ids(
    nfs41_idmapper *context,
    const char *username,
    uid_t *uid_out,
    gid_t *gid_out);

int nfs41_idmap_uid_to_name(
    nfs41_idmapper *context,
    uid_t uid,
    char *name_out,
    size_t len);

int nfs41_idmap_principal_to_ids(
    nfs41_idmapper *context,
    const char *principal,
    uid_t *uid_out,
    gid_t *gid_out);

int nfs41_idmap_group_to_gid(
    nfs41_idmapper *context,
    const char *name,
    gid_t *gid_out);

int nfs41_idmap_gid_to_group(
    nfs41_idmapper *context,
    gid_t gid,
    char *name_out,
    size_t len);

#endif /* !IDMAP_H */
