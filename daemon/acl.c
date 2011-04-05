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
#include <sddl.h>

#include "nfs41.h"
#include "nfs41_ops.h"
#include "daemon_debug.h"
#include "util.h"
#include "upcall.h"
#include "nfs41_xdr.h"

static int parse_getacl(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    upcall_root_ref(upcall, args->root);
    status = safe_read(&buffer, &length, &args->state, sizeof(args->state));
    if (status) goto out;
    upcall_open_state_ref(upcall, args->state);
    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;

    dprintf(1, "parsing NFS41_ACL_QUERY: info_class=%d root=0x%p open_state=0x%p\n",
        args->query, args->root, args->state);
out:
    return status;
}

static int create_unknownsid(WELL_KNOWN_SID_TYPE type, PSID *sid, DWORD *sid_len)
{
    int status;
    *sid_len = 0;
    *sid = NULL;
    if (!CreateWellKnownSid(type, NULL, *sid, sid_len)) {
        status = GetLastError();
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            *sid = malloc(*sid_len);
            if (*sid == NULL) return ERROR_INSUFFICIENT_BUFFER;
            if (!CreateWellKnownSid(type, NULL, *sid, sid_len)) {
                free(*sid);
                status = GetLastError();
                dprintf(1, "CreateWellKnownSid failed with %d\n", status);
                return status;
            } else return 0;
        } else return status;
    } else return ERROR_INTERNAL_ERROR;
}

static void convert_nfs4name_2_user_domain(LPSTR nfs4name, 
    LPSTR *domain)
{
    LPSTR p = nfs4name;
    for(; p[0] != '\0'; p++) {
        if (p[0] == '@') { 
            p[0] = '\0';
            *domain = &p[1];
            break;
        }
    }
}

static int map_name_2_sid(DWORD *sid_len, PSID *sid, LPCSTR name)
{
    int status;
    SID_NAME_USE sid_type;
    LPSTR tmp_buf = NULL;
    DWORD tmp = 0;

    status = LookupAccountName(NULL, name, NULL, sid_len, NULL, &tmp, &sid_type);
    dprintf(1, "LookupAccountName returned %d GetLastError %d owner len %d "
        "domain len %d\n", status, GetLastError(), *sid_len, tmp); 
    if (!status) {
        status = GetLastError();
        switch(status) {
        case ERROR_INSUFFICIENT_BUFFER:
            *sid = malloc(*sid_len);
            if (*sid == NULL) {
                status = GetLastError();
                goto out;
            }
            tmp_buf = (LPSTR) malloc(tmp);
            if (tmp_buf == NULL) {
                status = GetLastError();
                free(*sid);
                goto out;
            }
            status = LookupAccountName(NULL, name, *sid, sid_len, tmp_buf, 
                                        &tmp, &sid_type);
            dprintf(1, "sid_type = %d\n", sid_type);
            free(tmp_buf);
            if (!status) {
                status = GetLastError();
                free(*sid);
                dprintf(1, "handle_getacl: LookupAccountName for owner failed "
                        "with %d\n", status);
                goto out;
            } else {
                LPSTR ssid = NULL;
                if (IsValidSid(*sid))
                    if (ConvertSidToStringSidA(*sid, &ssid))
                        printf("SID %s\n", ssid);
                    else
                        printf("ConvertSidToStringSidA failed with %d\n", GetLastError());
                else
                    printf("Invalid Sid\n");
                if (ssid) LocalFree(ssid);
            }
            status = 0;
            break;
        case ERROR_NONE_MAPPED:
            status = create_unknownsid(WinNullSid, sid, sid_len);
            break;
        }
    } else // This shouldn't happen
        status = ERROR_INTERNAL_ERROR;
out:
    return status;
}

static int handle_getacl(nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    getacl_upcall_args *args = &upcall->args.getacl;
    nfs41_open_state *state = args->state;
    nfs41_file_info info;
    bitmap4 attr_request;
    LPSTR domain = NULL;

    // need to cache owner/group information XX
    ZeroMemory(&info, sizeof(info));
    init_getattr_request(&attr_request);
    if (args->query & DACL_SECURITY_INFORMATION) {
        info.acl = calloc(1, sizeof(nfsacl41));
        if (info.acl == NULL) {
            status = GetLastError();
            goto out;
        }
        attr_request.arr[0] |= FATTR4_WORD0_ACL;
    }
    status = nfs41_getattr(state->session, &state->file, &attr_request, &info);
    if (status) {
        eprintf("nfs41_cached_getattr() failed with %d\n", status);
        goto out;
    }

    args->osid_len = args->gsid_len = 0;
    if (args->query & OWNER_SECURITY_INFORMATION) {
        // parse user@domain. currently ignoring domain part XX
        convert_nfs4name_2_user_domain((LPSTR)info.owner, &domain);
        dprintf(1, "handle_getacl: OWNER_SECURITY_INFORMATION: for user=%s domain=%s\n", 
                info.owner, domain?domain:"<null>");
        status = map_name_2_sid(&args->osid_len, &args->osid, (LPSTR)info.owner);
        if (status)
            goto out;
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        convert_nfs4name_2_user_domain((LPSTR)info.owner_group, &domain);
        dprintf(1, "handle_getacl: GROUP_SECURITY_INFORMATION: for %s domain=%s\n", 
                info.owner_group, domain?domain:"<null>");
        status = map_name_2_sid(&args->gsid_len, &args->gsid, (LPSTR)info.owner_group);
        if (status)
            goto out;
    }
    if (args->query & DACL_SECURITY_INFORMATION)
        dprintf(1, "handle_getacl: DACL_SECURITY_INFORMATION\n");
    if (args->query & SACL_SECURITY_INFORMATION)
        dprintf(1, "handle_getacl: SACL_SECURITY_INFORMATION\n");

out:
    if (args->query & DACL_SECURITY_INFORMATION) {
        nfsacl41_free(info.acl);
        free(info.acl);
    }
    return status;
}

static int marshall_acl(unsigned char **buffer, uint32_t *remaining, uint32_t sid_len, PSID sid)
{
    int status;
    status = safe_write(buffer, remaining, &sid_len, sizeof(sid_len));
    if (status) goto out;
    if (*remaining < sid_len)
        return ERROR_BUFFER_OVERFLOW;
    status = CopySid(sid_len, *buffer, sid);
    free(sid);
    if (!status) {
        status = GetLastError();
        dprintf(1, "marshall_acl: CopySid failed %d\n", status);
        goto out;
    } else {
        status = 0;
        *buffer += sid_len;
        *remaining -= sid_len;
    }
out:
    return status;
}

static int marshall_getacl(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    getacl_upcall_args *args = &upcall->args.getacl;

    if (args->query & OWNER_SECURITY_INFORMATION) {
        status = marshall_acl(&buffer, length, args->osid_len, args->osid);
        if (status) goto out;
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        status = marshall_acl(&buffer, length, args->gsid_len, args->gsid);
        if (status) goto out;
    }
out:
    return status;
}

const nfs41_upcall_op nfs41_op_getacl = {
    parse_getacl,
    handle_getacl,
    marshall_getacl
};

static int parse_setacl(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    setacl_upcall_args *args = &upcall->args.setacl;
    ULONG sec_desc_len;

    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    upcall_root_ref(upcall, args->root);
    status = safe_read(&buffer, &length, &args->state, sizeof(args->state));
    if (status) goto out;
    upcall_open_state_ref(upcall, args->state);
    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;
    status = safe_read(&buffer, &length, &sec_desc_len, sizeof(ULONG));
    if (status) goto out;
    args->sec_desc = malloc(sec_desc_len);
    if (args->sec_desc == NULL) {
        status = GetLastError();
        goto out;
    }
    status = safe_read(&buffer, &length, args->sec_desc, sec_desc_len);
    if (status) goto out_free;
    status = IsValidSecurityDescriptor(args->sec_desc);
    if (!status) {
        eprintf("parse_setacl: received invalid security descriptor\n");
        status = ERROR_INVALID_PARAMETER;
        goto out_free;
    } else status = 0;

    dprintf(1, "parsing NFS41_ACL_SET: info_class=%d root=0x%p open_state=0x%p "
        "sec_desc_len=%d\n", args->query, args->root, args->state, sec_desc_len);
out:
    return status;
out_free:
    free(args->sec_desc);
    goto out;
}

static int is_well_known_sid(PSID sid, char *who) 
{
    int status, i;
    for (i = 0; i < 78; i++) {
        status = IsWellKnownSid(sid, (WELL_KNOWN_SID_TYPE)i);
        if (!status) continue;
        else {
            dprintf(1, "WELL_KNOWN_SID_TYPE %d\n", i);
            switch((WELL_KNOWN_SID_TYPE)i) {
            case WinCreatorOwnerSid:
                memcpy(who, ACE4_OWNER, strlen(ACE4_OWNER)+1); return TRUE;
            case WinNullSid:
                memcpy(who, ACE4_NOBODY, strlen(ACE4_NOBODY)+1); return TRUE;
            case WinAnonymousSid:
                memcpy(who, ACE4_ANONYMOUS, strlen(ACE4_ANONYMOUS)+1); return TRUE;
            case WinWorldSid:
                memcpy(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1); return TRUE;
            case WinCreatorGroupSid:
            case WinBuiltinUsersSid:
                memcpy(who, ACE4_GROUP, strlen(ACE4_GROUP)+1); return TRUE;
            case WinAuthenticatedUserSid:
                memcpy(who, ACE4_AUTHENTICATED, strlen(ACE4_AUTHENTICATED)+1); return TRUE;
            case WinDialupSid:
                memcpy(who, ACE4_DIALUP, strlen(ACE4_DIALUP)+1); return TRUE;
            case WinNetworkSid:
                memcpy(who, ACE4_NETWORK, strlen(ACE4_NETWORK)+1); return TRUE;
            case WinBatchSid:
                memcpy(who, ACE4_BATCH, strlen(ACE4_BATCH)+1); return TRUE;
            case WinInteractiveSid:
                memcpy(who, ACE4_INTERACTIVE, strlen(ACE4_INTERACTIVE)+1); return TRUE;
            case WinNetworkServiceSid:
            case WinLocalServiceSid:
            case WinServiceSid:
                memcpy(who, ACE4_SERVICE, strlen(ACE4_SERVICE)+1); return TRUE;
            default: return FALSE;
            }
        }
    }
    return FALSE;
}

static void map_aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags)
{
    if (win_aceflags & OBJECT_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_FILE_INHERIT_ACE;
    if (win_aceflags & CONTAINER_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_FILE_INHERIT_ACE;
    if (win_aceflags & NO_PROPAGATE_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_NO_PROPAGATE_INHERIT_ACE;
    if (win_aceflags & INHERIT_ONLY_ACE)
        *nfs4_aceflags |= ACE4_INHERIT_ONLY_ACE;
    if (win_aceflags & INHERITED_ACE)
        *nfs4_aceflags |= ACE4_INHERITED_ACE;
    dprintf(1, "ACE FLAGS: %x nfs4 aceflags %x\n", win_aceflags, *nfs4_aceflags);
}

static void set_ace4_read_data(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    /* excluding STANDARD_RIGHTS_READ . winnt.h defines that as read_control which is acl/owner */
    /* excluding STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_ALL, SPECIFIC_RIGHTS_ALL,
     * FILE_GENERIC_READ, FILE_ALL_ACCESS */
    if (mask & FILE_READ_DATA || mask & GENERIC_READ || mask & GENERIC_ALL /*|| 
            (mask & FILE_GENERIC_READ || mask & FILE_ALL_ACCESS)*/)
        *nfs4_mask |= ACE4_READ_DATA;
}

static void set_ace4_list_directory(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    if (file_type == NF4DIR && (mask & FILE_TRAVERSE))
        *nfs4_mask |= ACE4_LIST_DIRECTORY;
}

static void set_ace4_writeappend_data(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    /* excluding STANDARD_RIGHTS_WRITE . winnt.h defines that as read_control which is acl/owner */
    /* excluding STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_ALL and SPECIFIC_RIGHTS_ALL,
     * FILE_GENERIC_WRITE, FILE_ALL_ACCESS NEED IT ???*/
    if (mask & FILE_WRITE_DATA || mask & GENERIC_WRITE
        || mask & GENERIC_ALL || mask & FILE_APPEND_DATA ||
            (mask & FILE_GENERIC_WRITE /*|| mask & FILE_ALL_ACCESS*/))
        *nfs4_mask |= ACE4_WRITE_DATA | ACE4_APPEND_DATA;
}

static void set_ace4_read_named_attributes(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_GENERIC_READ, FILE_ALL_ACCESS, GENERIC_ALL */
    if (mask & FILE_READ_EA /*||
            (mask & FILE_GENERIC_READ || mask & FILE_ALL_ACCESS || mask & GENERIC_ALL)*/)
        *nfs4_mask |= ACE4_READ_NAMED_ATTRS;
}

static void set_ace4_write_named_attributes(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_GENERIC_WRITE, FILE_ALL_ACCESS, GENERIC_ALL */
    if (mask & FILE_WRITE_EA /*||
            (mask & FILE_GENERIC_WRITE || mask & FILE_ALL_ACCESS || mask & GENERIC_ALL)*/)
        *nfs4_mask |= ACE4_WRITE_NAMED_ATTRS;
}

static void set_ace4_execute(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding STANDARD_RIGHTS_EXECUTE . winnt.h defines that as read_control which is acl/owner */
    /* excluding STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_ALL and SPECIFIC_RIGHTS_ALL,
     * FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS NEED IT ???*/
    if (mask & FILE_EXECUTE || mask & GENERIC_EXECUTE || mask & GENERIC_ALL ||
            (mask & FILE_GENERIC_EXECUTE || mask & FILE_ALL_ACCESS))
        *nfs4_mask |= ACE4_EXECUTE;
}

static void set_ace4_delete(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    /* excluding FILE_ALL_ACCESS, GENERIC_ALL */
    if (mask & FILE_DELETE_CHILD || mask & DELETE || 
            mask & STANDARD_RIGHTS_REQUIRED || mask & STANDARD_RIGHTS_ALL || 
            mask & SPECIFIC_RIGHTS_ALL)
        if (file_type == NF4DIR)
            *nfs4_mask |= ACE4_DELETE_CHILD;
        else
            *nfs4_mask |= ACE4_DELETE;
}

static void set_ace4_read_attributes(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_ALL and SPECIFIC_RIGHTS_ALL,
     * FILE_GENERIC_READ, FILE_ALL_ACCESS, GENERIC_ALL*/
    if (mask & FILE_READ_ATTRIBUTES)
        *nfs4_mask |= ACE4_READ_ATTRIBUTES;
}

static void set_ace4_write_attributes(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_ALL and SPECIFIC_RIGHTS_ALL,
     * FILE_GENERIC_WRITE, FILE_ALL_ACCESS, GENERIC_ALL*/
    if (mask & FILE_WRITE_ATTRIBUTES)
        *nfs4_mask |= ACE4_WRITE_ATTRIBUTES;
}

static void set_ace4_read_acl(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_ALL_ACCESS */
    if (mask & READ_CONTROL || mask & STANDARD_RIGHTS_READ || 
            mask & STANDARD_RIGHTS_ALL || mask & SPECIFIC_RIGHTS_ALL || 
            mask & STANDARD_RIGHTS_REQUIRED)
        *nfs4_mask |= ACE4_READ_ACL;
}

static void set_ace4_write_acl(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_ALL_ACCESS */
    if (mask & WRITE_DAC || mask & STANDARD_RIGHTS_WRITE || 
            mask & STANDARD_RIGHTS_ALL || mask & SPECIFIC_RIGHTS_ALL || 
            mask & STANDARD_RIGHTS_REQUIRED)
        *nfs4_mask |= ACE4_WRITE_ACL;
}

static void set_ace4_write_owner(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_ALL_ACCESS */
    if (mask & WRITE_OWNER || mask & STANDARD_RIGHTS_WRITE || 
            mask & STANDARD_RIGHTS_ALL || mask & SPECIFIC_RIGHTS_ALL || 
            mask & STANDARD_RIGHTS_REQUIRED)
        *nfs4_mask |= ACE4_WRITE_OWNER;
}

static void set_ace4_synchronize(ACCESS_MASK mask, uint32_t *nfs4_mask)
{
    /* excluding FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, 
     * FILE_ALL_ACCESS */
    if (mask & SYNCHRONIZE || mask & STANDARD_RIGHTS_ALL || 
            mask & SPECIFIC_RIGHTS_ALL)
        *nfs4_mask |= ACE4_SYNCHRONIZE;
}

static void map_acemask(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    /* 03/31/2011 NOT HANDLING LINKS */
    print_windows_access_mask(mask);

    set_ace4_read_data(mask, file_type, nfs4_mask);
    set_ace4_list_directory(mask, file_type, nfs4_mask);
    set_ace4_writeappend_data(mask, file_type, nfs4_mask);
    set_ace4_read_named_attributes(mask, nfs4_mask);
    set_ace4_write_named_attributes(mask, nfs4_mask);
    set_ace4_execute(mask, nfs4_mask);
    set_ace4_delete(mask, file_type, nfs4_mask);
    set_ace4_read_attributes(mask, nfs4_mask);
    set_ace4_write_attributes(mask, nfs4_mask);
    set_ace4_read_acl(mask, nfs4_mask);
    set_ace4_write_acl(mask, nfs4_mask);
    set_ace4_write_owner(mask, nfs4_mask);
    set_ace4_synchronize(mask, nfs4_mask);

    dprintf(1, "ACCESS MASK %d object type=%d nfs4 mask %x\n", 
            mask, file_type, *nfs4_mask);
    print_nfs_access_mask(*nfs4_mask);
}

static int map_who(PSID sid, char *who_out)
{
    int status = ERROR_INTERNAL_ERROR;
    DWORD size = 0, tmp_size = 0;
    SID_NAME_USE sid_type;
    LPSTR tmp_buf = NULL, who = NULL;

    status = IsValidSid(sid);
    if (!status) {
        eprintf("map_dacl_2_nfs4acl: invalid sid\n");
        status = GetLastError();
        goto out;
    }
    status = is_well_known_sid(sid, who_out);
    if (status) 
        return 0;
    status = LookupAccountSid(NULL, sid, who, &size, tmp_buf, 
        &tmp_size, &sid_type);
    if (!status) {
        status = GetLastError();
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            who = malloc(size);
            if (who == NULL) {
                status = GetLastError();
                goto out;
            }
            tmp_buf = malloc(tmp_size);
            if (tmp_buf == NULL) {
                status = GetLastError();
                free(who);
                goto out;
            }
            status = LookupAccountSid(NULL, sid, who, &size, tmp_buf, 
                &tmp_size, &sid_type);
            free(tmp_buf);
            if (!status) {
                status = GetLastError();
                eprintf("map_dacl_2_nfs4acl: failed to lookup account name "
                    "for sid %d\n", status);
                free(who);
                goto out;
            }
            memcpy(who_out, who, size);
            memcpy(who_out+size, "@citi.umich.edu", 15);

            free(who);
            status = 0;
        } else {
            eprintf("map_dacl_2_nfs4acl: failed to lookup account name for "
                "sid %d\n", status);
            goto out;
        }
    } else {
        dprintf(1, "this shouldn't happen\n");
        goto out;
    }
out:
    return status;
}
static int map_dacl_2_nfs4acl(PACL acl, nfsacl41 *nfs4_acl, int file_type)
{
    int status;
    if (acl == NULL) {
        dprintf(1, "this is a NULL dacl: all access to an object\n");
        nfs4_acl->count = 1;
        nfs4_acl->aces = calloc(1, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        memcpy(nfs4_acl->aces->who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1);
        nfs4_acl->aces->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
        nfs4_acl->aces->acemask = ACE4_ALL;
        nfs4_acl->aces->aceflag = 0;
    } else {
        int i;
        PACE_HEADER ace;
        PBYTE tmp_pointer;

        dprintf(1, "NON-NULL dacl with %d ACEs\n", acl->AceCount);
        print_hexbuf_no_asci(3, (unsigned char *)"ACL\n", (unsigned char *)acl, acl->AclSize);
        nfs4_acl->count = acl->AceCount;
        nfs4_acl->aces = calloc(nfs4_acl->count, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        for (i = 0; i < acl->AceCount; i++) {
            status = GetAce(acl, i, &ace);
            if (!status) {
                status = GetLastError();
                goto out;
            }
            tmp_pointer = (PBYTE)ace;
            print_hexbuf_no_asci(3, (unsigned char *)"ACE\n", (unsigned char *)ace, ace->AceSize); 
            dprintf(1, "ACE TYPE: %x\n", ace->AceType);
            if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
            else if (ace->AceType == ACCESS_DENIED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_DENIED_ACE_TYPE;
            else {
                eprintf("map_dacl_2_nfs4acl: unsupported ACE type %d\n",
                    ace->AceType);
                status = ERROR_NOT_SUPPORTED;
                goto out_free;
            }

            map_aceflags(ace->AceFlags, &nfs4_acl->aces[i].aceflag);            
            map_acemask(*(PACCESS_MASK)(ace + 1), file_type, &nfs4_acl->aces[i].acemask);

            tmp_pointer += sizeof(ACCESS_MASK) + sizeof(ACE_HEADER);
            status = map_who(tmp_pointer, nfs4_acl->aces[i].who);
            if (status)
                goto out_free;
        }
    }
    status = 0;
out:
    return status;
out_free:
    free(nfs4_acl->aces);
    goto out;
}

static int handle_setacl(nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    setacl_upcall_args *args = &upcall->args.setacl;
    nfs41_open_state *state = args->state;
    nfs41_file_info info;
    stateid_arg stateid;
    nfsacl41 nfs4_acl;

    ZeroMemory(&info, sizeof(info));

    if (args->query & OWNER_SECURITY_INFORMATION)
        dprintf(1, "handle_setacl: OWNER_SECURITY_INFORMATION\n");
    if (args->query & GROUP_SECURITY_INFORMATION)
        dprintf(1, "handle_setacl: GROUP_SECURITY_INFORMATION\n");
    if (args->query & DACL_SECURITY_INFORMATION) {
        BOOL dacl_present, dacl_default;
        PACL acl;
        dprintf(1, "handle_setacl: DACL_SECURITY_INFORMATION\n");
        status = GetSecurityDescriptorDacl(args->sec_desc, &dacl_present,
            &acl, &dacl_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorDacl failed with %d\n", status);
            goto out;
        }
        status = map_dacl_2_nfs4acl(acl, &nfs4_acl, state->type);
        if (status)
            goto out;
        else {
            info.acl = &nfs4_acl;
            info.attrmask.arr[0] |= FATTR4_WORD0_ACL;
            info.attrmask.count = 1;
        }
    }

    nfs41_lock_stateid_arg(state, &stateid);
    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        dprintf(1, "handle_setacl: nfs41_setattr() failed with error %s.\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
    }

    if (args->query & DACL_SECURITY_INFORMATION)
        free(nfs4_acl.aces);

out:
    free(args->sec_desc);
    return status;
}

const nfs41_upcall_op nfs41_op_setacl = {
    parse_setacl,
    handle_setacl,
};