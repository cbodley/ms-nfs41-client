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

#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <iphlpapi.h> /* for GetAdaptersAddresses() */
#include <wincrypt.h> /* for Crypt*() functions */
#include <winsock2.h> /* for hostent struct */

#include "tree.h"
#include "delegation.h"
#include "daemon_debug.h"
#include "nfs41_ops.h"


uint32_t nfs41_exchange_id_flags(
    IN bool_t is_data)
{
    uint32_t flags = EXCHGID4_FLAG_SUPP_MOVED_REFER;
    if (is_data)
        flags |= EXCHGID4_FLAG_USE_PNFS_DS;
    else
        flags |= EXCHGID4_FLAG_USE_NON_PNFS | EXCHGID4_FLAG_USE_PNFS_MDS;
    return flags;
}

static int pnfs_client_init(
    IN nfs41_client *client)
{
    enum pnfs_status pnfsstat;
    int status = NO_ERROR;

    /* initialize the pnfs layout and device lists for metadata clients */
    pnfsstat = pnfs_layout_list_create(&client->layouts);
    if (pnfsstat) {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto out;
    }
    pnfsstat = pnfs_file_device_list_create(&client->devices);
    if (pnfsstat) {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto out_err_layouts;
    }
out:
    return status;

out_err_layouts:
    pnfs_layout_list_free(client->layouts);
    client->layouts = NULL;
    goto out;
}

static int update_server(
    IN nfs41_client *client,
    IN const char *server_scope,
    IN const server_owner4 *owner)
{
    nfs41_server *server;
    int status;

    /* find a server matching the owner.major_id and scope */
    status = nfs41_server_find_or_create(owner->so_major_id,
        server_scope, nfs41_rpc_netaddr(client->rpc), &server);
    if (status)
        goto out;

    /* if the server is the same, we now have an extra reference. if
     * the servers are different, we still need to deref the old server.
     * so both cases can be treated the same */
    if (client->server)
        nfs41_server_deref(client->server);
    client->server = server;
out:
    return status;
}

static int update_exchangeid_res(
    IN nfs41_client *client,
    IN const nfs41_exchange_id_res *exchangeid)
{
    client->clnt_id = exchangeid->clientid;
    client->seq_id = exchangeid->sequenceid;
    client->roles = exchangeid->flags & EXCHGID4_FLAG_MASK_PNFS;
    return update_server(client, exchangeid->server_scope,
        &exchangeid->server_owner);
}

static void print_getaddrinfo(struct addrinfo *ptr)
{
    char ipstringbuffer[46];
    DWORD ipbufferlength = 46;

    dprintf(1, "getaddrinfo response flags: 0x%x\n", ptr->ai_flags);
    switch (ptr->ai_family) {
    case AF_UNSPEC: dprintf(1, "Family: Unspecified\n"); break;
    case AF_INET:
        dprintf(1, "Family: AF_INET IPv4 address %s\n",
            inet_ntoa(((struct sockaddr_in *)ptr->ai_addr)->sin_addr));
        break;
    case AF_INET6:
        if (WSAAddressToString((LPSOCKADDR)ptr->ai_addr, (DWORD)ptr->ai_addrlen, 
                NULL, ipstringbuffer, &ipbufferlength))
            dprintf(1, "WSAAddressToString failed with %u\n", WSAGetLastError());
        else    
            dprintf(1, "Family: AF_INET6 IPv6 address %s\n", ipstringbuffer);
        break;
    case AF_NETBIOS: dprintf(1, "AF_NETBIOS (NetBIOS)\n"); break;
    default: dprintf(1, "Other %ld\n", ptr->ai_family); break;
    }
    dprintf(1, "Canonical name: %s\n", ptr->ai_canonname);
}

static int getdomainname(char *domain)
{
    int status = 0;
    PFIXED_INFO net_info = NULL;
    DWORD size = 0;
    BOOLEAN flag = FALSE;

    status = GetNetworkParams(net_info, &size);
    if (status != ERROR_BUFFER_OVERFLOW) {
        eprintf("getdomainname: GetNetworkParams returned %d\n", status);
        goto out;
    }
    net_info = calloc(1, size);
    if (net_info == NULL) {
        status = GetLastError();
        goto out;
    }
    status = GetNetworkParams(net_info, &size);
    if (status) {
        eprintf("getdomainname: GetNetworkParams returned %d\n", status);
        goto out_free;
    }

    if (net_info->DomainName[0] == '\0') {
        struct addrinfo *result = NULL, *ptr = NULL, hints = { 0 };
        char hostname[NI_MAXHOST], servInfo[NI_MAXSERV];

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        status = getaddrinfo(net_info->HostName, NULL, &hints, &result);
        if (status) {
            status = WSAGetLastError();
            eprintf("getdomainname: getaddrinfo failed with %d\n", status);
            goto out_free;
        } 

        for (ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
            print_getaddrinfo(ptr);

            switch (ptr->ai_family) {
            case AF_INET6:
            case AF_INET:
                status = getnameinfo((struct sockaddr *)ptr->ai_addr,
                            (socklen_t)ptr->ai_addrlen, hostname, NI_MAXHOST, 
                            servInfo, NI_MAXSERV, NI_NAMEREQD);
                if (status)
                    dprintf(1, "getnameinfo failed %d\n", WSAGetLastError());
                else {
                    int i = 0;
                    size_t len = strlen(hostname);
                    char *p = hostname;
                    dprintf(1, "getdomainname: hostname %s %d\n", hostname, len);
                    for(i = 0; i < len; i++)
                        if (p[i] == '.')
                            break;
                    if (i == len)
                        break;
                    flag = TRUE;
                    memcpy(domain, &hostname[i+1], len-i);
                    dprintf(1, "getdomainname: domainname %s %d\n", domain, strlen(domain));
                    goto out_loop;
                }
                break;
            default:
                break;
            }
        }
out_loop:
        if (!flag) {
            status = ERROR_INTERNAL_ERROR;
            eprintf("getdomainname: unable to get a domain name. "
                "Set this machine's domain name:\n"
                "System > ComputerName > Change > More > mydomain\n");
        }
        freeaddrinfo(result);
    } else {
        dprintf(1, "domain name is %s\n", net_info->DomainName);
        memcpy(domain, net_info->DomainName, strlen(net_info->DomainName));
        domain[strlen(net_info->DomainName)] = '\0';
    }
out_free:
    free(net_info);
out:
    return status;
}

int nfs41_client_create(
    IN nfs41_rpc_clnt *rpc,
    IN const client_owner4 *owner,
    IN bool_t is_data,
    IN const nfs41_exchange_id_res *exchangeid,
    OUT nfs41_client **client_out)
{
    int status;
    nfs41_client *client;

    client = calloc(1, sizeof(nfs41_client));
    if (client == NULL) {
        status = GetLastError();
        goto out_err_rpc;
    }

    status = getdomainname(client->domain_name);
    if (status) {
        free(client);
        goto out_err_rpc;
    }

    memcpy(&client->owner, owner, sizeof(client_owner4));
    client->rpc = rpc;
    client->is_data = is_data;

    status = update_exchangeid_res(client, exchangeid);
    if (status)
        goto out_err_client;

    list_init(&client->state.opens);
    list_init(&client->state.delegations);
    InitializeCriticalSection(&client->state.lock);

    //initialize a lock used to protect access to client id and client id seq#
    InitializeSRWLock(&client->exid_lock);

    InitializeConditionVariable(&client->recovery.cond);
    InitializeCriticalSection(&client->recovery.lock);

    status = pnfs_client_init(client);
    if (status) {
        eprintf("pnfs_client_init() failed with %d\n", status);
        goto out_err_client;
    }
    *client_out = client;
out:
    return status;
out_err_client:
    nfs41_client_free(client); /* also calls nfs41_rpc_clnt_free() */
    goto out;
out_err_rpc:
    nfs41_rpc_clnt_free(rpc);
    goto out;
}

static void dprint_roles(
    IN int level,
    IN uint32_t roles)
{
    dprintf(level, "roles: %s%s%s\n",
        (roles & EXCHGID4_FLAG_USE_NON_PNFS) ? "USE_NON_PNFS " : "",
        (roles & EXCHGID4_FLAG_USE_PNFS_MDS) ? "USE_PNFS_MDS " : "",
        (roles & EXCHGID4_FLAG_USE_PNFS_DS) ? "USE_PNFS_DS" : "");
}

int nfs41_client_renew(
    IN nfs41_client *client)
{
    nfs41_exchange_id_res exchangeid = { 0 };
    int status;

    status = nfs41_exchange_id(client->rpc, &client->owner,
        nfs41_exchange_id_flags(client->is_data), &exchangeid);
    if (status) {
        eprintf("nfs41_exchange_id() failed with %d\n", status);
        status = ERROR_BAD_NET_RESP;
        goto out;
    }

    if (client->is_data) { /* require USE_PNFS_DS */
        if ((exchangeid.flags & EXCHGID4_FLAG_USE_PNFS_DS) == 0) {
            eprintf("client expected USE_PNFS_DS\n");
            status = ERROR_BAD_NET_RESP;
            goto out;
        }
    } else { /* require USE_NON_PNFS or USE_PNFS_MDS */
        if ((exchangeid.flags & EXCHGID4_FLAG_USE_NON_PNFS) == 0 &&
            (exchangeid.flags & EXCHGID4_FLAG_USE_PNFS_MDS) == 0) {
            eprintf("client expected USE_NON_PNFS OR USE_PNFS_MDS\n");
            status = ERROR_BAD_NET_RESP;
            goto out;
        }
    }

    dprint_roles(2, exchangeid.flags);

    AcquireSRWLockExclusive(&client->exid_lock);
    status = update_exchangeid_res(client, &exchangeid);
    ReleaseSRWLockExclusive(&client->exid_lock);
out:
    return status;
}

void nfs41_client_free(
    IN nfs41_client *client)
{
    dprintf(2, "nfs41_client_free(%llu)\n", client->clnt_id);
    nfs41_client_delegation_free(client);
    if (client->session) nfs41_session_free(client->session);
    nfs41_destroy_clientid(client->rpc, client->clnt_id);
    if (client->server) nfs41_server_deref(client->server);
    nfs41_rpc_clnt_free(client->rpc);
    if (client->layouts) pnfs_layout_list_free(client->layouts);
    if (client->devices) pnfs_file_device_list_free(client->devices);
    DeleteCriticalSection(&client->state.lock);
    DeleteCriticalSection(&client->recovery.lock);
    free(client);
}


/* client_owner generation
 * we choose to use MAC addresses to generate a client_owner value that
 * is unique to a machine and persists over restarts.  because the client
 * can have multiple network adapters/addresses, we take each adapter into
 * account.  the specification suggests that "for privacy reasons, it is
 * best to perform some one-way function," so we apply an md5 hash to the
 * sorted list of MAC addresses */

/* References:
 * RFC 5661: 2.4. Client Identifiers and Client Owners
 * http://tools.ietf.org/html/rfc5661#section-2.4
 *
 * MSDN: GetAdaptersAddresses Function
 * http://msdn.microsoft.com/en-us/library/aa365915%28VS.85%29.aspx
 *
 * MSDN: Example C Program: Creating an MD5 Hash from File Content
 * http://msdn.microsoft.com/en-us/library/aa382380%28VS.85%29.aspx */


/* use an rbtree to sort mac address entries */
struct mac_entry {
    RB_ENTRY(mac_entry)     rbnode;
    PBYTE                   address;
    ULONG                   length;
};

int mac_cmp(struct mac_entry *lhs, struct mac_entry *rhs)
{
    const int diff = rhs->length - lhs->length;
    return diff ? diff : strncmp((const char*)lhs->address,
        (const char*)rhs->address, lhs->length);
}
RB_HEAD(mac_tree, mac_entry);
RB_GENERATE(mac_tree, mac_entry, rbnode, mac_cmp)

static void mac_entry_insert(
    IN struct mac_tree *root,
    IN PBYTE address,
    IN ULONG length)
{
    struct mac_entry *entry;

    entry = calloc(1, sizeof(struct mac_entry));
    if (entry == NULL)
        return;

    entry->address = address;
    entry->length = length;

    if (RB_INSERT(mac_tree, root, entry))
        free(entry);
}

static int adapter_valid(
    IN const IP_ADAPTER_ADDRESSES *addr)
{
    /* ignore generic interfaces whose address is not unique */
    switch (addr->IfType) {
    case IF_TYPE_SOFTWARE_LOOPBACK:
    case IF_TYPE_TUNNEL:
        return 0;
    }
    /* must have an address */
    if (addr->PhysicalAddressLength == 0)
        return 0;
    /* must support ip */
    return addr->Ipv4Enabled || addr->Ipv6Enabled;
}

static DWORD hash_mac_addrs(
    IN HCRYPTHASH hash)
{
    PIP_ADAPTER_ADDRESSES addr, addrs = NULL;
    struct mac_tree rbtree = RB_INITIALIZER(rbtree);
    struct mac_entry *entry, *node;
    ULONG len;
    DWORD status;

    /* start with enough room for DEFAULT_MINIMUM_ENTITIES */
    len = DEFAULT_MINIMUM_ENTITIES * sizeof(IP_ADAPTER_ADDRESSES);

    do {
        PIP_ADAPTER_ADDRESSES tmp;
        /* reallocate the buffer until we can fit all of it */
        tmp = realloc(addrs, len);
        if (tmp == NULL) {
            status = GetLastError();
            goto out;
        }
        addrs = tmp;
        status = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME |
            GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST,
            NULL, addrs, &len);
    } while (status == ERROR_BUFFER_OVERFLOW);

    if (status) {
        eprintf("GetAdaptersAddresses() failed with %d\n", status);
        goto out;
    }

    /* get the mac address of each adapter */
    for (addr = addrs; addr; addr = addr->Next)
        if (adapter_valid(addr))
            mac_entry_insert(&rbtree, addr->PhysicalAddress,
                addr->PhysicalAddressLength);

    /* require at least one valid address */
    if (RB_EMPTY(&rbtree)) {
        status = ERROR_FILE_NOT_FOUND;
        eprintf("GetAdaptersAddresses() did not return "
            "any valid mac addresses, failing with %d.\n", status);
        goto out;
    }

    RB_FOREACH_SAFE(entry, mac_tree, &rbtree, node) {
        RB_REMOVE(mac_tree, &rbtree, entry);

        if (!CryptHashData(hash, entry->address, entry->length, 0)) {
            status = GetLastError();
            eprintf("CryptHashData() failed with %d\n", status);
            /* don't break here, we need to free the rest */
        }
        free(entry);
    }
out:
    free(addrs);
    return status;
}

int nfs41_client_owner(
    IN const char *name,
    IN uint32_t sec_flavor,
    OUT client_owner4 *owner)
{
    HCRYPTPROV context;
    HCRYPTHASH hash;
    PBYTE buffer;
    DWORD length;
    const ULONGLONG time_created = GetTickCount64();
    int status;
    char username[UNLEN + 1];
    DWORD len = UNLEN + 1;

    if (!GetUserNameA(username, &len)) {
        status = GetLastError();
        eprintf("GetUserName() failed with %d\n", status);
        goto out;
    }

    /* owner.verifier = "time created" */
    memcpy(owner->co_verifier, &time_created, sizeof(time_created));

    /* set up the md5 hash generator */
    if (!CryptAcquireContext(&context, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        status = GetLastError();
        eprintf("CryptAcquireContext() failed with %d\n", status);
        goto out;
    }
    if (!CryptCreateHash(context, CALG_MD5, 0, 0, &hash)) {
        status = GetLastError();
        eprintf("CryptCreateHash() failed with %d\n", status);
        goto out_context;
    }

    if (!CryptHashData(hash, (const BYTE*)&sec_flavor, (DWORD)sizeof(sec_flavor), 0)) {
        status = GetLastError();
        eprintf("CryptHashData() failed with %d\n", status);
        goto out_hash;
    }

    if (!CryptHashData(hash, (const BYTE*)username, (DWORD)strlen(username), 0)) {
        status = GetLastError();
        eprintf("CryptHashData() failed with %d\n", status);
        goto out_hash;
    }

    if (!CryptHashData(hash, (const BYTE*)name, (DWORD)strlen(name), 0)) {
        status = GetLastError();
        eprintf("CryptHashData() failed with %d\n", status);
        goto out_hash;
    }

    /* add the mac address from each applicable adapter to the hash */
    status = hash_mac_addrs(hash);
    if (status) {
        eprintf("hash_mac_addrs() failed with %d\n", status);
        goto out_hash;
    }

    /* extract the hash size (should always be 16 for md5) */
    buffer = (PBYTE)&owner->co_ownerid_len;
    length = (DWORD)sizeof(DWORD);
    if (!CryptGetHashParam(hash, HP_HASHSIZE, buffer, &length, 0)) {
        status = GetLastError();
        eprintf("CryptGetHashParam(size) failed with %d\n", status);
        goto out_hash;
    }
    /* extract the hash buffer */
    buffer = owner->co_ownerid;
    length = owner->co_ownerid_len;
    if (!CryptGetHashParam(hash, HP_HASHVAL, buffer, &length, 0)) {
        status = GetLastError();
        eprintf("CryptGetHashParam(val) failed with %d\n", status);
        goto out_hash;
    }

out_hash:
    CryptDestroyHash(hash);
out_context:
    CryptReleaseContext(context, 0);
out:
    return status;
}
