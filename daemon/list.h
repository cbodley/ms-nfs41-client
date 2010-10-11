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

#ifndef NFS41_LIST_H
#define NFS41_LIST_H


/* doubly-linked list */
struct list_entry {
    struct list_entry *prev;
    struct list_entry *next;
};


#define list_container(entry, type, field) \
    ((type*)((const char*)(entry) - (const char*)(&((type*)0)->field)))

#define list_for_each(entry, head) \
    for (entry = (head)->next; entry != (head); entry = entry->next)

#define list_for_each_tmp(entry, tmp, head) \
    for (entry = (head)->next, tmp = entry->next; entry != (head); \
        entry = tmp, tmp = entry->next)

#define list_for_each_reverse(entry, head) \
    for (entry = (head)->prev; entry != (head); entry = entry->prev)

#define list_for_each_reverse_tmp(entry, tmp, head) \
    for (entry = (head)->next, tmp = entry->next; entry != (head); \
        entry = tmp, tmp = entry->next)


static void list_init(
    struct list_entry *head)
{
    head->prev = head;
    head->next = head;
}

static int list_empty(
    struct list_entry *head)
{
    return head->next == head;
}

static void list_add(
    struct list_entry *entry,
    struct list_entry *prev,
    struct list_entry *next)
{
    /* assert(prev->next == next && next->prev == prev); */
    entry->prev = prev;
    entry->next = next;
    prev->next = entry;
    next->prev = entry;
}

static void list_add_head(
    struct list_entry *head,
    struct list_entry *entry)
{
    list_add(entry, head, head->next);
}

static void list_add_tail(
    struct list_entry *head,
    struct list_entry *entry)
{
    list_add(entry, head->prev, head);
}

static void list_remove(
    struct list_entry *entry)
{
    if (!list_empty(entry)) {
        entry->next->prev = entry->prev;
        entry->prev->next = entry->next;
        list_init(entry);
    }
}

typedef int (*list_compare_fn)(const struct list_entry*, const void*);

static struct list_entry* list_search(
    const struct list_entry *head,
    const void *value,
    list_compare_fn compare)
{
    struct list_entry *entry;
    list_for_each(entry, head)
        if (compare(entry, value) == 0)
            return entry;
    return NULL;
}

#endif /* !NFS41_LIST_H */
