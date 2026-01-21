/* List handling
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef LIST_H
#define LIST_H

#include "atomic.h"
#include "bool.h"

#define member_offset(data_type, member_var)                                   \
	((size_t)&((data_type *)0)->member_var)

#define WRITE_ATOMIC(dst, val)                                                 \
	do {                                                                   \
		*(volatile typeof(dst) *)&(dst) = (val);                       \
	} while (0)

/**
 * @brief return data structure the member is part of
 *
 * Example:
 * struct foo *val = member_to_struct(&struct->list_entry, struct foo, list_entry);
 *
 * @param member the pointer to the member.
 * @param data_type the data type of the struct the member is part of.
 * @param member_var the member variable of the struct the member is
 *		     referenced with
 *
 */
#define member_to_struct(member, data_type, member_var)                        \
	(data_type *)((char *)(member) - (char *)&((data_type *)0)->member_var)

struct list_entry {
	struct list_entry *next;
	struct list_entry *prev;
};

/* Ensure that new list entry has its pointers initialized pointing to itself */
#define LIST_ENTRY_INIT(name)                                                  \
	name.next = &name;                                                     \
	name.prev = &name;

#define LIST_ENTRY(name) struct list_entry name = { &(name), &(name) }

static inline struct list_entry *list_read(struct list_entry *entry)
{
	struct list_entry *ret;

	mb();
	ret = entry;
	mb();

	return ret;
}

static inline void list_write(struct list_entry **dst, struct list_entry *val)
{
	mb();
	*dst = val;
	mb();
}

/**
 * @brief return the data structure the list is referencing
 * @param list_entry the pointer to the list entry.
 * @param data_type the data type of the struct the list entry is part of.
 * @param list_var the member variable of the struct the list is referenced with
 */
#define list_to_struct(list_entry, data_type, list_var)                        \
	(member_to_struct(list_entry, data_type, list_var))

/**
 * @brief iterate over each member of a list - do not delete the entry while
 *	  iterating
 * @param data_struct a data structure pointer of target type used as iterator
 * @param list_start the start point of the list
 * @param list_var the member variable in the struct data_struct the list is
 *		   referenced with
 *
 * Example:
 *
 * km_lkey_t *lkey;
 * unsigned int found_keys = 0;
 * list_for_each(lkey, &keyring->plaintext_key_list, key_list)
 *	found_keys++;
 */
#define list_for_each(data_struct, list_start, list_var)                       \
	for (data_struct = list_to_struct((list_start)->next,                  \
					  __typeof__(*data_struct), list_var); \
	     &data_struct->list_var != (list_start);                           \
	     data_struct = list_to_struct(data_struct->list_var.next,          \
					  __typeof__(*data_struct), list_var))

/**
 * @brief iterate over each member of a list guarded against removal of list
 *	  entry - this macro can be used to iterate over the list and remove
 *	  or free a list entry
 * @param data_struct a data structure pointer of target type used as iterator -
 *		      this is the target structure of the list member and can
 *		      be manipulated / freed as needed
 * @param tmp_struct another data structure pointer of target type used as
 *		     temporary storage - temporary storage guarding the removal
 *		     and should not further be used in the loop
 * @param list_start the start point of the list - i.e. the list head
 * @param list_var the member variable in the struct data_struct the list is
 *		   referenced with
 *
 * Example:
 *
 * km_lkey_t *lkey, *tmp;
 * list_for_each_guarded(lkey, tmp, &keyring->plaintext_key_list,
 *		  	 key_list)
 *	free(lkey);
 */
#define list_for_each_guarded(data_struct, tmp_var, list_start, list_var)      \
	for (data_struct = list_to_struct((list_start)->next,                  \
					  __typeof__(*data_struct), list_var), \
	    tmp_var = list_to_struct(data_struct->list_var.next,               \
				     __typeof__(*data_struct), list_var);      \
	     &data_struct->list_var != (list_start); data_struct = tmp_var,    \
	    tmp_var = list_to_struct(tmp_var->list_var.next,                   \
				     __typeof__(*tmp_var), list_var))

/**
 * @brief returns true if list is empty
 * @param start the start of list
 */
static inline bool list_is_empty(const struct list_entry *start)
{
	return list_read(start->next) == start;
}

/**
 * @brief returns true if list entry is the last entry of list
 * @param start the start of list
 * @param entry the list entry to test
 */
static inline bool list_is_last(const struct list_entry *start,
				const struct list_entry *entry)
{
	return list_read(entry->next) == start;
}

/**
 * @brief insert a new list entry or complete list between two given
 *	  entries with entries are known to exist
 * @param entry the list entry to add
 * @param prev the previous list entry of the existing list
 * @param next the next list entry of the existing list
 */
static inline void list_add_internal(struct list_entry *entry,
				     struct list_entry *prev,
				     struct list_entry *next)
{
	struct list_entry *entry_first = list_read(entry->next);
	struct list_entry *entry_last = list_read(entry->prev);

	list_write(&entry_first->prev, prev);
	list_write(&entry_last->next, next);

	list_write(&prev->next, entry_first);
	list_write(&next->prev, entry_last);
}

/**
 * @brief insert a new list entry or complete list at the end of the list when
 *	  pointing to the start of a list with \p start. Otherwise the
 *	  new list entry is added before the entry pointed to by \p start.
 * @param entry the list entry (or the start list entry of the new list) to add
 * @param start the start of list (or the list entry before which the new list
 *		or list entry shall be added)
 */
static inline void list_add_end(struct list_entry *entry,
				struct list_entry *start)
{
	list_add_internal(entry, start->prev, start);
}

/**
 * @brief insert a new list entry or list after the given list entry
 * @param entry the list entry (or the start list entry of the new list) to add
 * @param start the start of list (or the list entry after which the new list
 *		or list entry shall be added)
 */
static inline void list_add(struct list_entry *entry, struct list_entry *start)
{
	list_add_internal(entry, start, start->next);
}

/**
 * @brief delete list entry from the list with entries are known to exist
 * @param prev the previous list entry of the existing list
 * @param next the next list entry of the existing list
 */
static inline void list_del_internal(struct list_entry *prev,
				     struct list_entry *next)
{
	list_write(&next->prev, prev);
	list_write(&prev->next, next);
}

/**
 * @brief delete list entry from list
 * @param entry the list entry to delete
 */
static inline void list_del_entry(struct list_entry *entry)
{
	list_del_internal(entry->prev, entry->next);

	/*
	 * Ensure that the entry that is removed is still a fully-defined
	 * list.
	 */
	list_write(&entry->next, entry);
	list_write(&entry->prev, entry);
}

#define list_get_next(entry) list_read(entry->next)

#endif /* LIST_H */
