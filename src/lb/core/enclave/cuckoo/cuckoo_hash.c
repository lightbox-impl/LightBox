/*
  Copyright (C) 2010 Tomash Brechko.  All rights reserved.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "cuckoo_hash.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//#include <assert.h>

#include "lb_type.h"
#include "../../enclave/include/lb_utils_t.h"

static inline
void
compute_hash(const void *key, size_t key_len,
             uint32_t *h1, uint32_t *h2)
{
  extern void hashlittle2(const void *key, size_t length,
                          uint32_t *pc, uint32_t *pb);

  /* Initial values are arbitrary.  */
  *h1 = 0x3ac5d673;
  *h2 = 0x6d7839d0;
  hashlittle2(key, key_len, h1, h2);
  if (*h1 != *h2)
    {
      return;
    }
  else
    {
      *h2 = ~*h2;
    }
}

//extern state_entry_t *_state_cache_rear;
//extern state_entry_t *_state_cache_front;
//extern state_entry_t *sb;
//extern lkup_entry_t *sb_lkup;

struct _cuckoo_hash_elem
{
  struct cuckoo_hash_item hash_item;
  uint32_t hash1;
  uint32_t hash2;
};


bool
cuckoo_hash_init(struct cuckoo_hash *hash, unsigned char power)
{
  if (power == 0)
    power = 1;

  hash->power = power;
  hash->bin_size = 4;
  hash->count = 0;
  hash->capacity = hash->bin_size << power;
  // allocate a little bite more
  //hash->capacity += hash->capacity*0.5;
  hash->max_depth = (size_t)hash->power << 5;
  //if (hash->max_depth > (size_t)hash->bin_size << hash->power)
	 // hash->max_depth = (size_t)hash->bin_size << hash->power;
  hash->table = calloc(hash->capacity, sizeof(*hash->table));
  if (! hash->table)
    return false;

  eprintf("lkup : %d %d\n", hash->bin_size << power, hash->capacity);
  return true;
}


void
cuckoo_hash_destroy(const struct cuckoo_hash *hash)
{

  free(hash->table);
}


static inline
struct _cuckoo_hash_elem *
bin_at(const struct cuckoo_hash *hash, uint32_t index)
{
  return (hash->table + index * hash->bin_size);
}


static inline
struct cuckoo_hash_item *
lookup(const struct cuckoo_hash *hash, const void *key, size_t key_len,
       uint32_t h1, uint32_t h2)
{
  uint32_t mask = (1U << hash->power) - 1;

  struct _cuckoo_hash_elem *elem, *end;

  elem = bin_at(hash, (h1 & mask));
  end = elem + hash->bin_size;
  while (elem != end)
    {
      if (elem->hash2 == h2 && elem->hash1 == h1
          //&& elem->hash_item.key_len == key_len
          && memcmp(&elem->hash_item.key, key, key_len) == 0)
        {
          return &elem->hash_item;
        }

      ++elem;
    }

  elem = bin_at(hash, (h2 & mask));
  end = elem + hash->bin_size;
  while (elem != end)
    {
      if (elem->hash2 == h1 && elem->hash1 == h2
          //&& elem->hash_item.key_len == key_len
          && memcmp(&elem->hash_item.key, key, key_len) == 0)
        {
          return &elem->hash_item;
        }

      ++elem;
    }

  return NULL;
}

uint32_t cache_lkup_h1, cache_lkup_h2;

struct cuckoo_hash_item *
cuckoo_hash_lookup(const struct cuckoo_hash *hash,
                   const void *key, size_t key_len)
{
  uint32_t h1, h2;
  compute_hash(key, key_len, &h1, &h2);

  /* To speed up dual lookup */
  cache_lkup_h1 = h1;
  cache_lkup_h2 = h2;

  return lookup(hash, key, key_len, h1, h2);
}

struct cuckoo_hash_item *
	cuckoo_hash_fast_lookup(const struct cuckoo_hash *hash,
		const void *key, size_t key_len)
{
	return lookup(hash, key, key_len, cache_lkup_h1, cache_lkup_h2);
}

void
cuckoo_hash_remove(struct cuckoo_hash *hash,
                   const struct cuckoo_hash_item *hash_item)
{
  if (hash_item)
    {
      struct _cuckoo_hash_elem *elem =
        ((struct _cuckoo_hash_elem *)
         ((char *) hash_item - offsetof(struct _cuckoo_hash_elem, hash_item)));
      elem->hash1 = elem->hash2 = 0;
      --hash->count;
    }
}

//static
//bool
//grow_table(struct cuckoo_hash *hash)
//{
//	printf("grow_table\n");
//
//  size_t size =
//    ((size_t) hash->bin_size << hash->power) * sizeof(*hash->table);
//  struct _cuckoo_hash_elem *table = realloc(hash->table, size * 2);
//  if (! table)
//    return false;
//
//  hash->table = table;
//  memcpy((char *) hash->table + size, hash->table, size);
//  ++hash->power;
//
//  return true;
//}
//
//
//static
//bool
//grow_bin_size(struct cuckoo_hash *hash)
//{
//	printf("grow_bin_size\n");
//
//  size_t size =
//    ((size_t) hash->bin_size << hash->power) * sizeof(*hash->table);
//  uint32_t bin_count = 1U << hash->power;
//  size_t add = bin_count * sizeof(*hash->table);
//  struct _cuckoo_hash_elem *table = realloc(hash->table, size + add);
//  if (! table)
//    return false;
//
//  hash->table = table;
//  for (uint32_t bin = bin_count - 1; bin > 0; --bin)
//    {
//      struct _cuckoo_hash_elem *old = bin_at(hash, bin);
//      struct _cuckoo_hash_elem *new = old + bin;
//      memmove(new, old, hash->bin_size * sizeof(*hash->table));
//      memset(new + hash->bin_size, 0, sizeof(*hash->table));
//    }
//  memset(hash->table + hash->bin_size, 0, sizeof(*hash->table));
//
//  ++hash->bin_size;
//
//  return true;
//}


//static
//bool
//undo_insert(struct cuckoo_hash *hash, struct _cuckoo_hash_elem *item,
//            size_t max_depth, uint32_t offset, int phase)
//{
//  uint32_t mask = (1U << hash->power) - 1;
//
//  for (size_t depth = 0; depth < max_depth * phase; ++depth)
//    {
//      if (offset-- == 0)
//        offset = hash->bin_size - 1;
//
//      uint32_t h2m = item->hash2 & mask;
//      struct _cuckoo_hash_elem *beg = bin_at(hash, h2m);
//
//      struct _cuckoo_hash_elem victim = beg[offset];
//
//      beg[offset].hash_item = item->hash_item;
//      beg[offset].hash1 = item->hash2;
//      beg[offset].hash2 = item->hash1;
//
//      uint32_t h1m = victim.hash1 & mask;
//      if (h1m != h2m)
//        {
//          assert(depth >= max_depth);
//
//          return true;
//        }
//
//      *item = victim;
//    }
//
//  //XPROBES_SITE(cuckoo_hash, insert_undo,
//  //             (const struct cuckoo_hash *,
//  //              int, size_t),
//  //             (hash, phase, max_depth));
//
//  return false;
//}


static inline
bool
insert(struct cuckoo_hash *hash, struct _cuckoo_hash_elem *item)
{
  //size_t max_depth = (size_t) hash->power << 5;
  //if (max_depth > (size_t) hash->bin_size << hash->power)
  //  max_depth = (size_t) hash->bin_size << hash->power;

  uint32_t offset = 0;
  //int phase = 0;
  //while (phase < 2)
  //  {
      uint32_t mask = (1U << hash->power) - 1;
	  uint32_t max_depth = hash->max_depth;
      for (size_t depth = 0; depth < max_depth; ++depth)
        {
          uint32_t h1m = item->hash1 & mask;
          struct _cuckoo_hash_elem *beg = bin_at(hash, h1m);
          struct _cuckoo_hash_elem *end = beg + hash->bin_size;

		  //int cnt = 0;
          for (struct _cuckoo_hash_elem *elem = beg; elem != end; ++elem)
            {
			  /*++cnt;
			  if (sb && (elem->hash_item.value == sb)) {
				  eprintf("bucket %p %p\n", &elem->hash_item, sb_lkup);
			  }*/

              if (elem->hash1 == elem->hash2 // the element is empty
				  || (elem->hash1 & mask) != h1m) // all elements in the bucket must have same hash
                {
                  *elem = *item;
				  // fix lkup link
				  ((state_entry_t *)elem->hash_item.value)->lkup = &elem->hash_item;

                  return true;
                }
            }

		  /*struct _cuckoo_hash_elem *_victim = &beg[offset];
		  if (sb && (_victim->hash_item.value == sb))
			  eprintf("_victim %p %p\n", &_victim->hash_item, sb_lkup);

		  struct _cuckoo_hash_elem __victim = *_victim;
		  if (sb && (__victim.hash_item.value == sb)) {
			  eprintf("__victim %p %p\n", &__victim.hash_item, sb_lkup);
			  eprintf("__victim eqyalk %d\n", memcmp(&__victim.hash_item, sb_lkup, sizeof(sb_lkup)));
			  eprintf("__victim key %d\n", memcmp(&__victim.hash_item.key, &sb_lkup->key, KEY_LEN));
		  }*/

          struct _cuckoo_hash_elem victim = beg[offset];

		  /*if (sb && (victim.hash_item.value == sb && &victim.hash_item != sb_lkup)) {
			  eprintf("%d %d check %p %p\n", cnt, offset, &victim.hash_item, sb_lkup);
		  }*/

		  /*if (sb == victim.hash_item.value) {
			  state_entry_t *sb_state = (state_entry_t *)sb_lkup->value;
			  eprintf("lkup %p %p %p %p %d %d\n", 
				  sb->lkup, &victim.hash_item, 
				  sb, victim.hash_item.value,
				  sb->idx, victim.hash_item.key.dst_ip);
			  eprintf("d90 %d %d\n", sb_state->idx, sb_lkup->key.dst_ip);
		  }*/

          beg[offset] = *item;
		  // fix lkup link
		  ((state_entry_t *)beg[offset].hash_item.value)->lkup = &beg[offset].hash_item;

          item->hash_item = victim.hash_item;
          item->hash1 = victim.hash2;
          item->hash2 = victim.hash1;

          if (++offset == hash->bin_size)
            offset = 0;

		  /*if (sb && (sb->idx != sb->lkup->key.dst_ip)) {
			  state_entry_t* aa = (state_entry_t*)victim.hash_item.value;
			  eprintf("%p %p %p %p %p\n", aa, sb, aa->lkup, sb->lkup, &victim.hash_item);
			  state_entry_t *item_state = (state_entry_t*)item->hash_item.value;
			  eprintf("item %d %d\n", item_state->idx, item->hash_item.key.dst_ip);
			  eprintf("victim %d %d\n", aa->idx, victim.hash_item.key.dst_ip);
			  eprintf("3dep sb %d %d front %d %d rear %d %d\n", sb->idx, sb->lkup->key.dst_ip,
				  _state_cache_front->idx, _state_cache_front->lkup->key.dst_ip,
				  _state_cache_rear->idx, _state_cache_rear->lkup->key.dst_ip);
			  abort();
		  }*/
        }
	  return false;
  //    ++phase;

  //    if (phase == 1)
  //      {
  //        if (grow_table(hash))
  //          /* continue */;
  //        else
  //          break;
  //      }
  //  }

  //if (grow_bin_size(hash))
  //  {
  //    uint32_t mask = (1U << hash->power) - 1;
  //    struct _cuckoo_hash_elem *last =
  //      bin_at(hash, (item->hash1 & mask) + 1) - 1;

  //    *last = *item;

  //    return true;
  //  }
  //else
  //  {
  //    return undo_insert(hash, item, max_depth, offset, phase);
  //  }
}

struct cuckoo_hash_item *
cuckoo_hash_insert(struct cuckoo_hash *hash,
                   const void *key, size_t key_len, void *value)
{
  uint32_t h1, h2;
  compute_hash(key, key_len, &h1, &h2);

  /* We always do this checking outside before calling this function */
  //struct cuckoo_hash_item *item = lookup(hash, key, key_len, h1, h2);
  //if (item)
  //  {
  //    //XPROBES_SITE(cuckoo_hash, insert_exists,
  //    //             (const struct cuckoo_hash *),
  //    //             (hash));

  //    return item;
  //  }

  /*struct _cuckoo_hash_elem elem = {
    .hash_item = { .key = key, .key_len = key_len, .value = value },
    .hash1 = h1,
    .hash2 = h2
  };*/
  struct _cuckoo_hash_elem elem;
  memcpy(&elem.hash_item.key, key, key_len);
  elem.hash_item.value = value;
  elem.hash1 = h1;
  elem.hash2 = h2;

  /*if (sb && (sb->idx != sb->lkup->key.dst_ip))
	  eprintf("c2 sb %d %d front %d %d rear %d %d\n", sb->idx, sb->lkup->key.dst_ip,
		  _state_cache_front->idx, _state_cache_front->lkup->key.dst_ip,
		  _state_cache_rear->idx, _state_cache_rear->lkup->key.dst_ip);*/

  if (insert(hash, &elem))
    {
      ++hash->count;

	  /*if (sb && (sb->idx != sb->lkup->key.dst_ip))
		  eprintf("c3 sb %d %d front %d %d rear %d %d\n", sb->idx, sb->lkup->key.dst_ip,
			  _state_cache_front->idx, _state_cache_front->lkup->key.dst_ip,
			  _state_cache_rear->idx, _state_cache_rear->lkup->key.dst_ip);*/
      //return NULL;
	  return lookup(hash, key, key_len, h1, h2);
    }
  else
    {
      //assert(elem.hash_item.key == key);
      //assert(elem.hash_item.key_len == key_len);
      //assert(elem.hash_item.value == value);
      //assert(elem.hash1 == h1);
      //assert(elem.hash2 == h2);

      return CUCKOO_HASH_FAILED;
    }
}


struct cuckoo_hash_item *
cuckoo_hash_next(const struct cuckoo_hash *hash,
                 const struct cuckoo_hash_item *hash_item)
{
  struct _cuckoo_hash_elem *elem =
    (hash_item != NULL
     ? ((struct _cuckoo_hash_elem *)
        ((char *) hash_item - offsetof(struct _cuckoo_hash_elem, hash_item))
        + 1)
     : hash->table);

  uint32_t bin_count = 1U << hash->power;
  struct _cuckoo_hash_elem *end = bin_at(hash, bin_count);
  uint32_t mask = bin_count - 1;
  while (elem != end)
    {
      if (elem->hash1 != elem->hash2)
        {
          /*
            Test that the element is valid, i.e., its hash1 matches
            the bin index it resides in.
          */
          struct _cuckoo_hash_elem *bin = bin_at(hash, (elem->hash1 & mask));
          if (bin <= elem && elem < bin + hash->bin_size)
            return &elem->hash_item;
        }

      ++elem;
    }

  return NULL;
}

double cuckoo_hash_load(const struct cuckoo_hash *hash)
{
	return hash->count*1.0 / hash->capacity;
}
