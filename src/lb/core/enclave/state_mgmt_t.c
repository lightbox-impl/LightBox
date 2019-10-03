#include "state_mgmt_t.h"

#include "cuckoo/cuckoo_hash.h"

#include "crypto_t.h"

#include "lb_edge_t.h"
#include "utils_t.h"

#include <string.h>
#include <stdlib.h>

//#define SGX_PAGING
// #define CONNECTION 0
// #define CAIDA 1
#define LKUP_DUAL

/* statistics of lb_state */
lb_state_stats_t lb_state_stats = { 0, 0, 0 };

#define LKUP_CAP_POW 19 // capacity = 2^(CAP_POW+2)
struct cuckoo_hash grand_lkup_table;

#define LKUP_CACHE_POW 12 // 2^(LKUP_CACHE_POW+2)
struct cuckoo_hash cache_lkup_table;

#define LKUP_STORE_POW 18 //
struct cuckoo_hash store_lkup_table;

#define CACHE_CAP (1<<LKUP_CACHE_POW) //4096
state_entry_t *_state_cache = 0;
state_entry_t *_state_cache_front = 0, *_state_cache_rear = 0; // LRU
int state_cache_used = 0; // for cold start
state_entry_t *_state_cache_free;

int state_cache_size()
{
	int rlt = 0;
	state_entry_t *it = _state_cache_front;
	while (it) {
		++rlt;
		it = it->next;
	}
	return rlt;
}

void add_to_free(state_entry_t *free)
{
	// free != 0, guaranteed by outside

	// drop from LRU link
	if (free->next)
		free->next->prev = free->prev;
	if (free->prev)
		free->prev->next = free->next;

	if (free == _state_cache_front)
		_state_cache_front = free->next;
	if (free == _state_cache_rear)
		_state_cache_rear = free->prev;

	//eprintf("Add %p\n", free);
	free->prev = 0;
	free->next = _state_cache_free;
	_state_cache_free = free;

	//eprintf("cache %d\n", state_cache_size());
}

int state_cache_free()
{
	return _state_cache_free != 0;
}

state_entry_t *state_cache_alloc()
{
	state_entry_t *free = _state_cache_free;
	_state_cache_free = _state_cache_free->next;
	return free;
}

void init_state_mgmt()
{
	// init hash table, etc.
#ifndef LKUP_DUAL
	cuckoo_hash_init(&grand_lkup_table, LKUP_CAP_POW);
#else
	cuckoo_hash_init(&cache_lkup_table, LKUP_CACHE_POW);
	cuckoo_hash_init(&store_lkup_table, LKUP_STORE_POW);
#endif

	_state_cache = calloc(CACHE_CAP, sizeof(state_entry_t));
	_state_cache_front = 0;
	_state_cache_rear = 0;
	state_cache_used = 0;

	_state_cache_free = 0;
	int i;
	for (i=0; i < CACHE_CAP; ++i) {
		add_to_free(&_state_cache[i]);
	}
	
	/*state_entry_t *free = _state_cache_free;
	eprintf("free: ");
	while (free) {
		eprintf("%p --> ", free);
		free = free->next;
	}
	eprintf("\n");

	eprintf("alloc: ");
	state_entry_t *alloc = 0;
	while (state_cache_free()) {
		alloc = state_cache_alloc();
		eprintf(" --> %p", alloc);
	}
	eprintf("\n");

	eprintf("add_back: ");
	add_to_free(alloc);
	while(state_cache_free()) {
		alloc = state_cache_alloc();
		eprintf(" --> %p", alloc);
	}
	eprintf("\n");

	abort();*/

    lb_state_stats.cache_hit = 0;
    lb_state_stats.store_hit = 0;
    lb_state_stats.miss = 0;
}

void deinit_state_mgmt()
{
	free(_state_cache);

#ifndef LKUP_DUAL
	cuckoo_hash_destroy(&grand_lkup_table);
#else
	cuckoo_hash_destroy(&cache_lkup_table);
	cuckoo_hash_destroy(&store_lkup_table);
#endif
}

//state_entry_t *state_cache_cold_alloc()
//{
//	if (state_cache_used < CACHE_CAP) {
//		//eprintf("alloc %d %p %p\n", state_cache_used, &_state_cache[state_cache_used], &_state_cache[state_cache_used+1]);
//		return &_state_cache[state_cache_used++];
//	}
//	else
//		return 0;
//}

//int state_cache_is_cold()
//{
//	return state_cache_used < CACHE_CAP;
//}

void _raise_to_front(state_entry_t *entry) {
	/* isolate entry from linked list */
	// case 1: already in front
	if (entry == _state_cache_front) {
		//eprintf("front %d %d\n", entry->idx, _state_cache_front->idx);
		return;
	}
	// case 2: rear
	else if (entry == _state_cache_rear) {
		_state_cache_rear = entry->prev;
		_state_cache_rear->next = 0;
	}
	// case 3: middle
	else {
		entry->prev->next = entry->next;
		entry->next->prev = entry->prev;
	}
	/* raise entry to the front in the last two cases */
	_state_cache_front->prev = entry;
	entry->next = _state_cache_front;
	entry->prev = 0;
	_state_cache_front = entry;

	//eprintf("after %d %d\n", entry->idx, _state_cache_front->idx);
	//if (entry->idx != entry->lkup->key.dst_ip)
	//	eprintf("raise cache %d entry %d %d\n", state_cache_size(), entry->idx, entry->lkup->key.dst_ip);
}

//static int push_cnt = 0;
void _push_to_front(state_entry_t *entry) {
	
	//push_cnt++;
	// TODO: why this case?
	if (unlikely(entry == _state_cache_front)) {
		eprintf("push_to_front strange case!\n");
		return;
	}
	// the very first one
	if (unlikely(_state_cache_front == 0 && _state_cache_rear == 0)) {
		entry->prev = 0;
		entry->next = 0;
		_state_cache_front = _state_cache_rear = entry;
		//eprintf("first front %d\n", entry->idx);
	}
	else {
		entry->next = _state_cache_front;
		entry->prev = 0;
		_state_cache_front->prev = entry;
		_state_cache_front = entry;
		//eprintf("front %d rear %d\n", _state_cache_front->idx, _state_cache_rear->idx);
	}
	
	//if (entry->idx != entry->lkup->key.dst_ip)
	//	eprintf("push cache %d entry %d %d\n", state_cache_size(), entry->idx, entry->lkup->key.dst_ip);
	//eprintf("front %p\n", _state_cache_front);
}

state_entry_t* _drop_from_rear() {
	/*if (_state_cache_rear->idx != _state_cache_rear->lkup->key.dst_ip) {
		eprintf("catch you inside %d %d\n",
			_state_cache_rear->idx, _state_cache_rear->lkup->key.dst_ip);
	}

	state_entry_t *prev = _state_cache_rear->prev;
	if (prev->idx != prev->lkup->key.dst_ip)
	{
		eprintf("catch you prev %d %d\n",
			prev->idx, prev->lkup->key.dst_ip);
	}

	static int drop_cnt = 0;
	drop_cnt++;*/
	state_entry_t *evicted;
	if (unlikely(_state_cache_front == _state_cache_rear)) {
		if (!_state_cache_front)
			eprintf("[*] No more to drop!\n");
		eprintf("[*] Dropping the very last entry in state_cache!\n");
		evicted = _state_cache_rear;
		_state_cache_front =_state_cache_rear = 0;
	}
	else {
		//if (_state_cache_rear->prev->idx != _state_cache_rear->prev->lkup->key.dst_ip) {
		//	eprintf("catch you before evict %d %d %d %d\n",
		//		_state_cache_rear->prev->idx, _state_cache_rear->prev->lkup->key.dst_ip,
		//		_state_cache_rear->prev->prev->idx, _state_cache_rear->prev->prev->lkup->key.dst_ip);
		//}

		evicted = _state_cache_rear;
		_state_cache_rear = _state_cache_rear->prev;
		_state_cache_rear->next = 0;

		//if (_state_cache_rear->idx != _state_cache_rear->lkup->key.dst_ip) {
		//	eprintf("catch you after evict %d %d\n",
		//		_state_cache_rear->idx, _state_cache_rear->lkup->key.dst_ip);
		//}
		//eprintf("[*] %p %p\n", state_cache_rear, evicted);
	}

	// eprintf("drop cache %d %d %d\n", state_cache_size(), evicted->idx, evicted->lkup->key.dst_ip);

	//if (evicted->idx != evicted->lkup->key.dst_ip) {
	//	/*int b = 0;
	//	int a = 1 / b;
	//	eprintf("%d %d\n", a, b);*/
	//	eprintf("drop %d %d %d\n", 
	//		state_cache_size(), evicted->idx, evicted->lkup->key.dst_ip);
	//}

	evicted->prev = 0;
	evicted->next = 0;
	return evicted;
}

void print_cache()
{
	state_entry_t *it = _state_cache_front;
	if (!it)
		return;
	/*eprintf("cache: %p", it);
	while (it->next) {
		eprintf(" --> %p", it->next);
		it = it->next;
	}*/
	eprintf("===============================\n");
	eprintf("cache: %d", it->idx);
	while (it != _state_cache_rear) {
		it = it->next;
		eprintf(" --> %d", it->idx);
	}
	eprintf("\n");
}

#ifndef LKUP_DUAL
flow_tracking_status flow_tracking(const fid_t *fid, state_entry_t **out_flow_state, time_t ts, int idx)
{
	static state_entry_t swap_buffer;

	// lookup index
	lkup_entry_t *lkup_entry = cuckoo_hash_lookup(&grand_lkup_table, fid, KEY_LEN);

	if (lkup_entry) {
		state_entry_t *tracked = (state_entry_t *)lkup_entry->value;

		// in cache
		if (tracked->within_enclave) {
			_raise_to_front(tracked);

			tracked->last_access_time = ts;

			*out_flow_state = (state_entry_t*)&tracked->state;

            ++lb_state_stats.cache_hit;
			return ft_cache_hit;
		}
		// in store
		else {
			// evict and buffer
			state_entry_t *victim = _drop_from_rear();
			auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac);
			victim->within_enclave = 0;
			lkup_entry_t *victim_lkup = victim->lkup;

			memcpy(&swap_buffer, victim, sizeof(state_entry_t));

			// copy (and decrypt) tracked entry to enclave
			state_entry_t *cache_free = victim;
			veri_dec(&tracked->state, FLOW_STATE_SIZE, &cache_free->state, &tracked->mac);
			cache_free->idx = idx;
			cache_free->within_enclave = 1;
			cache_free->lkup = lkup_entry;
			lkup_entry->value = cache_free;

			_push_to_front(cache_free);

			// copy evicted entry to store
			memcpy(tracked, &swap_buffer, sizeof(state_entry_t));
			tracked->lkup = victim_lkup;
			tracked->lkup->value = tracked;

			tracked->last_access_time = ts;

			*out_flow_state = (state_entry_t*)&cache_free->state;

            ++lb_state_stats.store_hit;
			return ft_store_hit;
		}
	}
	else {
		state_entry_t *fresh = 0;

		if(unlikely(state_cache_free())) {
			fresh = state_cache_alloc();
		}
		else {
			// evict the victim to store
			state_entry_t *victim = _drop_from_rear();

			lkup_entry_t *victim_lkup = victim->lkup;
			//eprintf("auth_enc %d\n", sgx_is_within_enclave(&victim->state, FLOW_STATE_SIZE));
			//eprintf("%p %p %p %d\n", victim, &victim->state, &victim->within_enclave, (void *)&victim->within_enclave- (void *)&victim->state);
			auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac);
			victim->within_enclave = 0;
			state_entry_t *store_new = 0;
			//eprintf("ocall_state_store_new\n");
#ifndef SGX_PAGING
			ocall_state_store_alloc((void **)&store_new);
#else
			store_new = malloc(sizeof(state_entry_t));
#endif
			if (!store_new) {
				eprintf("ocall_state_store_new\n");
				abort();
			}

			memcpy(store_new, victim, sizeof(state_entry_t));
			store_new->next = 0;
			store_new->prev = 0;
			// restore lookup relationship
			store_new->lkup = victim_lkup;
			store_new->lkup->value = store_new;

			// take over the slot occupied by victim
			fresh = victim;
		}

		lkup_entry_t *lkup = cuckoo_hash_insert(&grand_lkup_table, fid, KEY_LEN, fresh);

		if (lkup != CUCKOO_HASH_FAILED) {
			fresh->lkup = lkup;

			fresh->within_enclave = 1;

			fresh->idx = idx;

			_push_to_front(fresh);

			fresh->last_access_time = ts;

			*out_flow_state = (state_entry_t*)&fresh->state;
		}
		else {
			*out_flow_state = NULL;
			eprintf("cuckoo_hash_insert error here!\n");
			abort();
		}

        ++lb_state_stats.miss;
		return ft_miss;
	}
}
#else
// dual lookup
#if CONNECTION==0
flow_tracking_status flow_tracking(const fid_t *fid, state_entry_t **out_flow_state, time_t ts, int idx)
{
	static state_entry_t swap_buffer;

	lkup_entry_t *cache_lkup_entry = cuckoo_hash_lookup(&cache_lkup_table, fid, KEY_LEN);

	// cache hit
	if (cache_lkup_entry) {
		state_entry_t *tracked = (state_entry_t *)cache_lkup_entry->value;

		_raise_to_front(tracked);

		tracked->last_access_time = ts;

		// Test only
		tracked->is_client = 1;

		*out_flow_state = (state_entry_t*)&tracked->state;

        ++lb_state_stats.cache_hit;
		return ft_cache_hit;
	}
	else {
		// fast lookup without re-hashing
		lkup_entry_t *store_lkup_entry = cuckoo_hash_fast_lookup(&store_lkup_table, fid, KEY_LEN);

		// store hit
		if (store_lkup_entry) {
			// evict and buffer
			state_entry_t *victim = _drop_from_rear();
			auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac);
			//victim->within_enclave = 0;

			memcpy(&swap_buffer, victim, sizeof(state_entry_t));

			fid_t victim_fid = victim->lkup->key;

			cuckoo_hash_remove(&cache_lkup_table, victim->lkup);

			// copy (and decrypt) tracked entry to enclave
			state_entry_t *cache_free = victim;
			state_entry_t *tracked = (state_entry_t *)store_lkup_entry->value;

			veri_dec(&tracked->state, FLOW_STATE_SIZE, &cache_free->state, &tracked->mac);
			cache_free->idx = idx;
			//cache_free->within_enclave = 1;

			// remove from the tracked entry from store lkup table
			cuckoo_hash_remove(&store_lkup_table, store_lkup_entry);
			// and then add it to cache lkup table
			lkup_entry_t *cache_new_lkup = cuckoo_hash_insert(&cache_lkup_table, fid, KEY_LEN, cache_free);
			if (cache_new_lkup)
				cache_free->lkup = cache_new_lkup;
			else {
				eprintf("cache_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			_push_to_front(cache_free);

			// Test only
			cache_free->is_client = 1;

			cache_free->last_access_time = ts;

			// copy evicted entry to store
			memcpy(tracked, &swap_buffer, sizeof(state_entry_t));
			lkup_entry_t *store_new_lkup = cuckoo_hash_insert(&store_lkup_table, &victim_fid, KEY_LEN, tracked);
			if (store_new_lkup)
				tracked->lkup = store_new_lkup;
			else {
				eprintf("store_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			*out_flow_state = (state_entry_t*)&cache_free->state;

            ++lb_state_stats.store_hit;
			return ft_store_hit;
		}
		// store miss, hence new flow
		else {
			state_entry_t *fresh = 0;

			if (unlikely(state_cache_free())) {
				fresh = state_cache_alloc();
			}
			else {
				// evict the victim to store
				state_entry_t *victim = _drop_from_rear();

				fid_t victim_fid = victim->lkup->key;
				auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac);
				//victim->within_enclave = 0;
				state_entry_t *store_new = 0;
				//eprintf("ocall_state_store_new\n");
				ocall_state_store_alloc((void **)&store_new);
				if (!store_new) {
					eprintf("ocall_state_store_new\n");
					abort();
				}

				cuckoo_hash_remove(&cache_lkup_table, victim->lkup);

				//eprintf("memcpy\n");
				memcpy(store_new, victim, sizeof(state_entry_t));
				// restore lookup relationship
				lkup_entry_t *store_new_lkup = cuckoo_hash_insert(&store_lkup_table, &victim_fid, KEY_LEN, store_new);
				if (store_new_lkup)
					store_new->lkup = store_new_lkup;
				else {
					eprintf("store miss store_new_lkup cuckoo_hash_insert error\n");
					abort();
				}

				// take over the slot occupied by victim
				fresh = victim;
			}

			lkup_entry_t *cache_new_lkup = cuckoo_hash_insert(&cache_lkup_table, fid, KEY_LEN, fresh);

			if (cache_new_lkup != CUCKOO_HASH_FAILED) {
				//eprintf("succ\n");
				fresh->lkup = cache_new_lkup;

				//fresh->within_enclave = 1;

				fresh->idx = idx;

				_push_to_front(fresh);

				// Test only
				fresh->is_client = 1;

				fresh->last_access_time = ts;

				*out_flow_state = (state_entry_t*)&fresh->state;
			}
			else {
				*out_flow_state = NULL;
				eprintf("store miss cuckoo_hash_insert error\n");
				abort();
			}

            ++lb_state_stats.miss;
			return ft_miss;
		}
	}
}
flow_tracking_status flow_tracking_no_creation(const fid_t *fid, state_entry_t **out_flow_state, time_t ts, int idx)
{
	static state_entry_t swap_buffer;

	lkup_entry_t *cache_lkup_entry = cuckoo_hash_lookup(&cache_lkup_table, fid, KEY_LEN);

	// cache hit
	if (cache_lkup_entry) {
		state_entry_t *tracked = (state_entry_t *)cache_lkup_entry->value;

		_raise_to_front(tracked);

		tracked->last_access_time = ts;

		// Test only
		tracked->is_client = 1;

		*out_flow_state = (state_entry_t*)&tracked->state;

        ++lb_state_stats.cache_hit;
		return ft_cache_hit;
	}
	else {
		// fast lookup without re-hashing
		lkup_entry_t *store_lkup_entry = cuckoo_hash_fast_lookup(&store_lkup_table, fid, KEY_LEN);

		// store hit
		if (store_lkup_entry) {
			// evict and buffer
			state_entry_t *victim = _drop_from_rear();
			auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac);
			//victim->within_enclave = 0;

			memcpy(&swap_buffer, victim, sizeof(state_entry_t));

			fid_t victim_fid = victim->lkup->key;

			cuckoo_hash_remove(&cache_lkup_table, victim->lkup);

			// copy (and decrypt) tracked entry to enclave
			state_entry_t *cache_free = victim;
			state_entry_t *tracked = (state_entry_t *)store_lkup_entry->value;

			veri_dec(&tracked->state, FLOW_STATE_SIZE, &cache_free->state, &tracked->mac);
			cache_free->idx = idx;
			//cache_free->within_enclave = 1;

			// remove from the tracked entry from store lkup table
			cuckoo_hash_remove(&store_lkup_table, store_lkup_entry);
			// and then add it to cache lkup table
			lkup_entry_t *cache_new_lkup = cuckoo_hash_insert(&cache_lkup_table, fid, KEY_LEN, cache_free);
			if (cache_new_lkup)
				cache_free->lkup = cache_new_lkup;
			else {
				eprintf("cache_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			_push_to_front(cache_free);

			// Test only
			cache_free->is_client = 1;

			cache_free->last_access_time = ts;

			// copy evicted entry to store
			memcpy(tracked, &swap_buffer, sizeof(state_entry_t));
			lkup_entry_t *store_new_lkup = cuckoo_hash_insert(&store_lkup_table, &victim_fid, KEY_LEN, tracked);
			if (store_new_lkup)
				tracked->lkup = store_new_lkup;
			else {
				eprintf("store_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			*out_flow_state = (state_entry_t*)&cache_free->state;

            ++lb_state_stats.store_hit;
			return ft_store_hit;
		}
		// store miss, we refrain from creating new flow, in case the middlebox will do so
		else {
			return ft_miss;
		}
	}
}
#else
// two-way lkup for CAIDA trace contaning both client and server data
flow_tracking_status flow_tracking(const fid_t *fid, state_entry_t **out_state, time_t ts, int idx)
{
	static state_entry_t swap_buffer;

	static fid_t alt_fid;
	alt_fid.dst_ip = fid->src_ip;
	alt_fid.dst_port = fid->src_port;
	alt_fid.src_ip = fid->dst_ip;
	alt_fid.src_port = fid->dst_port;
	alt_fid.proto = fid->proto;
	lkup_entry_t *cache_lkup_entry_c = cuckoo_hash_lookup(&cache_lkup_table, fid, KEY_LEN);
	lkup_entry_t *cache_lkup_entry_s = cuckoo_hash_lookup(&cache_lkup_table, &alt_fid, KEY_LEN);

	// cache hit
	if (cache_lkup_entry_c || cache_lkup_entry_s) {
		state_entry_t *tracked;
		if (cache_lkup_entry_c) {
			tracked = (state_entry_t *)cache_lkup_entry_c->value;
			tracked->is_client = 1;
		}
		else {
			tracked = (state_entry_t *)cache_lkup_entry_s->value;
			tracked->is_client = 0;
		}

		_raise_to_front(tracked);

		tracked->last_access_time = ts;

		*out_state = tracked;

        ++lb_state_stats.cache_hit;
		return ft_cache_hit;
	}
	else {
		// do not apply fast lookup trick for this case
		lkup_entry_t *store_lkup_entry_c = cuckoo_hash_lookup(&store_lkup_table, fid, KEY_LEN);
		lkup_entry_t *store_lkup_entry_s = cuckoo_hash_lookup(&store_lkup_table, &alt_fid, KEY_LEN);

		// store hit
		if (store_lkup_entry_c || store_lkup_entry_s) {
			// evict and buffer
			state_entry_t *victim = _drop_from_rear();
			if (!auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac)) {
				eprintf("store hit!\n");
			}
			//victim->within_enclave = 0;

			memcpy(&swap_buffer, victim, sizeof(state_entry_t));

			fid_t victim_fid = victim->lkup->key;

			cuckoo_hash_remove(&cache_lkup_table, victim->lkup);

			// copy (and decrypt) tracked entry to enclave
			state_entry_t *cache_free = victim;
			state_entry_t *tracked;
			if (store_lkup_entry_c) {
				tracked = (state_entry_t *)store_lkup_entry_c->value;
			}
			else {
				tracked = (state_entry_t *)store_lkup_entry_s->value;
			}
			
			veri_dec(&tracked->state, FLOW_STATE_SIZE, &cache_free->state, &tracked->mac);
			if (store_lkup_entry_c) {
				cache_free->is_client = 1;
			}
			else {
				cache_free->is_client = 0;
			}
			cache_free->idx = idx;
			//cache_free->within_enclave = 1;

			// remove the tracked entry from store lkup table
			if (store_lkup_entry_c)
				cuckoo_hash_remove(&store_lkup_table, store_lkup_entry_c);
			else
				cuckoo_hash_remove(&store_lkup_table, store_lkup_entry_s);

			// and then add it to cache lkup table
			lkup_entry_t *cache_new_lkup = cuckoo_hash_insert(&cache_lkup_table, fid, KEY_LEN, cache_free);
			if (cache_new_lkup)
				cache_free->lkup = cache_new_lkup;
			else {
				eprintf("cache_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			_push_to_front(cache_free);

			cache_free->last_access_time = ts;

			// copy evicted entry to store
			memcpy(tracked, &swap_buffer, sizeof(state_entry_t));
			lkup_entry_t *store_new_lkup = cuckoo_hash_insert(&store_lkup_table, &victim_fid, KEY_LEN, tracked);
			if (store_new_lkup) {
				tracked->lkup = store_new_lkup;
			}
			else {
				eprintf("store_new_lkup cuckoo_hash_insert error\n");
				abort();
			}

			*out_state = cache_free;

            ++lb_state_stats.store_hit;
			return ft_store_hit;
		}
		// store miss, hence new flow
		else {
			state_entry_t *fresh = 0;

			if (unlikely(state_cache_free())) {
				fresh = state_cache_alloc();
			}
			else {
				// evict the victim to store
				state_entry_t *victim = _drop_from_rear();
				fid_t victim_fid = victim->lkup->key;
				if (!auth_enc(&victim->state, FLOW_STATE_SIZE, &victim->state, &victim->mac)) {
					eprintf("store miss!");
				}
				//victim->within_enclave = 0;
				state_entry_t *store_new = 0;
				//eprintf("ocall_state_store_new\n");
				ocall_state_store_alloc((void **)&store_new);
				if (!store_new) {
					eprintf("ocall_state_store_new\n");
					abort();
				}

				cuckoo_hash_remove(&cache_lkup_table, victim->lkup);

				//eprintf("memcpy\n");
				memcpy(store_new, victim, sizeof(state_entry_t));
				// restore lookup relationship
				lkup_entry_t *store_new_lkup = cuckoo_hash_insert(&store_lkup_table, &victim_fid, KEY_LEN, store_new);
				if (store_new_lkup) {
					store_new->lkup = store_new_lkup;
				}
				else {
					eprintf("store miss store_new_lkup cuckoo_hash_insert error\n");
					abort();
				}

				if (store_new->last_access_time < 0) {
					eprintf("store_new %d %d\n", store_new->idx, store_new->last_access_time);
					abort();
				}

				// take over the slot occupied by victim
				fresh = victim;
			}

			lkup_entry_t *cache_new_lkup = cuckoo_hash_insert(&cache_lkup_table, fid, KEY_LEN, fresh);

			if (cache_new_lkup != CUCKOO_HASH_FAILED) {
				//eprintf("succ\n");
				fresh->lkup = cache_new_lkup;

				//fresh->within_enclave = 1;

				fresh->idx = idx;

				_push_to_front(fresh);

				fresh->last_access_time = ts;

				*out_state = fresh;

				// client always initiates the request
				fresh->is_client = 1;
			}
			else {
				*out_state = NULL;
				eprintf("store miss cache_lkup cuckoo_hash_insert error\n");
				abort();
			}

            ++lb_state_stats.miss;
			return ft_miss;
		}
	}
}
#endif
#endif

#ifndef LKUP_DUAL
flow_tracking_status stop_tracking(const fid_t *fid)
{
	lkup_entry_t *lkup_entry = cuckoo_hash_lookup(&grand_lkup_table, fid, KEY_LEN);

	if (lkup_entry) {
		state_entry_t *tracked = (state_entry_t *)lkup_entry->value;
		cuckoo_hash_remove(&grand_lkup_table, lkup_entry);

		if (tracked->within_enclave) {
			//int cache_size = state_cache_size();
			add_to_free(tracked);
			/*if ((cache_size - 1) != state_cache_size())
				eprintf("wrong cache %d %d\n", cache_size, state_cache_size());*/
			return ft_stop_cache;
		}
		else {
			ocall_state_store_free(tracked);
			return ft_stop_store;
		}
	}
	else {
		return ft_stop_inexist;
	}
}
#else
flow_tracking_status stop_tracking(const fid_t *fid)
{
	lkup_entry_t *cache_lkup_entry = cuckoo_hash_lookup(&cache_lkup_table, fid, KEY_LEN);

	// in cache
	if (cache_lkup_entry) {
		state_entry_t *tracked = (state_entry_t *)cache_lkup_entry->value;

		add_to_free(tracked);
		cuckoo_hash_remove(&cache_lkup_table, cache_lkup_entry);
		return ft_stop_cache;
	}
	// in store
	else {
		lkup_entry_t *store_lkup_entry = cuckoo_hash_lookup(&store_lkup_table, fid, KEY_LEN);

		if (store_lkup_entry) {
			
			state_entry_t *tracked = (state_entry_t *)store_lkup_entry->value;
			ocall_state_store_free(tracked);
			cuckoo_hash_remove(&store_lkup_table, store_lkup_entry);
			return ft_stop_store;
		}
		else {
            eprintf("%s : flow inexist!\n", __func__);
            abort();
			return ft_stop_inexist;
		}
	}
}

// don't use or refer to this legacy code! Use stop_tracking instead
void check_expiration(time_t crt_time, int timeout)
{
	struct cuckoo_hash_item *it;
	for (cuckoo_hash_each(it, &store_lkup_table))
	{
		state_entry_t *state = it->value;
		time_t state_time = state->last_access_time;
		// Force to_end for testing
		//state->to_end = 1;
		if (state->to_end && (crt_time - state_time) > timeout) {
			// safe to remove while iterating
			cuckoo_hash_remove(&store_lkup_table, state->lkup);
			ocall_state_store_free(state);
		}
	}
}
#endif

// try generating "size" number of "idx", of which "miss_rate" 
// of them fall outside the range of [0, (1-miss_rate)*CACHE_CAP]
void gen_trace(unsigned int idx[], int num_idx, unsigned int max, double hitrate)
{
	int i = 0;
	unsigned int r = 0;
	// in cache
	for (; i < num_idx; ++i) {
		ocall_random(&r);
		idx[i] = r % CACHE_CAP;
	}
	// out cache
	int num_miss = num_idx * (1.0 - hitrate);
	for (i = 0; i < num_miss; ++i) {
		ocall_random(&r);
		if(hitrate == 0)
			idx[i] = CACHE_CAP + r % (max - CACHE_CAP);
		else
			idx[r % num_idx] = CACHE_CAP + r % (max - CACHE_CAP);
	}
}

void test_insertion(const fid_t fid_list[], int num_fid)
{
	state_entry_t *state = 0;
	flow_tracking_status status = ft_init;
	int cached = 0, stored = 0, missed = 0;

	long long  start_s, start_ns, end_s, end_ns;
	time_t ts = 0;

	/* Initial insertion */
	int i;
	ocall_get_time(&start_s, &start_ns);
	for (i = 0; i < num_fid; ++i) {
		status = flow_tracking(&fid_list[i], &state, i, i);
		switch (status) {
		case ft_cache_hit:
			++cached;
			break;
		case ft_store_hit:
			++stored;
			break;
		case ft_miss:
			++missed;
			break;
		default:
			eprintf("invalid flow tracking status!\n", status);
			abort();
		}
	}
	ocall_get_time(&end_s, &end_ns);

	eprintf("==========Test Insertion==========\n");
#ifndef LKUP_DUAL
	eprintf("All %d Cached %d New %d Load %f Avg Time %fus\n",
		grand_lkup_table.count, state_cache_size(), missed,
		grand_lkup_table.count*1.0 / grand_lkup_table.capacity,
		TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / num_fid);
#else
	eprintf("Insertion status : cached %d stored %d missed %d\n", cached, stored, missed);
	eprintf("Cache : size %d load %f\n", cache_lkup_table.count, cuckoo_hash_load(&cache_lkup_table));
	eprintf("Store : size %d load %f\n", store_lkup_table.count, cuckoo_hash_load(&store_lkup_table));
	eprintf("Avg time : %fus\n", TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / num_fid);
#endif
	eprintf("==================================\n\n");
}

void test_random_lkup(const fid_t fid_list[], int num_fid, 
					  int test_size, double hitrate)
{
	// test results
	int start_s, start_ns, end_s, end_ns;
	int cached = 0, stored = 0, missed = 0;
	
	// function arguments
	state_entry_t *state = 0;
	flow_tracking_status status = ft_init;

	// prepare test data
	unsigned int *idx = calloc(test_size, sizeof(unsigned int));
	gen_trace(idx, test_size, num_fid, hitrate);

	// cache warm up
	int i;
	for (i = 0; i < CACHE_CAP; ++i) {
		status = flow_tracking(&fid_list[i], &state, i, i);
	}

	// start test
	ocall_get_time(&start_s, &start_ns);
	for (i = 0; i < test_size; ++i) {
		status = flow_tracking(&fid_list[idx[i]], &state, i, idx[i]);
		switch (status) {
		case ft_cache_hit:
			++cached;
			break;
		case ft_store_hit:
			++stored;
			break;
		case ft_miss:
			++missed;
			break;
		default:
			;
			/*eprintf("invalid flow tracking status!\n", status);
			abort();*/
		}
	}
	ocall_get_time(&end_s, &end_ns);

	free(idx);

	// print out results
	eprintf("==========Test Random Lookup==========\n");
#ifndef LKUP_DUAL
	eprintf("Cache Hit %f Store Hit %f Avg Time %fus\n",
		cached*1.0 / test_size, stored*1.0 / test_size,
		TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / test_size);
#else
	eprintf("Lookup status : cached %d stored %d missed %d hitrate %f\n", cached, stored, missed, cached*1.0/test_size);
	eprintf("Cache : size %d load %f\n", cache_lkup_table.count, cuckoo_hash_load(&cache_lkup_table));
	eprintf("Store : size %d load %f\n", store_lkup_table.count, cuckoo_hash_load(&store_lkup_table));
	eprintf("Avg time : %fus\n", TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / test_size);
#endif
	eprintf("======================================\n\n");
}

void test_deletion(const fid_t fid_list[], int num_fid, int test_size)
{
	flow_tracking_status status = ft_init;
	int stop_in_cache = 0, stop_in_store = 0, stop_inexist = 0;

	int start_s, start_ns, end_s, end_ns;

	int i;

	// prepare test data
	unsigned int *rand_idx = calloc(test_size, sizeof(unsigned int));
	for (i = 0; i < test_size; ++i) {
		draw_rand(&rand_idx[i], sizeof(unsigned int));
		rand_idx[i] %= num_fid;
		//rand_idx[i] = num_fid - 1 - i;
		//eprintf("%d \n", rand_idx[i]);
	}

	ocall_get_time(&start_s, &start_ns);
	for (i = 0; i < test_size; ++i) {
		status = stop_tracking(&fid_list[rand_idx[i]]);
		switch (status) {
		case ft_stop_cache:
			++stop_in_cache;
			break;
		case ft_stop_store:
			++stop_in_store;
			break;
		case ft_stop_inexist:
			++stop_inexist;
			break;
		default:
			;
			/*eprintf("invalid flow tracking status!\n", status);
			abort();*/
		}
	}
	ocall_get_time(&end_s, &end_ns);

	eprintf("==========Test Deletion==========\n");
#ifndef LKUP_DUAL
	eprintf("All %d Cached %d Load %f Avg Time %fus %d %d %d\n",
	grand_lkup_table.count, state_cache_size(),
	grand_lkup_table.count*1.0 / grand_lkup_table.capacity,
	TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / test_size,
		stop_in_cache, stop_in_store, stop_inexist);
#else
	eprintf("Deletion status : in cache %d in store %d inexist %d\n", stop_in_cache, stop_in_store, stop_inexist);
	eprintf("Cache : size %d load %f\n", cache_lkup_table.count, cuckoo_hash_load(&cache_lkup_table));
	eprintf("Store : size %d load %f\n", store_lkup_table.count, cuckoo_hash_load(&store_lkup_table));
	eprintf("Avg time : %fus\n", TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / num_fid);
#endif
	eprintf("=================================\n\n");
}

//void test_expiration(const fid_t fid_list[], int num_fid)
//{
//	flow_tracking_status status = ft_init;
//
//	int start_s, start_ns, end_s, end_ns;
//
//	int i;
//
//	ocall_get_time(&start_s, &start_ns);
//	
//	check_expiration(num_fid, num_fid/2);
//
//	ocall_get_time(&end_s, &end_ns);
//
//	eprintf("==========Test Expiration Checking==========\n");
//#ifndef LKUP_DUAL
//	eprintf("All %d Cached %d Load %f Avg Time %fus %d %d %d\n",
//		grand_lkup_table.count, state_cache_size(),
//		grand_lkup_table.count*1.0 / grand_lkup_table.capacity,
//		TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / (num_fid / 2));
//#else
//	eprintf("Cache : size %d load %f\n", cache_lkup_table.count, cuckoo_hash_load(&cache_lkup_table));
//	eprintf("Store : size %d load %f\n", store_lkup_table.count, cuckoo_hash_load(&store_lkup_table));
//	eprintf("Time : %fus\n", TIME_ELAPSED_IN_US(start_s, start_ns, end_s, end_ns) / num_fid);
//#endif
//	eprintf("=================================\n\n");
//}

void test_timing()
{
	long long  start_s, start_ns, end_s, end_ns;
	int tri = 1000000;
	int i;
	double prec = 0;
	for (i = 0; i < tri; ++i) {
		ocall_get_time(&start_s, &start_ns);
		ocall_get_time(&end_s, &end_ns);
		//eprintf("timing precision %d ns\n", TIME_ELAPSED_IN_NS(start_s, start_ns, end_s, end_ns));
		prec += TIME_ELAPSED_IN_NS(start_s, start_ns, end_s, end_ns);
	}
	eprintf("avg %f\n", prec / tri);
}

void print_test_conf()
{
	eprintf("=======================================\n");
	eprintf("Overall test configurations:\n");
	eprintf("\tState entry size %d\n", sizeof(state_entry_t));
	eprintf("\tState cache size %d\n", CACHE_CAP);
#ifndef LKUP_DUAL
	eprintf("\tLkup table size 2^%d\n", (LKUP_CAP_POW+2));
#else
	eprintf("\tCache lkup table size 2^%d\n", (LKUP_CACHE_POW + 2));
	eprintf("\tStore lkup table size 2^%d\n", (LKUP_STORE_POW + 2));
#endif
	eprintf("=======================================\n\n");
}

void ecall_state_test()
{
	print_test_conf();

	/* Prepare fid pool for test */
#define NUM_FID 1500000
	fid_t fid_list[NUM_FID];
	int i = 0;
	for (; i < NUM_FID; ++i) {
		//draw_rand(&fid_list[i], sizeof(fid_t));
		/*if (i < 750000)
			fid_list[i].dst_ip = i;
		else
			fid_list[i].src_ip = i - 750000;*/
		fid_list[i].src_ip = i;
	}

	init_state_mgmt();

	/* Test Insertion */
	test_insertion(fid_list, NUM_FID);

	/* Test Random Lookup */	
	// hard-coded to obtain real hit rate
	double hitrate[] = {0,
					    0.001, 
						0.27, 
						0.46, 
						0.62, 
						0.72,
						0.815, 
						0.87, 
						0.93, 
						0.971, 
						1 };
	for (i=0; i<(sizeof(hitrate)/sizeof(double)); ++i) {
		test_random_lkup(fid_list, NUM_FID, 1000000, hitrate[i]);
	}

	//test_random_lkup(fid_list, NUM_FID, 2000000, 0.5);

	//test_expiration(fid_list, NUM_FID);

	/* Deletion */
	//test_deletion(fid_list, NUM_FID, 100000);

	///* Test Random Lookup */
	//for (i = 0; i<(sizeof(hitrate) / sizeof(double)); ++i) {
	//	test_random_lkup(fid_list, NUM_FID, 1000000, hitrate[i]);
	//}
}
