#ifndef LB_STATE_T_H
#define LB_STATE_T_H

#include <lb_type.h>

typedef struct {
    int cache_hit;
    int store_hit;
    int miss;
    int num_flow; 
} lb_state_stats_t;

typedef enum { ft_init,
			   ft_cache_hit,
			   ft_store_hit,
			   ft_miss,
			   ft_stop_cache,
			   ft_stop_store,
			   ft_stop_inexist
			 } flow_tracking_status;

void init_state_mgmt();

flow_tracking_status flow_tracking(const fid_t *fid, state_entry_t **out_state, time_t ts, int idx);
flow_tracking_status flow_tracking_no_creation(const fid_t *fid, state_entry_t **out_state, time_t ts, int idx);
flow_tracking_status stop_tracking(const fid_t *fid);
void check_expiration(time_t crt_time, int timeout);

#endif
