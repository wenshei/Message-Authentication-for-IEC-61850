#ifndef MT_STATE_H_
#define MT_STATE_H_

#include "mt_config.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "mt_arr_list.h"
// State of verification is held in a single linked-list. Implemented from scratch for efficacy.

typedef struct mt_slist_el {
	struct mt_slist_el* next;
	mt_hash_t data;
} mt_slist_el_t;

typedef struct ver_state_queue {
	mt_slist_el_t* begin, * end;
	uint32_t length;
} mt_queue_t;

mt_queue_t* mt_queue_create();
void mt_queue_free(mt_queue_t* q);
void mt_queue_print(mt_queue_t* q);
void mt_queue_push(mt_queue_t* q, uint8_t* d);
void mt_queue_pop(mt_queue_t* q);
bool mt_queue_isempty(mt_queue_t* q);
uint8_t* mt_queue_peek(mt_queue_t* q);
#endif // !MT_STATE_H_
