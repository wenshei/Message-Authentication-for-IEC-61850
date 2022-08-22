#include "mt_state.h"
/*
	There is to much redundancy right now.
	Later fix these if needed.
*/
mt_queue_t* mt_queue_create() {
	mt_queue_t* q = malloc(sizeof(mt_queue_t));
	q->begin = NULL;
	q->end = NULL;
	q->length = 0;
	return q;
}

void mt_queue_free(mt_queue_t* q) {
	mt_slist_el_t* pp = q->begin;
	mt_slist_el_t* temp;
	while (pp != NULL) {
		temp = pp->next;
		free(pp);
		pp = temp;
	}
	free(q);
}

void mt_queue_print(mt_queue_t* q) {
	int count = 0;
	mt_slist_el_t* p = q->begin;
	while (p != NULL) {
		printf("Elem %d:\t", count++);
		mt_al_print_hex_buffer(p->data, HASH_LENGTH);
		p = p->next;
		printf("\n");
	}
	
}
void mt_queue_push(mt_queue_t* q, uint8_t* d) {
	mt_slist_el_t* el = malloc(sizeof(mt_slist_el_t));//retrieve from a pool instead of performing an allocation
	memcpy(el->data, d, HASH_LENGTH);
	el->next = NULL;
	if (!q->length ) {
		q->begin = el;
		q->end = el;
	}
	else {
		q->end->next = el;
		q->end = el;
	}
	q->length++;
}

void mt_queue_pop(mt_queue_t* q) {

	if (mt_queue_isempty(q) ) {
		return;
	}

	mt_slist_el_t* el = q->begin;
	q->begin = el->next;
	q->length--;
	free(el);

	if (!q->begin) {
		q->end = NULL;
	}
}

bool mt_queue_isempty(mt_queue_t* q) {
	return !(q->length);
}

uint8_t* mt_queue_peek(mt_queue_t* q) {
	return q->begin->data;
}
