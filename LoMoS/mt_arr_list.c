/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 * 
 * This file is part of the Merkle Tree Library.
 * 
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 * 
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 * 
 * The Merkle Tree Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with the Merkle Tree Library. If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 * \brief Implements a resizeable array data type. The Merkle Tree uses one
 * resizeable array per level as data store for its nodes and leafs.
 */
#include "mt_arr_list.h"


/*!
 * \brief Computes the next highest power of two
 *
 * This nice little algorithm is taken from
 * http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 */
static uint32_t round_next_power_two(uint32_t v)
{
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  v += (v == 0); // handle v == 0 edge case
  return v;
}

//----------------------------------------------------------------------
static int is_power_of_two(uint32_t v)
{
  return (v != 0) && ((v & (v - 1)) == 0);
}

//----------------------------------------------------------------------
mt_al_t* mt_al_leaf_create(uint32_t len, uint32_t leaves, size_t data_t_size) {
	mt_al_t* mt_al = (mt_al_t *)calloc(1,sizeof(mt_al_t));
	mt_al->elems = len;
	mt_al->mtdatalist =(mtdata_t *) calloc(len ,sizeof(mtdata_t));
	for (int i = 0; i < len; i++) {
		mt_al->mtdatalist[i].data_type_size = data_t_size;
		mt_al->mtdatalist[i].data_size = leaves;
		mt_al->mtdatalist[i].data_digest = (uint8_t *) malloc(HASH_LENGTH);
		mt_al->mtdatalist[i].hashed_data = (uint8_t *) malloc(HASH_LENGTH * leaves);
		mt_al->mtdatalist[i].data = (uint8_t * ) malloc(leaves * data_t_size); // NOTE2MYSELF: maybe FIX this later
	}
	return mt_al;
}


void mt_al_sign_data(mt_al_t* mt_al, uint8_t* data) {

	uint32_t leave_num = mt_al->mtdatalist[0].data_size;
	uint32_t data_type_size = mt_al->mtdatalist[0].data_type_size;
	uint32_t inc = leave_num * data_type_size;
	for (int i = 0; i < mt_al->elems; i++) {
		memcpy(mt_al->mtdatalist[i].data, data + i * inc , inc );
		sign_data(mt_al->mtdatalist + i);
	}
}

mt_al_t* mt_al_lazy_create(uint32_t len) {

	mt_al_t* mt_al = (mt_al_t*)malloc(sizeof(mt_al_t));
	mt_al->elems = len;
	mt_al->mtdatalist = (mtdata_t*)malloc(len * sizeof(mtdata_t));
	for (int i = 0; i < len; i++) {
		mt_al->mtdatalist[i].data_digest = NULL;
		mt_al->mtdatalist[i].data_size = 0;
	}
	return mt_al;
}
mt_al_t *mt_al_create(uint32_t len)
{
	mt_al_t* mt_al = (mt_al_t *) malloc(sizeof(mt_al_t));
	mt_al->elems = len;
	mt_al->mtdatalist = (mtdata_t *) malloc(len * sizeof(mtdata_t));
	for (int i = 0; i < len; i++) {
		mt_al->mtdatalist[i].data_digest = (uint8_t*) malloc(HASH_LENGTH);
		mt_al->mtdatalist[i].data_size = 0;
	}
	return mt_al;
 // return calloc(1, sizeof(mt_al_t));
}

void mtdata_delete(mtdata_t* mt_data) {
	free(mt_data->data_digest);
	if (mt_data->data_size) {
		free(mt_data->data);
		if (mt_data->hashed_data) // 27.06.2019
			free(mt_data->hashed_data);
	}
}

//----------------------------------------------------------------------
void mt_al_delete(mt_al_t *mt_al)
{
  //LinkList_Destroy(mt_al->storelist);
	mtdata_t* mt_data = mt_al->mtdatalist;
	for (int i = 0; i < mt_al->elems; i++, mt_data++ ) {
		mtdata_delete(mt_data);
	}
	free(mt_al->mtdatalist);
    free(mt_al);
}

//----------------------------------------------------------------------


//----------------------------------------------------------------------
const mtdata_t *mt_al_get(const mt_al_t *mt_al, const uint32_t offset)
{
  // this can only happen due to outside interference.
  assert(mt_al->elems < MT_AL_MAX_ELEMS);
  if (!(mt_al && offset < mt_al->elems)) {
    return NULL;
  }

  return mt_al->mtdatalist + offset;
  //return LinkList_Get(mt_al->storelist, offset);
}



//----------------------------------------------------------------------
void mt_al_print_hex_buffer(const uint8_t *buffer, const size_t size)
{
  if (!buffer) {
    fprintf(stderr,
        "[ERROR][mt_al_print_hex_buffer]: Merkle Tree array list is NULL");
    return;
  }
  for (size_t i = 0; i < size; ++i) {
    printf("%02X", buffer[i]);
  }
}

//----------------------------------------------------------------------
char *mt_al_sprint_hex_buffer(const uint8_t *buffer, const size_t size)
{
  if (!buffer) {
    fprintf(stderr,
        "[ERROR][mt_al_sprint_hex_buffer]: Merkle Tree array list is NULL");
    return NULL;
  }
  size_t to_alloc = size * (sizeof(char) * 2) + 1;
  char *str = (char * ) malloc(to_alloc);
  for (size_t i = 0; i < size; ++i) {
    snprintf((str + (i*2)), 3, "%02X", buffer[i]);
  }
  return str;
}

//----------------------------------------------------------------------
void mt_al_print(const mt_al_t *mt_al)
{
  
  if (!mt_al) {
    fprintf(stderr, "[ERROR][mt_al_print]: Merkle Tree array list is NULL");
    return;
  }
  printf("[%d---\n", (unsigned int)mt_al->elems);

  for (uint32_t i = 0; i < mt_al->elems; ++i) {

	mtdata_t  *temp = mt_al->mtdatalist + i;
	if (temp->data) {
		printf("%d-\tData Values & Hashes:\n",i);
		for (uint32_t j = 0; j < temp->data_size; j++) {
			printf("\t%d-\tValue:\t ", j);
			mt_al_print_hex_buffer(temp->data + j * temp->data_type_size, temp->data_type_size);
			printf("\t\tHash:\t");
			mt_al_print_hex_buffer(temp->hashed_data + j * HASH_LENGTH, HASH_LENGTH);
			printf("\n");
		}
		printf("\n\tDigest:");
	}
	if (temp->data_digest)
		mt_al_print_hex_buffer(temp->data_digest, HASH_LENGTH);
	else
		printf("\tFREE");
	printf("\n");
  }
  
  printf("]\n");
}
