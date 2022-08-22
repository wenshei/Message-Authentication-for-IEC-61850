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
 * \brief Defines the interface of a resizeable array data type. The Merkle
 * Tree uses one resizeable array per level as data store for its nodes and
 * leafs.
 */

#ifndef MT_ARR_LIST_H_
#define MT_ARR_LIST_H_

#include "mt_config.h"
#include "mt_err.h"
#include <stdlib.h>
#include "mt_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

/*!
 * \brief A resizable array list for hash values
 *
 * The Merkle Tree array list data structure is a simple, resizable array
 * list. It allows to add new elements to the end of the list, truncating
 * the list, and read and write access to existing elements. Finally, the
 * list is able to print itself to standard out.
 *
 * The list uses a simple memory allocation algorithm. Whenever the number of
 * elements reaches a power of two + 1, enough space to hold the next power
 * of two elements is allocated. So for example, if 4 elements were already
 * allocated, and a 5th is to be added, enough memory for 8 elements is
 * allocated.
 */

typedef struct _RandomNode {
	char* randoms;
	mtdata_t * mtdata;
	int offset;
}RandomNode_t;

void print_payload(const void *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset, char *output);
#define  MTDATALEN sizeof(mtdata_t*)

typedef struct merkle_tree_array_list {
  uint32_t elems; /*!< number of elements in the list */
  //uint8_t *store; /*!< pointer to the address of the first element in the list */
  //LinkList *storelist;
  mtdata_t* mtdatalist;
} mt_al_t;

/*!
 * \brief Creates a new Merkle Tree array list instance.
 * @param len: predetermined length of the array list
 * @return a pointer to the freshly created Merkle Tree array list instance.
 */
mt_al_t *mt_al_create(uint32_t len);
mt_al_t* mt_al_lazy_create(uint32_t len);

void mt_al_sign_data(mt_al_t* mt_al, uint8_t* data);
mt_al_t* mt_al_leaf_create(uint32_t len, uint32_t leaves, size_t data_t_size);
void mtdata_delete(mtdata_t* mt_data);
/*!
 * \brief Deletes an existing Merkle Tree array list instance.
 *
 * @param[in] mt_al
 */
void mt_al_delete(mt_al_t *mt_al);

/*!
 * \brief Adds a new element to the list.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 * @param hash[in] the hash to add to the array list
 * @return MT_SUCCESS if adding the element is successful;
 *         MT_ERR_ILLEGAL_PARAM if any of the incoming parameters is null;
 *         MT_ERR_OUT_OF_MEMORY if the array list cannot allocate any more
 *         space to grow;
 *         MT_ERR_ILLEGAL_STATE if an integer overflow in the allocation code
 *         occurs.
 */
mt_error_t mt_al_add(mt_al_t *mt_al, mtdata_t * data);


/*!
 * \brief Truncates the list of hash values to the given number of elements.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 * @param elems[in] the number of elements to truncate the array list to
 * @return MT_SUCCESS if truncation is successful;
 *         MT_ERR_ILLEGAL_PARAM if the array list pointer is null, or
 *         the new number of elements is out of bounds;
 *         MT_ERR_OUT_OF_MEMORY if reducing the amount of allocated memory
 *         fails.
 */
//mt_error_t mt_al_truncate(mt_al_t *mt_al, const uint32_t elems);

/*!
 * \brief Return a specific hash element from the array list.
 *
 * If either the array list pointer is NULL, or the specified offset is out
 * of bounds, the function will return NULL.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 * @param offset[in] the offset of the element to fetch
 * @return a pointer to the requested hash element in the array list
 */
const mtdata_t *mt_al_get(const mt_al_t *mt_al, const uint32_t offset);

/*!
 * \brief Checks if the element at the given offset has a right neighbor.
 *
 * If the given list pointer is NULL this function will return false.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 * @param offset[in] the offset of the element for which to look for a
 * neighbor
 * @return true if the element at the given offset has a neighbor.
 */
static inline uint32_t mt_al_has_right_neighbor(const mt_al_t *mt_al,
    const uint32_t offset) {
  if (!mt_al) {
    return 0;
  }
  return (offset + 1) < mt_al->elems;
}

/*!
 * \brief Returns the number of elements in the list.
 *
 * If the given list pointer is NULL this function will return 0.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 * @return the number of elements in the list
 */
static inline uint32_t mt_al_get_size(const mt_al_t *mt_al) {
  if (!mt_al) {
    return 0;
  }
  return mt_al->elems;
}

/*!
 * \brief Print a given buffer as hex formated string.
 *
 * If the given list pointer is NULL this function will print an error
 * message.
 *
 * @param buffer[in] the buffer to print
 * @param size[in] the size of the buffer
 */
void mt_al_print_hex_buffer(const uint8_t *buffer, const size_t size);

/*!
 * \brief Print a given buffer as hex formated string into a newly allocated
 * string
 *
 * This function uses a callee allocates caller frees scheme. This function
 * will allocate the memory for the returned string, but it is the callers
 * responsibility to free it. If the given list pointer is NULL this function
 * will print an error message.
 *
 * @param buffer[in] the buffer to print
 * @param size[in] the size of the buffer
 * @return a human readable hex string representation of the buffer
 */
char *mt_al_sprint_hex_buffer(const uint8_t *buffer, const size_t size);

/*!
 * \brief Print the Merkle Tree array list of hashes.
 *
 * If the given list pointer is NULL this function will print an error
 * message.
 *
 * @param mt_al[in] the Merkle Tree array list data type instance
 */
void mt_al_print(const mt_al_t *mt_al);

#endif /* MT_ARR_LIST_H_ */
