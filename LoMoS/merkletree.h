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
 * \brief Defines the public interface for the Merkle Tree Library.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MERKLETREE_H_
#define MERKLETREE_H_
#define D_TEST_VALUES 64
#define LEAFE_SIZE 3
//#define MT_DEBUG 1

#include "mt_config.h"
#include "mt_err.h"
#include "mt_state.h"
#include "mt_arr_list.h"
#include <string.h>
#include "mt_crypto.h"
#include <ctype.h>


#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/*!
 * \brief defines the Merkle Tree data type
 *
 * A Merkle Tree is used for ...
 */
typedef struct merkle_tree {
  uint32_t elems;
  mt_al_t** level;
  uint32_t levels;
  uint32_t data_type_size;
  mtdata_t* current_location ;

} mt_t;


// FISH
void printProof(mt_t* mt, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_size);
// FISH
void mt_shift_loc(mt_t *mt, uint32_t shift_size);
// FISH
void mt_jump_loc(mt_t *mt, uint32_t offset);
// FISH
uint8_t* mt_generate_eff_proof(mt_t* mt, uint8_t* message, uint32_t message_len, uint32_t* proof_len);
// FISH
uint8_t* mt_generate_proof(mt_t* mt, uint8_t* message, uint32_t message_len, uint32_t* proof_len);
// FISH
uint32_t mt_verify_proof(uint8_t* root_digest, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size);
//FISH 
uint32_t mt_verify_eff_proof(mt_queue_t **p_state,uint8_t* root_digest, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size);
//FISH
uint32_t mt_verify_meff_proof(mt_t *mt_state, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size);
/*!
 * \brief creates a new instance of the Merkle Tree data type
 *
 * This function tries to create a new Merkle Tree data type for ...
 */
mt_t* mt_create(uint32_t number_of_levels, size_t data_t_size);
mt_t *mt_create_lazy(uint32_t number_of_levels);
/*!
 *
 * \brief deletes the specified Merkle Tree instance
 *
 * \param[in] mt a pointer to the Merkle Tree instance to delete
 */
void mt_delete(mt_t *mt);
/*!
 * \brief Prints a human readable representation of a hash in hexadecimal notation
 *
 * @param hash the hash to print
 */
void mt_print_hash(const mt_hash_t hash);

/*!
 * Print a human readable representation of the Merkle Tree
 * @param mt a pointer to the Merkle Tree data type instance to print
 */
void mt_print(const mt_t *mt);

uint8_t* mt_get_root_digest(const mt_t* mt);
uint32_t mt_get_offset(const mt_t* mt);
mt_error_t mt_build(mt_t *mt, uint8_t* buffer);


#endif /* MERKLETREE_H_ */
#ifdef __cplusplus
}
#endif
