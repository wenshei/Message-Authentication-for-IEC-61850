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
 * \brief Implements the Merkle Tree data type.
 */
#include "merkletree.h"
#include "sha.h"


#define BREAK_CHAR 'B'
#define ONE_CHAR '1'
#define ZERO_CHAR '0'


#if MT_DEBUG==1
#define DEBUG(m, ...) do {printf(m, __VA_ARGS__);} while(0);
#define LOG_HASH(str, ... )  printf("%s",str);\
mt_al_print_hex_buffer(__VA_ARGS__);\
printf("\n");
#else
#define DEBUG(m, ...)
#define LOG_HASH(str, ...)
#endif


// FISH
void mt_shift_loc(mt_t* mt, uint32_t shift_size) {
	mt->current_location += shift_size;
}
// FISH
void mt_jump_loc(mt_t* mt, uint32_t offset) {
	mt->current_location = mt->level[0]->mtdatalist + offset;
}

void printProof(mt_t* mt, uint8_t *message, uint32_t message_len, uint8_t* proof, uint32_t proof_size) {
	uint8_t* curs = proof;
	printf("Offset: %d\n", *((uint32_t *)curs));
	curs += sizeof(uint32_t);

	printf("\nElements:\n");
	for (int i = 0; i < message_len; i++) {
		printf("Input %d:\n", i );
		mt_al_print_hex_buffer(curs, 2 * HASH_LENGTH + mt->data_type_size);
		curs += 2 * HASH_LENGTH + mt->data_type_size;
		printf("\n");
	}
	
	printf("\nProofs:\n");
	while ( curs < proof + proof_size) {
		mt_al_print_hex_buffer(curs, HASH_LENGTH);
		printf("\n");
		curs += HASH_LENGTH;
	}
}

uint8_t* mt_generate_proof(mt_t* mt, uint8_t* message, uint32_t message_len, uint32_t* proof_len)
{
	assert( (1 << mt->levels) - mt_get_offset(mt) >= message_len);
	uint32_t tree_height = mt->levels;
	uint32_t offset_left_leaf = mt->current_location - mt->level[0]->mtdatalist; // FISHPER
	uint32_t offset_right_leaf = offset_left_leaf + message_len - 1;

	*proof_len = sizeof(uint32_t) + (2 * HASH_LENGTH + mt->data_type_size) * message_len + 2 * HASH_LENGTH * tree_height;
	uint8_t * proof = (uint8_t*) calloc(*proof_len, 1);
	uint8_t* proof_curs = proof;

	// emplace offset
	memcpy(proof_curs, &offset_left_leaf, sizeof(uint32_t));
	proof_curs += sizeof(uint32_t);

	// emplace nonce values etc.
	for (int i = 0; i < message_len; i++) {

		mtdata_t* leaf = mt->current_location + i;
		// For testing purposes 
		if (message[i] != '0' && message[i] != '1' && message[i] != 'B') {
			message[i] = '1';
		}
		switch (message[i])
		{
		case ZERO_CHAR:
			memcpy(proof_curs, leaf->data, mt->data_type_size);
			proof_curs += mt->data_type_size;
			memcpy(proof_curs, leaf->hashed_data + HASH_LENGTH, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->hashed_data + (HASH_LENGTH << 1), HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			break;
		case ONE_CHAR:
			memcpy(proof_curs, leaf->hashed_data, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->data + mt->data_type_size, mt->data_type_size);
			proof_curs += mt->data_type_size;
			memcpy(proof_curs, leaf->hashed_data + (HASH_LENGTH << 1), HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			break;
		case BREAK_CHAR:
			memcpy(proof_curs, leaf->hashed_data, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->hashed_data + HASH_LENGTH , HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->data + (mt->data_type_size << 1), mt->data_type_size);
			proof_curs += mt->data_type_size;
			break;
		default:
			break;
		}
	}

	uint32_t it_left = offset_left_leaf;
	uint32_t it_right = offset_right_leaf;
	uint32_t l = 0;

	while (it_left ^ it_right) {

		if (it_left & 1) {
			uint8_t* left_proof = mt->level[l]->mtdatalist[it_left ^ 1].data_digest;
			memcpy(proof_curs, left_proof, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			LOG_HASH("Proof LEFT Added:\t", left_proof, HASH_LENGTH );
		}
		if ( !(it_right & 1) ) {
			uint8_t * right_proof = mt->level[l]->mtdatalist[it_right ^ 1].data_digest;
			memcpy(proof_curs, right_proof, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			LOG_HASH("Proof RIGHT Added:\t", right_proof, HASH_LENGTH);
		}

		it_left >>= 1;
		it_right >>= 1;
		l++;
	}

	while (l < tree_height) {
		uint8_t* proof = mt->level[l]->mtdatalist[it_left ^ 1].data_digest;
		memcpy(proof_curs, proof, HASH_LENGTH);
		proof_curs += HASH_LENGTH;
		it_left >>= 1;
		l++;
	}

	//printf("\nMEMORY ALLOCATION: %d \t %d\n ", *proof_len, proof_curs - proof);
	*proof_len = proof_curs - proof;
	proof = realloc(proof, *proof_len);
	mt_shift_loc(mt, message_len - 1);

	if (MT_DEBUG) {
		print_payload(proof, (int) (*proof_len));
	}
    return  proof;
}

uint8_t* mt_generate_eff_proof(mt_t* mt, uint8_t* message, uint32_t message_len, uint32_t* proof_len) {
	assert((1 << mt->levels) - mt_get_offset(mt) >= message_len);
	uint32_t tree_height = mt->levels;
	uint32_t offset_left_leaf = mt->current_location - mt->level[0]->mtdatalist; // FISHPER
	uint32_t offset_right_leaf = offset_left_leaf + message_len - 1;

	*proof_len = sizeof(uint32_t) + (2 * HASH_LENGTH + mt->data_type_size) * message_len +  HASH_LENGTH * tree_height;
	uint8_t* proof = (uint8_t*)calloc(*proof_len, 1);
	uint8_t* proof_curs = proof;

	// emplace offset
	memcpy(proof_curs, &offset_left_leaf, sizeof(uint32_t));
	proof_curs += sizeof(uint32_t);

	// emplace nonce values etc.
	for (int i = 0; i < message_len; i++) {

		mtdata_t* leaf = mt->current_location + i;
		// For testing purposes 
		if (message[i] != '0' && message[i] != '1' && message[i] != 'B') {
			message[i] = '1';
		}
		switch (message[i])
		{
		case ZERO_CHAR:
			memcpy(proof_curs, leaf->data, mt->data_type_size);
			proof_curs += mt->data_type_size;
			memcpy(proof_curs, leaf->hashed_data + HASH_LENGTH, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->hashed_data + (HASH_LENGTH << 1), HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			break;
		case ONE_CHAR:
			memcpy(proof_curs, leaf->hashed_data, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->data + mt->data_type_size, mt->data_type_size);
			proof_curs += mt->data_type_size;
			memcpy(proof_curs, leaf->hashed_data + (HASH_LENGTH << 1), HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			break;
		case BREAK_CHAR:
			memcpy(proof_curs, leaf->hashed_data, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->hashed_data + HASH_LENGTH, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
			memcpy(proof_curs, leaf->data + (mt->data_type_size << 1), mt->data_type_size);
			proof_curs += mt->data_type_size;
			break;
		default:
			break;
		}
	}

	uint32_t it_right = offset_right_leaf;
	uint32_t l = 0;

	while (l < tree_height) {
		if (!(it_right & 1)) {
			uint8_t* proof = mt->level[l]->mtdatalist[it_right ^ 1].data_digest;
			memcpy(proof_curs, proof, HASH_LENGTH);
			proof_curs += HASH_LENGTH;
		}
		it_right >>= 1;
		l++;
	}

	//printf("\nMEMORY ALLOCATION: %d \t %d\n ", *proof_len, proof_curs - proof);
	*proof_len = proof_curs - proof;
	proof = realloc(proof, *proof_len);
	mt_shift_loc(mt, message_len - 1);

	return  proof;
}

uint32_t mt_verify_proof(uint8_t* root_digest, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size)
{
	uint8_t* proof_cur = proof;

	uint32_t offset = *((uint32_t*)proof_cur);
	proof_cur += sizeof(uint32_t);


	mt_hash_t workbench[message_len];
	SHA256Context ctx;

	for (int i = 0; i < message_len; i++) {
		mt_hash_t hashed_value;
		SHA256Reset(&ctx);

		if (message[i] != '0' && message[i] != '1' && message[i] != 'B') {
			message[i] = '1';
		}

		switch (message[i])
		{
			// this parth may be sped up
			// alternatively mt_hash_t * hashbech[3]; 
			// if hash_lenght is too long 
			// this may reduce the memory copy overhead
			case ZERO_CHAR:
				SHA256Input(&ctx, proof_cur, tree_value_size );
				proof_cur += tree_value_size;
				SHA256Result(&ctx, hashed_value);

				SHA256Reset(&ctx);
				SHA256Input(&ctx, hashed_value, HASH_LENGTH);
				SHA256Input(&ctx, proof_cur, HASH_LENGTH << 1);
				SHA256Result(&ctx, workbench[i]);

				proof_cur += HASH_LENGTH << 1;
				break;
			case ONE_CHAR:
				SHA256Input(&ctx, proof_cur + HASH_LENGTH, tree_value_size);
				SHA256Result(&ctx, hashed_value);

				SHA256Reset(&ctx);
				SHA256Input(&ctx, proof_cur, HASH_LENGTH);
				SHA256Input(&ctx, hashed_value, HASH_LENGTH);
				SHA256Input(&ctx, proof_cur + HASH_LENGTH + tree_value_size , HASH_LENGTH);
				SHA256Result(&ctx, workbench[i]);

				proof_cur += (HASH_LENGTH << 1) + tree_value_size;
				break;
			case BREAK_CHAR:
				SHA256Input(&ctx, proof_cur + (HASH_LENGTH << 1), tree_value_size);
				SHA256Result(&ctx, hashed_value);

				SHA256Reset(&ctx);
				SHA256Input(&ctx, proof_cur, (HASH_LENGTH << 1));
				SHA256Input(&ctx, hashed_value, HASH_LENGTH);
				SHA256Result(&ctx, workbench[i]);
				proof_cur += (HASH_LENGTH << 1) + tree_value_size;
				break;

		default:
			break;
		}


		LOG_HASH("Calculated Hash:\t", workbench[i], HASH_LENGTH);
	
	}
		

	uint32_t it_left = offset;
	uint32_t l = 0;
	uint32_t lw = message_len;
	uint32_t nlw = 0;

	while ( lw > 1) {
		
		int i = 0;

		if (it_left & 1) {
			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
			SHA256Result(&ctx, workbench[0]);
			i++;
			nlw++;
			LOG_HASH("Extracted left proof:\t", proof_cur, HASH_LENGTH);
			proof_cur += HASH_LENGTH;
			LOG_HASH("Calculated LEFT Hash:\t", workbench[0], HASH_LENGTH);

		}

		int k = i;
		for (; k < lw - 1; k++) {
			SHA256Reset(&ctx);
			SHA256Input(&ctx, workbench[k++], HASH_LENGTH);
			SHA256Input(&ctx, workbench[k], HASH_LENGTH);
			SHA256Result(&ctx, workbench[k >> 1]);
			nlw++;

			LOG_HASH("Calculated INNER Hash:\t", workbench[k>>1], HASH_LENGTH);

		}

		if (lw - 1 == k) {
			SHA256Reset(&ctx);
			SHA256Input(&ctx, workbench[k], HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Result(&ctx, workbench[(k +1) >> 1]);
			
			LOG_HASH("Extracted right proof:\t", proof_cur, HASH_LENGTH);
			proof_cur += HASH_LENGTH;
			nlw++;

			LOG_HASH("Calculated RIGHT Hash:\t", workbench[k >> 1], HASH_LENGTH);

		}

		lw = nlw;
		nlw = 0;
		it_left >>= 1;
		l++;
	}

	
	while (proof_cur < proof + proof_len) {
		SHA256Reset(&ctx);
		if (it_left & 1) {
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
		}
		else {
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
		}
		SHA256Result(&ctx, workbench[0]);
		proof_cur += HASH_LENGTH;
		it_left >>= 1;

		LOG_HASH("Calculated SINGLE Hash:\t", workbench[0], HASH_LENGTH);

	}



	if (memcmp(workbench[0], root_digest, HASH_LENGTH)) {
		LOG_HASH("Roots Mismatch\nCalculated:\t", workbench[0], HASH_LENGTH);
		LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);

		return 1;
	}
	else {
		LOG_HASH("Roots Match\nCalculated:\t", workbench[0], HASH_LENGTH);
		LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);
		return 0;
	}

	
	/*
	for (int i = 0; i < HASH_LENGTH; i++) {
		if (workbench[0][i] != root_digest[i]) {

			LOG_HASH("Roots Mismatch\nCalculated:\t", workbench[0], HASH_LENGTH);
			LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);
			return 0;
		}
	}*/

	//LOG_HASH("Roots Match\nCalculated:\t", workbench[0], HASH_LENGTH);
	//LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);

	//return 1;
}

uint32_t mt_verify_eff_proof(mt_queue_t **p_state, uint8_t* root_digest, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size) {
	uint8_t* proof_cur = proof;

	uint32_t offset = *((uint32_t*)proof_cur);
	proof_cur += sizeof(uint32_t);


	mt_hash_t workbench[message_len];
	SHA256Context ctx;

	for (int i = 0; i < message_len; i++) {
		mt_hash_t hashed_value;
		SHA256Reset(&ctx);

		if (message[i] != '0' && message[i] != '1' && message[i] != 'B') {
			message[i] = '1';
		}

		switch (message[i])
		{
			// this parth may be sped up
			// alternatively mt_hash_t * hashbech[3]; 
			// if hash_lenght is too long 
			// this may reduce the memory copy overhead
		case ZERO_CHAR:
			SHA256Input(&ctx, proof_cur, tree_value_size);
			proof_cur += tree_value_size;
			SHA256Result(&ctx, hashed_value);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, hashed_value, HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH << 1);
			SHA256Result(&ctx, workbench[i]);

			proof_cur += HASH_LENGTH << 1;
			break;
		case ONE_CHAR:
			SHA256Input(&ctx, proof_cur + HASH_LENGTH, tree_value_size);
			SHA256Result(&ctx, hashed_value);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Input(&ctx, hashed_value, HASH_LENGTH);
			SHA256Input(&ctx, proof_cur + HASH_LENGTH + tree_value_size, HASH_LENGTH);
			SHA256Result(&ctx, workbench[i]);

			proof_cur += (HASH_LENGTH << 1) + tree_value_size;
			break;
		case BREAK_CHAR:
			SHA256Input(&ctx, proof_cur + (HASH_LENGTH << 1), tree_value_size);
			SHA256Result(&ctx, hashed_value);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, (HASH_LENGTH << 1));
			SHA256Input(&ctx, hashed_value, HASH_LENGTH);
			SHA256Result(&ctx, workbench[i]);
			proof_cur += (HASH_LENGTH << 1) + tree_value_size;
			break;

		default:
			break;
		}


		LOG_HASH("Calculated Hash:\t", workbench[i], HASH_LENGTH);

	}

	mt_queue_t* state = *p_state;
	mt_queue_t* new_state = mt_queue_create();

	uint32_t it_left = offset;
	uint32_t l = 0;
	uint32_t lw = message_len;
	uint32_t nlw = 0;


	while (lw > 1) {

		int i = 0;
		/*
			Following is an easy fix that checks if all bits are going to be matched.
		*/
		
		if (it_left & 1) {
			SHA256Reset(&ctx);
			SHA256Input(&ctx, mt_queue_peek(state), HASH_LENGTH);
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
			SHA256Result(&ctx, workbench[0]);
			i++;
			nlw++;
			mt_queue_pop(state);
			LOG_HASH("Calculated LEFT Hash:\t", workbench[0], HASH_LENGTH);
		}

		int k = i;
		for (; k < lw - 1; k++) {
			SHA256Reset(&ctx);
			SHA256Input(&ctx, workbench[k++], HASH_LENGTH);
			SHA256Input(&ctx, workbench[k], HASH_LENGTH);

			if (k == lw - 1) {
				// Hold and save the value before data overridden.
				mt_queue_push(new_state, workbench[lw - 2]);
			}

			SHA256Result(&ctx, workbench[k >> 1]);
			nlw++;

			LOG_HASH("Calculated INNER Hash:\t", workbench[k >> 1], HASH_LENGTH);

		}
		
		if (lw - 1 == k) {
			/*
			There is an unmatched bit.
			*/
			SHA256Reset(&ctx);
			SHA256Input(&ctx, workbench[k], HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Result(&ctx, workbench[(k + 1) >> 1]);
			proof_cur += HASH_LENGTH;
			nlw++;

			LOG_HASH("Calculated RIGHT Hash:\t", workbench[k >> 1], HASH_LENGTH);

		}
		
	

		lw = nlw;
		nlw = 0;
		it_left >>= 1;
		l++;
	}
	/*
		A very interesting logic error exits.
		So far, we assumed in the implementation that the rigthmost vertex will be the dependency of the left most vertex in the next message.
		However, since we ar    

	
	*/

	while (proof_cur < proof + proof_len || !mt_queue_isempty(state)) {
		SHA256Reset(&ctx);
		if (it_left & 1) {
			SHA256Input(&ctx, mt_queue_peek(state), HASH_LENGTH);
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
			mt_queue_push(new_state, mt_queue_peek(state));
			mt_queue_pop(state);
		}
		else {
			SHA256Input(&ctx, workbench[0], HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			proof_cur += HASH_LENGTH;
		}
		SHA256Result(&ctx, workbench[0]);
		it_left >>= 1;

		LOG_HASH("Calculated SINGLE Hash:\t", workbench[0], HASH_LENGTH);

	}

	free(state);
	*p_state = new_state;

	if (memcmp(workbench[0], root_digest, HASH_LENGTH)) {
		LOG_HASH("Roots Mismatch\nCalculated:\t", workbench[0], HASH_LENGTH);
		LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);

		return 1;
	}
	else {
		LOG_HASH("Roots Match\nCalculated:\t", workbench[0], HASH_LENGTH);
		LOG_HASH("Root is:\t", root_digest, HASH_LENGTH);
		return 0;
	}
}


/*
	mt_verify_meff_proof is compatible with proofs generated by mt_generate_proof 
*/
uint32_t mt_verify_meff_proof(mt_t* mt_state, uint8_t* message, uint32_t message_len, uint8_t* proof, uint32_t proof_len, uint32_t tree_value_size) {
	// come up with a more robust algorithm.
	uint8_t* proof_cur = proof;

	uint32_t offset = *((uint32_t*)proof_cur);
	uint32_t left_offset = offset;
	uint32_t right_offset = left_offset + message_len - 1;

	proof_cur += sizeof(uint32_t);

	mt_hash_t hashed_temp, hashed_res;


	SHA256Context ctx;
	mtdata_t* c_leaf = mt_state->level[0]->mtdatalist + left_offset;

	for (int i = 0; i < message_len; i++, c_leaf++) {
		
		SHA256Reset(&ctx);

		if (message[i] != '0' && message[i] != '1' && message[i] != 'B') {
			message[i] = '1';
		}

		switch (message[i])
		{
			// this parth may be sped up
			// alternatively mt_hash_t * hashbech[3]; 
			// if hash_lenght is too long 
			// this may reduce the memory copy overhead
			// the code became too complex unnecessarily
			// I have an instinct that whole procedure can be sped up bu suing the mathematical substructure.
		case ZERO_CHAR:
			SHA256Input(&ctx, proof_cur, tree_value_size);
			proof_cur += tree_value_size;
			SHA256Result(&ctx, hashed_temp);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, hashed_temp, HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH << 1);
			SHA256Result(&ctx, hashed_res);

			proof_cur += HASH_LENGTH << 1;
			break;
		case ONE_CHAR:
			SHA256Input(&ctx, proof_cur + HASH_LENGTH, tree_value_size);
			SHA256Result(&ctx, hashed_temp);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Input(&ctx, hashed_temp, HASH_LENGTH);
			SHA256Input(&ctx, proof_cur + HASH_LENGTH + tree_value_size, HASH_LENGTH);
			SHA256Result(&ctx, hashed_res);

			proof_cur += (HASH_LENGTH << 1) + tree_value_size;
			break;
		case BREAK_CHAR:
			SHA256Input(&ctx, proof_cur + (HASH_LENGTH << 1), tree_value_size);
			SHA256Result(&ctx, hashed_temp);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, (HASH_LENGTH << 1));
			SHA256Input(&ctx, hashed_temp, HASH_LENGTH);
			SHA256Result(&ctx, hashed_res);
			proof_cur += (HASH_LENGTH << 1) + tree_value_size;
			break;

		default:
			break;
		}

		if (c_leaf->data_digest) {
			if (memcmp(c_leaf->data_digest, hashed_res, HASH_LENGTH)) {
				//printf("false proof");
				return 1;
			}
			else {
				//printf("Skipped %d-%d", 0, offset + i);
				left_offset++;
			}
		}
		else {
			c_leaf->data_digest = malloc(HASH_LENGTH);
			memcpy(c_leaf->data_digest, hashed_res, HASH_LENGTH);
		}

		LOG_HASH("Calculated Hash:\t", c_leaf->data_digest, HASH_LENGTH);
	
	}
	
	uint32_t redundant_left_proof_tracker = offset;
	uint32_t left = left_offset;
	uint32_t right = right_offset;

	for (uint32_t l = 0; l < mt_state->levels; l++) { // check if upper bound for level-wise scan
		
	

		uint32_t c = left;

		if (left & 1) {
			// CHALLENGE: how to eliminate redundant left proofs. 
			// this condition is never satisfied unless there is a lost message.
			mtdata_t* right_node = mt_state->level[l]->mtdatalist + left;
			mtdata_t* up_node = mt_state->level[l + 1]->mtdatalist + (left >> 1 );
			
			SHA256Reset(&ctx);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Input(&ctx, right_node->data_digest, HASH_LENGTH);
			SHA256Result(&ctx, hashed_res);
			proof_cur += HASH_LENGTH;

			if (up_node->data_digest) {
				if (memcmp(hashed_res, up_node->data_digest, HASH_LENGTH)) {
					printf("\nExtracted left proof:\t");
					mt_al_print_hex_buffer(proof_cur - HASH_LENGTH, HASH_LENGTH);
					printf("\nCalculated upper level:\t");
					mt_al_print_hex_buffer(hashed_res, HASH_LENGTH);
					printf("\nExpected upper level:\t");
					mt_al_print_hex_buffer(up_node->data_digest, HASH_LENGTH);
					return 1;
				}
				else {
					left++;
				}
			
			}
			else {
				up_node->data_digest = malloc(HASH_LENGTH);
				memcpy(up_node->data_digest, hashed_res, HASH_LENGTH);
				//storing the proof is unnecessary
			}

			c++;
		}
		else if (redundant_left_proof_tracker & 1) {
			// waste the redundant proof.
			proof_cur += HASH_LENGTH;
		}
		redundant_left_proof_tracker >>= 1;
		
		for (; c < right; c+= 2) {

			mtdata_t* left_p, * right_p, * up_p;
			left_p = mt_state->level[l]->mtdatalist + c;
			right_p = mt_state->level[l]->mtdatalist + c + 1;
			up_p = mt_state->level[l + 1]->mtdatalist + (c >> 1);

			SHA256Reset(&ctx);
			SHA256Input(&ctx, left_p->data_digest, HASH_LENGTH);
			SHA256Input(&ctx, right_p->data_digest, HASH_LENGTH);
			SHA256Result(&ctx, hashed_res);

			if (up_p->data_digest) {
				if (memcmp(up_p->data_digest, hashed_res, HASH_LENGTH)) {
					return 1;
				}
				else {
					//printf("Skipped %d-%d", l, c);
					left += 2;
				}
			}
			else {
				up_p->data_digest = malloc(HASH_LENGTH);
				memcpy(up_p->data_digest, hashed_res, HASH_LENGTH);
			}
		}


		if (c == right) {

			// proof is the value of the following node on the tree
			mtdata_t* left_node = mt_state->level[l]->mtdatalist + c;
			mtdata_t* proof_node = mt_state->level[l]->mtdatalist + c + 1;
			mtdata_t* up_node = mt_state->level[l + 1]->mtdatalist + (c >> 1);
			// read from proof 
			SHA256Reset(&ctx);
			SHA256Input(&ctx, left_node->data_digest, HASH_LENGTH);
			SHA256Input(&ctx, proof_cur, HASH_LENGTH);
			SHA256Result(&ctx, hashed_res);

			if (up_node->data_digest) {
				if (memcmp(up_node->data_digest, hashed_res, HASH_LENGTH)) {
					
					printf("\nPosition:%d, %d\nExtracted right proof:\t",l,c);
					mt_al_print_hex_buffer(proof_cur, HASH_LENGTH);
					printf("\nCalculated upper level:\t");
					mt_al_print_hex_buffer(hashed_res, HASH_LENGTH);
					printf("\nExpected upper level:\t");
					mt_al_print_hex_buffer(up_node->data_digest, HASH_LENGTH);
					
					return 1;
				}
				else {
					// termination  condition
					// dont forget to copy the proof

					//printf("Skipped %d-%d. Finished.\n", l, c);
					proof_node->data_digest = malloc(HASH_LENGTH);
					memcpy(proof_node->data_digest, proof_cur, HASH_LENGTH);
					return 0;
				}
			}
			else {
				up_node->data_digest = malloc(HASH_LENGTH);
				proof_node->data_digest = malloc(HASH_LENGTH);
				memcpy(proof_node->data_digest, proof_cur, HASH_LENGTH);
				memcpy(up_node->data_digest, hashed_res, HASH_LENGTH);
				proof_cur += HASH_LENGTH;
				right++;
			}

		}


		left = left >> 1;
		right = right >> 1;
		

	}

	return 0;

	




	
}


// a new function for mt's needed for verification needed.

//----------------------------------------------------------------------
mt_t* mt_create_lazy(uint32_t number_of_levels) {
	mt_t* mt = (mt_t*)calloc(1, sizeof(mt_t));
	if (!mt) {
		return NULL;
	}
	mt->levels = number_of_levels;
	mt->level = (mt_al_t * *)calloc((number_of_levels + 1), sizeof(mt_al_t*));
	uint32_t number_of_leaves = 1 << number_of_levels;
	mt->elems = number_of_leaves;
	for (int i = 0; i <= number_of_levels; i++) {
		mt->level[i] = mt_al_lazy_create(number_of_leaves);
		number_of_leaves >>= 1;
	}
	mt_jump_loc(mt, 0);
	return mt;
}
mt_t *mt_create(uint32_t number_of_levels, size_t data_t_size)
{

 // FURTHER OPTIMIZATIONS DEALING WITH MEMORY ALLOCATIONS POSSIBLE  

  mt_t *mt = (mt_t *) calloc(1, sizeof(mt_t));
  if (!mt) {
	  return NULL;
  }
  mt->data_type_size = data_t_size;
  mt->levels = number_of_levels;
  mt->level = (mt_al_t **) calloc((number_of_levels + 1 ), sizeof(mt_al_t*));

  uint32_t number_of_leaves = 1 << number_of_levels;
  mt->elems = number_of_leaves;
  mt->level[0] = mt_al_leaf_create(number_of_leaves, 3, mt->data_type_size);// NOTE2MYSELF: maybe FIX this later
  number_of_leaves >>= 1;

  for (int i = 1; i <= number_of_levels; i++) {
	  mt->level[i] = mt_al_create(number_of_leaves);
	  number_of_leaves >>= 1;
  }
  /*
  if (!mt) {
    return NULL;
  }
  
  for (uint32_t i = 0; i < TREE_LEVELS; ++i) {
    mt_al_t *tmp = mt_al_create();
    if (!tmp) {
      for (uint32_t j = 0; j < i; ++j) {
        mt_al_delete(mt->level[j]);
      }
      free(mt);
      return NULL;
    }
    mt->level[i] = tmp;
  }*/
  mt_jump_loc(mt, 0);

  return mt;
}

//----------------------------------------------------------------------
void mt_delete(mt_t *mt)
{
  if (!mt) {return;}
  for (uint32_t i = 0; i < mt->levels; ++i) {
    mt_al_delete(mt->level[i]);
  }
  free(mt);
}

/*!
 * \brief Determines if the given index points to a right node in the tree
 * @param offset the index of the node
 * @return true if the given index is a right node; false otherwise
 */
static int mt_right(uint32_t offset)
{
  // odd index means we are in the right subtree
  return offset & 0x01;
}

/*!
 * \brief Determines if the given index points to a left node in the tree
 * @param offset the index of the node
 * @return true if the given index is a left node; false otherwise
 */
static int mt_left(uint32_t offset)
{
  // even index means we are in the left subtree
  return !(offset & 0x01);
}

//----------------------------------------------------------------------
/*
mt_error_t mt_add(mt_t *mt, mtdata_t* data)
{

	if (data->data_digest) {
		return MT_ERR_ILLEGAL_PARAM;
	}
	sign_data(data);
	mt_al_add(mt->level[0], data);

	return MT_SUCCESS;
}*/
mt_error_t mt_build(mt_t* mt, uint8_t* buffer ) {

	mt_al_sign_data(mt->level[0], buffer);

	uint8_t message_digest[HASH_LENGTH];
	uint32_t q;
	uint32_t l = 0;         // level
	uint32_t ql = mt->elems; // size of the current level
	//print_payload(right, sizeof(mtdata_t));

	mtdata_t* extra = NULL;

	while ((ql = mt_al_get_size(mt->level[l])) > 1) {
		
		int q = 1; // offset index for this level's elements

		for (; q < ql; q += 2) {
			calcHashFrom2(mt->level[l]->mtdatalist[q - 1].data_digest, mt->level[l]->mtdatalist[q].data_digest, mt->level[l + 1]->mtdatalist[q >> 1].data_digest);
		}

		if (q == ql) {
			//number of elements in this level are odd
			// q - 1 is the last odd element
			if (extra) {
				
				calcHashFrom2(mt->level[l]->mtdatalist[q-1].data_digest, extra->data_digest, mt->level[l + 1]->mtdatalist[q >> 1].data_digest);

				extra = NULL;
			}
			else {
				// reserve last element as extra
				extra = mt->level[l]->mtdatalist + (q - 1);
				//mt_al_get(mt->level[l], q - 1);
			}
		}
		l++;
	}

	mt_jump_loc(mt, 0);
	return MT_SUCCESS;
}

struct timeval timediff, starttime, endtime;

//----------------------------------------------------------------------
void mt_print_hash(const mt_hash_t hash)
{
  if (!hash) {
    printf("[ERROR][mt_print_hash]: Hash NULL");
  }
  mt_al_print_hex_buffer(hash, HASH_LENGTH);
  printf("\n");
}

//----------------------------------------------------------------------
void mt_print(const mt_t *mt)
{
  if (!mt) {
    printf("[ERROR][mt_print]: Merkle Tree NULL");
    return;
  }
  for (uint32_t i = 0; i <= mt->levels; ++i) {
    

    printf(
        "==================== Merkle Tree level[%02u]: ====================\n",
        (unsigned int)i);
    mt_al_print(mt->level[i]);
  }
}

uint8_t* mt_get_root_digest(const mt_t* mt) {
	return mt->level[mt->levels]->mtdatalist->data_digest;
}

uint32_t mt_get_offset(const mt_t* mt)
{
	return  mt->current_location - mt->level[0]->mtdatalist;
}



void print_hex_ascii_line(const u_char* payload, int len, int offset, char* output)
{

	int i;
	int gap;
	const u_char* ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		if (output != NULL) {
			sprintf(&output[i * 2], "%02x", *ch);
		}

		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}



/*
* print packet payload data (avoid printing binary data)
*/
void print_payload(const void* payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	u_char* ch = (u_char*)payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset, NULL);
		return;
	}

	/* data spans multiple lines */
	for (;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset, NULL);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset, NULL);
			break;
		}
	}

	return;
}