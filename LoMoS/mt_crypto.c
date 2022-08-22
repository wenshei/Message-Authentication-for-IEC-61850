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
 * \brief Implements the Merkle Tree hash interface using SHA-256 the hash
 * function.
 */

#include "sha.h"

#include "mt_crypto.h"

//----------------------------------------------------------------------

void  calcHashFrom2(mt_hash_t left, mt_hash_t right, mt_hash_t out) {

	SHA256Context ctx;
	SHA256Reset(&ctx);
	SHA256Input(&ctx, left, HASH_LENGTH);
	SHA256Input(&ctx, right, HASH_LENGTH);
	SHA256Result(&ctx, out);

}

mt_error_t sign_data( mtdata_t* data) {
	if  (!data->data_digest) return MT_ERR_ILLEGAL_PARAM;


	//data->hashed_data = malloc(HASH_LENGTH * data->data_size);


	uint8_t* p_data, * p_hash;
	p_data = data->data;
	p_hash = data->hashed_data;

	SHA256Context ctx;

	for (int i = 0; i < data->data_size; i++)
	{
		SHA256Reset(&ctx);
		SHA256Input(&ctx, p_data , data->data_type_size);
		SHA256Result(&ctx, p_hash);

		p_data += data->data_type_size;
		p_hash += HASH_LENGTH;

	}

	//data->data_digest = malloc(HASH_LENGTH);

	SHA256Reset(&ctx);
	SHA256Input(&ctx, data->hashed_data, p_hash - data->hashed_data);
	SHA256Result(&ctx, data->data_digest);

	return MT_SUCCESS;
}
