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
 * \brief Implements very simple tests which require manual checking.
 * Superseded by tests defined in the tests/ folder.
 */
#include <sched.h>
#include <openssl/bio.h>
#include <openssl/dsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "merkletree.h"
#include <sys/time.h> 
#include "time.h"

#define DEBUG_TEST 1
#define min(a, b) a < b ? a : b;
#define DATA_TYPE_SIZE 32
#define LEAFE_SIZE 3
#define KEY_SIZE 256
#define BUF_SIZE 200
#define RSA_KEY_LENGTH 3072
#define DSA_KEY_LENGTH  3072
#define DSA_TYPE_NUM 1

//#define KEY_LENGTH  2048
#define PUB_EXP     3
//#define TREE_HEIGHT 8
typedef struct timespec timespc;
int ERROR(char *warn) {
	fprintf(stdout, "%s\n", warn);
	return 1;
}

long long unsigned int DELTA(timespc* t1,timespc* t2) {
	uint64_t val = t1->tv_sec - t2->tv_sec;
	val *= 1e9;
	val += t1->tv_nsec - t2->tv_nsec;
	return val;
}

void LOG(timespc* end, timespc* beg) {
	printf("%llu\n", DELTA(end, beg));
}
void LOGF(FILE *f,timespc* end, timespc* beg) {
	fprintf(f,"%llu\n", DELTA(end, beg));
}
int main(int argc, char *argv[])
{

	struct sched_param param;
	param.sched_priority = 99;
	sched_setscheduler(0, SCHED_FIFO, &param);

	if (argc < 2) {
		return ERROR("USAGE:  TASK (ini,bld,sgn,dsa,gen,gef,ver,vef,vff, eccoo) ...");
	}
	
	char* TASK_NAME = argv[1];
	
	struct timespec meas_begin, meas_end;

	//  TEST_SIZE TREE_HEIGHT MESSAGE_LEN 
	if (!memcmp(TASK_NAME, "ini",3)) {

		if (argc < 4) {
			return ERROR("USAGE: ini TEST_SIZE TREE_HEIGHT");
		}
		int TEST_SIZE = atoi(argv[2]);
		uint32_t TREE_HEIGHT = atoi(argv[3]);
		uint32_t num_leave = 1 << TREE_HEIGHT;

		mt_t* mt = NULL;
		uint8_t* buffer = NULL;
		for (int T = 0; T < TEST_SIZE; T++) {
			// Below are the first time initializations 
			clock_gettime(CLOCK_MONOTONIC, &meas_begin);
			mt = mt_create(TREE_HEIGHT, DATA_TYPE_SIZE);
			buffer = (uint8_t*)malloc(num_leave * 3 * DATA_TYPE_SIZE);
			clock_gettime(CLOCK_MONOTONIC, &meas_end);
			LOG(&meas_end, &meas_begin);
			free(buffer);
			mt_delete(mt);
		}
	}
	else if (!memcmp(TASK_NAME, "bld",3)) {

		if (argc < 4) {
			return ERROR("USAGE: bld TEST_SIZE TREE_HEIGHT MESSAGE_LEN ");
		}
		int TEST_SIZE = atoi(argv[2]);
		uint32_t TREE_HEIGHT = atoi(argv[3]);
		uint32_t num_leave = 1 << TREE_HEIGHT;

		mt_t *mt = mt_create(TREE_HEIGHT, DATA_TYPE_SIZE);
		uint8_t* buffer = (uint8_t*)malloc(num_leave * 3 *DATA_TYPE_SIZE);
	
		for (int T = 0; T < TEST_SIZE; T++) {
			clock_gettime(CLOCK_MONOTONIC, &meas_begin);
			for (uint32_t i = 0; i < num_leave; i++) {
				buffer[i] = random() % 256;//31;//random();
			}
			mt_build(mt, buffer);
			clock_gettime(CLOCK_MONOTONIC, &meas_end);
			LOG(&meas_end, &meas_begin);
		}
		free(buffer);
		mt_delete(mt);
	}
	else if (!memcmp(TASK_NAME, "sgn",3))	{
		
		if (argc < 4)
		{
			return ERROR("USAGE: sgn TEST_SIZE LENGTH");
		}
		typedef struct timespec ts;
		int TEST_SIZE = atoi(argv[2]);
		int LENGTH = atoi(argv[3]);

		BIGNUM* expon = BN_new();
		BN_set_word(expon, PUB_EXP);

		RSA* rsa = RSA_new();
		RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, expon, NULL);

		EVP_MD_CTX* ctx = EVP_MD_CTX_create();
		EVP_PKEY* keys = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(keys, rsa);

		uint8_t* root_digest = malloc(LENGTH);
		unsigned char* root_digest_hash = NULL;


		for (int T = 0; T < TEST_SIZE; T++) {
			ts sgn_b, sgn_e, ver_b, ver_e;

			for (int i = 0; i < LENGTH; i++) {
				root_digest[i] = random() % 256;//i % 79;// random() % 256;
			}
	
			unsigned char* root_digest_u = (unsigned char*)root_digest; // (unsigned char*)"12345678";
			size_t enc_len;
			// ask whether we need to rebuild the tree
			clock_gettime(CLOCK_MONOTONIC, &sgn_b);
			EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, keys);
			EVP_DigestSignUpdate(ctx, root_digest_u, LENGTH);
			EVP_DigestSignFinal(ctx, NULL, &enc_len);
			if (root_digest_hash == NULL) {
				root_digest_hash = (unsigned  char*)malloc(enc_len);
			}
			EVP_DigestSignFinal(ctx, root_digest_hash, &enc_len);
			clock_gettime(CLOCK_MONOTONIC, &sgn_e);

			// EVP_MD_CTX_cleanup(ctx);
			// EVP_MD_CTX_free(ctx);
			
			clock_gettime(CLOCK_MONOTONIC, &ver_b);
			EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, keys);
			EVP_DigestVerifyUpdate(ctx, root_digest_u, LENGTH);
			if (!EVP_DigestVerifyFinal(ctx, root_digest_hash, enc_len)) {
				free(root_digest_hash);
				return ERROR("Could not verify root.\nTerminating...");
			}
			clock_gettime(CLOCK_MONOTONIC, &ver_e);

			printf("%10llu\t%10llu\n", DELTA(&sgn_e, &sgn_b), DELTA(&ver_e, &ver_b));

			// EVP_MD_CTX_cleanup(ctx);
			EVP_MD_CTX_free(ctx);
		}

		
		free(root_digest);
		free(root_digest_hash);
	}
	else if (!memcmp(TASK_NAME, "dsa", 3)) {

	if (argc < 4) {
		printf("USAGE dsa TEST_SIZE MSG_LEN\n");
		return 1;
	}
	typedef struct timespec ts;

	int TEST_SIZE = atoi(argv[2]);
	int MSG_LEN = atoi(argv[3]);

	DSA* dsa = DSA_new();

	if (!DSA_generate_parameters_ex(dsa, DSA_KEY_LENGTH, NULL, 0, NULL, NULL, NULL)) {
		printf("Parameters could not be generated.\n");
		return 1;
	}

	if (!DSA_generate_key(dsa)) {
		printf("Keys could not be generated.\n");
		return 1;
	}
	// init setup sign verify
	BN_CTX* bn_ctx = BN_CTX_new();

	unsigned char* msg, * msg_d, * sigret;
	sigret = malloc(DSA_size(dsa));
	msg = malloc(MSG_LEN);
	msg_d = malloc(HASH_LENGTH);

	// OpenSSL 1.1.1. DSA struct is opaque, cannot access members
	// dsa->kinvp = NULL;
	// dsa->rp = NULL;

	for (int i = -10; i < TEST_SIZE; i++) {

		srand(time(NULL));
		ts set_b, set_e, sgn_b, sgn_e, ver_b, ver_e;
		unsigned int siglen = 0;

		/* 
			OpenSSL 1.1.1 
			DSA_sign_setup() is defined only for backward binary compatibility and 
			should not be used. Since OpenSSL 1.1.0 the DSA type is opaque and the
			output of DSA_sign_setup() cannot be used anyway: calling this function
			will only cause overhead, and does not affect the actual signature
			(pre-)computation.
		*/
		clock_gettime(CLOCK_MONOTONIC, &set_b);
		// if (!DSA_sign_setup(dsa, bn_ctx, &(dsa->kinv), &(dsa->r))) {
		// 	printf("Sign setup error.\n");
		// 	return 1;
		// }
		clock_gettime(CLOCK_MONOTONIC, &set_e);

		for (int i = 0; i < MSG_LEN; i++) {
			msg[i] = '0' + (rand() & 1);
		}

		clock_gettime(CLOCK_MONOTONIC, &sgn_b);
		SHA256(msg, MSG_LEN, msg_d);
		if (!DSA_sign(DSA_TYPE_NUM, msg_d, HASH_LENGTH, sigret, &siglen, dsa)) {
			printf("Sign error.\n");
			return 1;
		}
		clock_gettime(CLOCK_MONOTONIC, &sgn_e);

		clock_gettime(CLOCK_MONOTONIC, &ver_b);
		SHA256(msg, MSG_LEN, msg_d);//rehash for time measurement
		int res = DSA_verify(DSA_TYPE_NUM, msg_d, HASH_LENGTH, sigret, siglen, dsa);
		if (res == -1) {
			printf("Verification error.\n");
			return 1;
		}
		else if (!res) {
			printf("Incorrect signature.\n");
			return 2;
		}
		clock_gettime(CLOCK_MONOTONIC, &ver_e);

		if (i >= 0)
			printf("%10llu\t%10llu\t%10llu\n", DELTA(&set_e, &set_b), DELTA(&sgn_e, &sgn_b), DELTA(&ver_e, &ver_b));

	}

	DSA_free(dsa);
	free(sigret);
	free(msg);
	free(msg_d);
	}
	else if ( sizeof(TASK_NAME) >= 5 && !memcmp(TASK_NAME, "eccoo", 5)) {
		if (argc < 4)
		{
			return ERROR("USAGE: ecc TEST_SIZE LENGTH");
		}

		typedef struct timespec ts;
		int TEST_SIZE = atoi(argv[2]);
		int MSG_LEN = atoi(argv[3]);
		
		int ret;
		ECDSA_SIG* sig;
		EC_KEY* eckey;

		eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

		if (eckey == NULL || EC_KEY_generate_key(eckey) == 0 )
		{
			printf("Error in key generation...");
			return 1;
		}


		if (argc < 3) {
			printf("USAGE TEST_SIZE BITS MSG_LEN\n");
			return 1;
		}

		
		// init setup sign verify
		BN_CTX* bn_ctx = BN_CTX_new();

		unsigned char* msg, * msg_d;
		msg = malloc(MSG_LEN);
		msg_d = malloc(HASH_LENGTH);

		BIGNUM *kinv = NULL;
		BIGNUM *rp = NULL;




		for (int i = -10; i < TEST_SIZE; i++) {

			srand(time(NULL));
			ts set_b, set_e, sgn_b, sgn_e, ver_b, ver_e;
			unsigned int siglen = 0;

			clock_gettime(CLOCK_MONOTONIC, &set_b);
			if (!ECDSA_sign_setup(eckey, bn_ctx, &kinv, &rp)) {
				printf("Sign setup error.\n");
				return 1;
			}
			clock_gettime(CLOCK_MONOTONIC, &set_e);

			for (int i = 0; i < MSG_LEN; i++) {
				msg[i] = rand() % 256;
			}

			clock_gettime(CLOCK_MONOTONIC, &sgn_b);
			SHA256(msg, MSG_LEN, msg_d);
			sig = ECDSA_do_sign_ex(msg_d, HASH_LENGTH, kinv, rp, eckey);
			if (sig == NULL) {
				printf("Sign Error!");
				return 1;
			}
			clock_gettime(CLOCK_MONOTONIC, &sgn_e);

			clock_gettime(CLOCK_MONOTONIC, &ver_b);
			SHA256(msg, MSG_LEN, msg_d);//rehash for time measurement
			int res = ECDSA_do_verify(msg_d, HASH_LENGTH, sig, eckey);
			if (res == -1) {
				printf("Verification error.\n");
				return 1;
			}
			else if (!res) {
				printf("Incorrect signature.\n");
				return 2;
			}
			clock_gettime(CLOCK_MONOTONIC, &ver_e);

			if (i >= 0)
				printf("%10llu\t%10llu\t%10llu\n", DELTA(&set_e, &set_b), DELTA(&sgn_e, &sgn_b), DELTA(&ver_e, &ver_b));
			ECDSA_SIG_free(sig);
		}

		free(msg);
		free(msg_d);

		
	}
	else if (!memcmp(TASK_NAME, "gen",3)) {

		if (argc < 5) {
			return ERROR("USAGE: gen TEST_SIZE TREE_HEIGHT MESSAGE_LEN ");
		}
		uint32_t TEST_SIZE = atoi(argv[2]);
		uint32_t TREE_HEIGHT = atoi(argv[3]);
		uint32_t MESSAGE_LEN = atoi(argv[4]);
		uint32_t num_leave = 1 << TREE_HEIGHT;

		FILE* f = fopen("data", "wb+");
		if (f == NULL) {
			return ERROR("OUTPUT FILE ERROR");
		}
		
		fwrite(&MESSAGE_LEN, sizeof(uint32_t), 1, f);
		
		mt_t* mt = mt_create(TREE_HEIGHT, DATA_TYPE_SIZE);
		uint32_t buf_len =  3 * DATA_TYPE_SIZE * (1 << TREE_HEIGHT);
		uint8_t* buffer = malloc(buf_len);
		uint8_t* message = malloc(MESSAGE_LEN );

		for ( uint32_t T = 0;  T < TEST_SIZE;) {

			for (uint32_t i = 0; i < buf_len; i++) {
				buffer[i] =  random() % 256;
			}

			mt_build(mt, buffer);
			if (DEBUG_TEST) mt_print(mt);
			fwrite(mt_get_root_digest(mt), 1, HASH_LENGTH, f);
			uint32_t msg_count = min(TEST_SIZE - T, num_leave / (MESSAGE_LEN) );
			fwrite(&msg_count, sizeof(uint32_t), 1, f);
			
			for (uint32_t M = 0; M < msg_count; M++, T++) {
				message[0] = 'B';
				for (uint32_t i = 1; i < MESSAGE_LEN - 1; i++) {
					message[i] = '1'; //+ (rand() ^ 1);
				}
				message[MESSAGE_LEN - 1] = 'B';

				uint32_t proof_len;
				clock_gettime(CLOCK_MONOTONIC, &meas_begin);
				uint8_t* pp = mt_generate_proof(mt, message, MESSAGE_LEN, &proof_len);
				clock_gettime(CLOCK_MONOTONIC, &meas_end);
				//printf("Proof Length: %u\n", proof_len);
				LOG(&meas_end, &meas_begin);
				fwrite(&proof_len, sizeof(uint32_t), 1, f);
				fwrite(pp, 1, proof_len, f);
				fwrite(message, 1, MESSAGE_LEN, f);
				free(pp);

			}
			
		}

		free(message);
		free(buffer);
		mt_delete(mt);
		fclose(f);
	}  
	else if (!memcmp(TASK_NAME, "gef", 3)) {
		if (argc < 5) {
			return ERROR("USAGE: gef TEST_SIZE TREE_HEIGHT MESSAGE_LEN ");
		}
		uint32_t TEST_SIZE = atoi(argv[2]);
		uint32_t TREE_HEIGHT = atoi(argv[3]);
		uint32_t MESSAGE_LEN = atoi(argv[4]);
		uint32_t num_leave = 1 << TREE_HEIGHT;

		FILE* f = fopen("data", "wb+");
		if (f == NULL) {
			return ERROR("OUTPUT FILE ERROR");
		}

		fwrite(&MESSAGE_LEN, sizeof(uint32_t), 1, f);

		mt_t* mt = mt_create(TREE_HEIGHT, DATA_TYPE_SIZE);
		uint32_t buf_len = 3 * DATA_TYPE_SIZE * (1 << TREE_HEIGHT);
		uint8_t* buffer = malloc(buf_len);
		uint8_t* message = malloc(MESSAGE_LEN);

		for (uint32_t T = 0; T < TEST_SIZE;) {

			for (uint32_t i = 0; i < buf_len; i++) {
				buffer[i] = random() % 256;//31;//random();//31;// random();
			}

			mt_build(mt, buffer);
			fwrite(mt_get_root_digest(mt), 1, HASH_LENGTH, f);
			uint32_t msg_count = min(TEST_SIZE - T, num_leave / (MESSAGE_LEN));
			fwrite(&msg_count, sizeof(uint32_t), 1, f);

			for (uint32_t M = 0; M < msg_count; M++, T++) {
				message[0] = 'B';
				for (uint32_t i = 1; i < MESSAGE_LEN - 1; i++) {
					message[i] = '0'; //+ (rand() ^ 1);
				}
				message[MESSAGE_LEN - 1] = 'B';

				uint32_t proof_len;
				clock_gettime(CLOCK_MONOTONIC, &meas_begin);
				uint8_t* pp = mt_generate_eff_proof(mt, message, MESSAGE_LEN, &proof_len);
				clock_gettime(CLOCK_MONOTONIC, &meas_end);
				LOG(&meas_end, &meas_begin);
				fwrite(&proof_len, sizeof(uint32_t), 1, f);
				fwrite(pp, 1, proof_len, f);
				fwrite(message, 1, MESSAGE_LEN, f);
				free(pp);

			}

		}

		free(message);
		free(buffer);
		mt_delete(mt);
		fclose(f);
	}
	else if (!memcmp(TASK_NAME, "ver",3)) {
		FILE* f = fopen("data", "rb");
		if (f == NULL) {
			return ERROR("Run \'gen\' first.");
		}
		int read_size = 0; //unused

		uint32_t MESSAGE_LEN;
		read_size = fread(&MESSAGE_LEN, sizeof(uint32_t), 1, f);
		uint8_t* message_buf = malloc(MESSAGE_LEN);
		uint8_t* root_digest = malloc(HASH_LENGTH);

		while (HASH_LENGTH == fread(root_digest, 1,  HASH_LENGTH, f)) {
			uint32_t msg_count;
			read_size = fread(&msg_count, sizeof(uint32_t), 1, f);
			

			for (int msg = 0; msg < msg_count; msg++) {
				uint32_t proof_len;
				read_size = fread(&proof_len, sizeof(uint32_t), 1, f);
				

				uint8_t* pp = malloc(proof_len);
				read_size = fread(pp, 1, proof_len, f);
				read_size = fread(message_buf, 1, MESSAGE_LEN, f);

				if (DEBUG_TEST) {
					printf("Retrieved proof:\n");
					mt_al_print_hex_buffer(pp, proof_len);
					printf("\n");
				}
				clock_gettime(CLOCK_MONOTONIC, &meas_begin);
				if (mt_verify_proof(root_digest, message_buf, MESSAGE_LEN, pp, proof_len, DATA_TYPE_SIZE)) {
					return ERROR("message denied");
				}
				clock_gettime(CLOCK_MONOTONIC, &meas_end);
				LOG(&meas_end, &meas_begin);
				free(pp);

			}
		}

		free(message_buf);
		free(root_digest);
		fclose(f);
	} 
	else if (!memcmp(TASK_NAME, "vef", 3)) {
		FILE* f = fopen("data", "rb");
		if (f == NULL) {
			return ERROR("Run \'gen\' first.");
		}

		uint32_t MESSAGE_LEN;
		int read_size = 0; // unused
		read_size = fread(&MESSAGE_LEN, sizeof(uint32_t), 1, f);
		uint8_t* message_buf = malloc(MESSAGE_LEN);
		uint8_t* root_digest = malloc(HASH_LENGTH);

		while (HASH_LENGTH == fread(root_digest, 1, HASH_LENGTH, f)) {
			uint32_t msg_count;
			read_size = fread(&msg_count, sizeof(uint32_t), 1, f);

			mt_queue_t* state = mt_queue_create();

			for (int msg = 0; msg < msg_count; msg++) {
				uint32_t proof_len;
				read_size = fread(&proof_len, sizeof(uint32_t), 1, f);


				uint8_t* pp = malloc(proof_len);
				read_size = fread(pp, 1, proof_len, f);
				read_size = fread(message_buf, 1, MESSAGE_LEN, f);


				clock_gettime(CLOCK_MONOTONIC, &meas_begin);
				if (mt_verify_eff_proof(&state,root_digest, message_buf, MESSAGE_LEN, pp, proof_len, DATA_TYPE_SIZE)) {
					return ERROR("message denied");
				}
				
				clock_gettime(CLOCK_MONOTONIC, &meas_end);
				LOG(&meas_end, &meas_begin);
				free(pp);

			}

			if (!state) {
				mt_queue_free(state);
			}
		}

		// free the queue later
		free(message_buf);
		free(root_digest);
		fclose(f);
	}
	else if (!memcmp(TASK_NAME, "vff", 3)) {
		if (argc < 3) {
			return ERROR("USAGE: vff TREE_HEIGHT");
			// encode this into data file later
		}

		int TREE_HEIGHT = atoi(argv[2]);

		FILE* f = fopen("data", "rb");
		if (f == NULL) {
			return ERROR("Run \'gen\' first.");
		}

		uint32_t MESSAGE_LEN;
		int read_size = 0; // unused
		read_size = fread(&MESSAGE_LEN, sizeof(uint32_t), 1, f);
		uint8_t* message_buf = malloc(MESSAGE_LEN);
		uint8_t* root_digest = malloc(HASH_LENGTH);//mt_state->level[mt_state->levels]->mtdatalist->data_digest;
		
		
		while (HASH_LENGTH == fread(root_digest, 1, HASH_LENGTH, f)) {
			
			mt_t* mt_state = mt_create_lazy(TREE_HEIGHT);
			mt_state->level[mt_state->levels]->mtdatalist->data_digest = malloc(HASH_LENGTH);
			memcpy(mt_state->level[mt_state->levels]->mtdatalist->data_digest, root_digest, HASH_LENGTH);

			uint32_t msg_count;
			read_size = fread(&msg_count, sizeof(uint32_t), 1, f);
			

			for (int msg = 0; msg < msg_count; msg++) {
				uint32_t proof_len;
				read_size = fread(&proof_len, sizeof(uint32_t), 1, f);


				uint8_t* pp = malloc(proof_len);
				read_size = fread(pp, 1, proof_len, f);
				read_size = fread(message_buf, 1, MESSAGE_LEN, f);

				if (DEBUG_TEST) {
					printf("Retrieved proof:\n");
					mt_al_print_hex_buffer(pp, proof_len);
					printf("\n");
				}

				clock_gettime(CLOCK_MONOTONIC, &meas_begin);
				if (mt_verify_meff_proof(mt_state, message_buf, MESSAGE_LEN, pp, proof_len, DATA_TYPE_SIZE)) {
					return ERROR("message denied");
				}
				else if (DEBUG_TEST) {
					printf("message approved.\n");
				}
				clock_gettime(CLOCK_MONOTONIC, &meas_end);
				LOG(&meas_end, &meas_begin);
				free(pp);

				if ( DEBUG_TEST ) mt_print(mt_state);

			}
			mt_delete(mt_state);

		}

		free(message_buf);
		fclose(f);
	}
	else {
		return ERROR("no such task");
	}
	
	return 0;
}

