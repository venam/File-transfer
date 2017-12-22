#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define ARRAYSIZE(x) (sizeof(x)/sizeof(*x))

struct enc_op {
	unsigned char right;
	unsigned char (*op)(unsigned char, unsigned char);
};

unsigned char
xor(unsigned char a, unsigned char b)
{
	return a^b;
}

unsigned char
not(unsigned char a, unsigned char b)
{
	return xor(a,0b11111111);
}

unsigned char
ror(unsigned char val, unsigned char r_bits)
{
	r_bits %= 8;
	return (val >> r_bits) | (val << (8-r_bits));
}

unsigned char
rol(unsigned char val, unsigned char r_bits)
{
	r_bits %= 8;
	return (val << r_bits) | (val  >> (8-r_bits));
}

struct enc_op*
interpret_enc(char encryption_scheme[], int decrypt)
{
	char *str2;
	char *token, *subtoken;
	char *saveptr1, *saveptr2;
	int nb_enc_op = 0;
	struct enc_op* enc_operations = calloc(sizeof(struct enc_op),255);

	for (token = strtok_r(encryption_scheme, ";", &saveptr1);
		token != NULL;
		token = strtok_r(NULL, ";", &saveptr1)) {

		int nb_iter = 0;
		unsigned char right = 0;
		unsigned char (*foo)(unsigned char, unsigned char) = NULL;

		str2 = token;
		char *operation = strtok_r(str2, ":", &saveptr2);
		if (operation == NULL) {
			puts("couldn't split on :\n");
			return NULL;
		}
		subtoken = strtok_r(NULL, ":", &saveptr2);
		if (subtoken == NULL) {
			puts("couldn't split on :\n");
			return NULL;
		}
		nb_iter = atoi(subtoken);
		if (strncmp(operation, "^", 1) == 0) {
			foo = xor;
			char right_str[10];
			memcpy(right_str, &operation[1], 9);
			right_str[10] = '\0';
			right = atoi(right_str);
		} else if (strncmp(operation, "~", 1) == 0) {
			foo = not;
			right = 0;
		} else if (strncmp(operation, "ror", 3) == 0) {
			if (decrypt) {
				foo = rol;
			} else {
				foo = ror;
			}
			char right_str[10];
			memcpy(right_str, &operation[3], 9);
			right_str[10] = '\0';
			right = atoi(right_str);
		} else if (strncmp(operation, "rol", 3) == 0) {
			if (decrypt) {
				foo = ror;
			} else {
				foo = rol;
			}
			char right_str[10];
			memcpy(right_str, &operation[3], 9);
			right_str[10] = '\0';
			right = atoi(right_str);
		}

		struct enc_op ep;
		ep.right = right;
		ep.op = foo;

		int i;
		for (i=0; i< nb_iter; i++) {
			if (nb_enc_op % 254 == 0) {
				enc_operations = realloc(enc_operations, nb_enc_op+255);
			}
			enc_operations[nb_enc_op] = ep;
			nb_enc_op++;
		}
	}

	struct enc_op ep;
	ep.right = 10;
	ep.op = NULL;
	enc_operations[nb_enc_op] = ep;

	return enc_operations;
}

char*
_encrypt(char* message, char* encryption_scheme, int decrypt)
{
	int i;
	int op_index = 0;
	int nb_op = 0;
	struct enc_op* enc_operations = NULL;
	char* encrypted = malloc(sizeof(message));

	char *encryption_scheme_cpy = malloc(sizeof(encryption_scheme));
	strcpy(encryption_scheme_cpy, encryption_scheme);
	enc_operations = interpret_enc(encryption_scheme_cpy, decrypt);
	if (enc_operations == NULL) {
		return message;
	}

	for (i = 0; enc_operations[i].op != NULL; i++) {
		nb_op++;
	}

	for (i = 0; i < strlen(message); i++) {
		op_index %= nb_op;
		encrypted[i] = enc_operations[op_index].op(
			message[i],
			enc_operations[op_index].right
		);
		op_index++;
	}

	return encrypted;
}

char*
encrypt(char* message, char* encryption_scheme) {
	return _encrypt(message, encryption_scheme, 0);
}


char*
decrypt(char* message, char* encryption_scheme)
{
	return _encrypt(message, encryption_scheme, 1);
}

int
main(int argc, char** argv)
{
	char enc[200] = "ror2:1;~:1;rol2:2";
	char *encrypted = encrypt("hello world", enc);
	puts(encrypted);
	char *decrypted = decrypt(encrypted, enc);
	puts(decrypted);

	return 0;
}

