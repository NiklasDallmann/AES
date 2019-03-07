#include <iostream>
#include <stdint.h>

#include "primitiveblock.h"
#include "utilities.h"

int main()
{
	uint8_t input[] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};
	
	uint8_t output[sizeof (input)];
	
	uint8_t key[] {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	
	INFO("PLAINTEXT")
	printBuffer(input, 16);
	
	INFO("KEY")
	printBuffer(key, 16);
	
	Aes::PrimitiveBlock<AES_128_KEY_SIZE> block(&key[0]);
	
	block.encrypt(&input[0], &output[0]);
	
	WARN("KEY MUST BE ZEROED")
	printBuffer(key, 16);
	
	INFO("CIPHERTEXT")
	printBuffer(output, 16);
	
	block.decrypt(&output[0], &input[0]);
	
	INFO("PLAINTEXT")
	printBuffer(input, 16);
	
	return 0;
}
