#ifndef CTR_H
#define CTR_H

#include <emmintrin.h>
#include <stdint.h>
#include <string.h>

#include "block.h"
#include "key.h"
#include "mode.h"
#include "utilities.h"

namespace Aes::Mode
{

template <uint8_t keySize>
class Ctr
{
	Ctr() = delete;
	~Ctr() = delete;
	
	static void encrypt(const Key<keySize> &key, const uint8_t *plaintext, const size_t size, uint8_t **ciphertext)
	{
		Block<keySize> block(key);
		
		// Calculate block count
		uint64_t blockCount = calculateBlockCount(size);
		
		// Allocate storage for ciphertext
		*ciphertext = new uint8_t[blockCount * AES_BLOCK_SIZE];
		
		// Iterate through blocks and encrypt plaintext
		for (uint64_t blockIndex = 0; blockIndex < blockCount; blockIndex++)
		{
			uint8_t outputBlock[AES_BLOCK_SIZE];
			uint8_t plainBlock[AES_BLOCK_SIZE];
			uint8_t counter[AES_BLOCK_SIZE];
			
			*reinterpret_cast<uint64_t *>(counter) = blockIndex;
			memcpy(plainBlock, plaintext + blockIndex * sizeof (uint32_t), AES_BLOCK_SIZE * sizeof (uint32_t));
			
			block.encrypt(counter, outputBlock);
			
			
		}
	}
	
	static void decrypt(const Key<keySize> &key, const uint8_t *ciphertext, const size_t size, uint8_t **plaintext)
	{
		Block<keySize> block(key);
		
		// Calculate block count
		uint64_t blockCount = calculateBlockCount(size);
		
		// Allocate storage for plaintext
		*plaintext = new uint8_t[blockCount * AES_BLOCK_SIZE];
		
		// Iterate through blocks and decrypt ciphertext
		for (size_t blockIndex = 0; blockIndex < blockCount; blockIndex++)
		{
			block.decrypt(ciphertext + AES_BLOCK_SIZE * sizeof (uint32_t), *plaintext + AES_BLOCK_SIZE * sizeof (uint32_t));
		}
	}
};

} // namespace Aes::Mode

#endif // CTR_H
