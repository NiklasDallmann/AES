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
public:
	Ctr() = delete;
	~Ctr() = delete;
	
	static void encrypt(const Key<keySize> &key, const uint8_t *initializationVector, const uint8_t *plaintext, const size_t size, uint8_t *ciphertext)
	{
		Block<keySize> block(key);
		
		// Calculate block count
		uint64_t blockCount = calculateBlockCount(size);
		
		// Iterate through the first n-1 blocks and encrypt plaintext
#pragma omp parallel for schedule(static, 4)
		for (uint64_t blockIndex = 0; blockIndex < blockCount - 1; blockIndex++)
		{
			Block<keySize> localBlock = block;
			uint8_t outputBlock[AES_BLOCK_SIZE * sizeof (uint32_t)];
			uint8_t plainBlock[AES_BLOCK_SIZE * sizeof (uint32_t)];
			uint8_t counter[AES_BLOCK_SIZE * sizeof (uint32_t)];
			
			// Copy current plaintext block
			memcpy(plainBlock, plaintext + blockIndex * sizeof (plainBlock), sizeof (plainBlock));
			
			// Copy initialization vector in counter
			memcpy(counter, initializationVector, (AES_BLOCK_SIZE * sizeof (uint32_t)));
			
			// Set lower half of counter with block index, i.e. the actual counter
			*(reinterpret_cast<uint64_t *>(counter) + 1) = changeEndianness(changeEndianness(*(reinterpret_cast<uint64_t *>(counter) + 1)) + blockIndex);
			
			// Encrypt counter
			block.encrypt(counter, outputBlock);
			
			// XOR output block with plain block and write to ciphertext
			for (uint8_t byte = 0; byte < sizeof (plainBlock); byte++)
			{
				ciphertext[byte + sizeof (plainBlock) * blockIndex] = plainBlock[byte] ^ outputBlock[byte];
			}
		}
		
		// Encrypt last possibly incomplete block
		Block<keySize> localBlock = block;
		uint8_t outputBlock[AES_BLOCK_SIZE * sizeof (uint32_t)];
		uint8_t plainBlock[AES_BLOCK_SIZE * sizeof (uint32_t)];
		uint8_t counter[AES_BLOCK_SIZE * sizeof (uint32_t)];
		
		// Copy current plaintext block
		memcpy(plainBlock, plaintext + (blockCount - 1) * sizeof (plainBlock), sizeof (plainBlock));
		
		// Copy initialization vector in counter
		memcpy(counter, initializationVector, (AES_BLOCK_SIZE * sizeof (uint32_t)));
		
		// Set lower half of counter with block index, i.e. the actual counter
		*(reinterpret_cast<uint64_t *>(counter) + 1) = changeEndianness(changeEndianness(*(reinterpret_cast<uint64_t *>(counter) + 1)) + (blockCount - 1));
		
		// Encrypt counter
		block.encrypt(counter, outputBlock);
		
		// XOR output block with plain block and write to ciphertext
		uint8_t remainingBytes = uint8_t(size - (sizeof (plainBlock) * (blockCount - 1)));
		for (uint8_t byte = 0; byte < remainingBytes; byte++)
		{
			ciphertext[byte + sizeof (plainBlock) * (blockCount - 1)] = plainBlock[byte] ^ outputBlock[byte];
		}
	}
	
	static void decrypt(const Key<keySize> &key, const uint8_t *initializationVector, const uint8_t *ciphertext, const size_t size, uint8_t *plaintext)
	{
		// CTR mode uses encryption for decryption
		encrypt(key, initializationVector, ciphertext, size, plaintext);
	}
};

using Ctr128 = Ctr<AES_128_KEY_SIZE>;
using Ctr192 = Ctr<AES_192_KEY_SIZE>;
using Ctr256 = Ctr<AES_256_KEY_SIZE>;

} // namespace Aes::Mode

#endif // CTR_H
