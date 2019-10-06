#ifndef CTRMODE_H
#define CTRMODE_H

#include <stdint.h>
#include <string.h>

#include "cipherkey.h"
#include "ciphermode.h"
#include "cryptoutilities.h"

///
/// \brief	Contains implementations of block cipher modes.
/// 
/// \since	1.0
///
namespace Crypto::Mode
{

///
/// \brief	Implements the counter (CTR) mode for \a BlockType.
/// 
/// \since	1.0
///
template <typename BlockType>
class Ctr
{
public:
	using KeyType = typename BlockType::KeyType;
	
	Ctr() = delete;
	~Ctr() = delete;
	
	static void encrypt(const KeyType &key, const uint8_t *initializationVector, const uint8_t *plaintext, const size_t size, uint8_t *ciphertext)
	{
		BlockType block(key);
		
		// Calculate block count
		uint64_t blockCount = calculateBlockCount<BlockType>(size);
		
		// Iterate through the first n-1 blocks and encrypt plaintext
#pragma omp parallel for schedule(static)
		for (uint64_t blockIndex = 0; blockIndex < blockCount - 1; blockIndex++)
		{
			BlockType localBlock = block;
			uint8_t outputBlock[BlockType::TraitsType::blockSize];
			uint8_t plainBlock[BlockType::TraitsType::blockSize];
			uint8_t counter[BlockType::TraitsType::blockSize];
			
			// Copy current plaintext block
			memcpy(plainBlock, plaintext + blockIndex * sizeof (plainBlock), sizeof (plainBlock));
			
			// Copy initialization vector in counter
			memcpy(counter, initializationVector, (BlockType::TraitsType::blockSize));
			
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
		BlockType localBlock = block;
		uint8_t outputBlock[BlockType::TraitsType::blockSize];
		uint8_t plainBlock[BlockType::TraitsType::blockSize];
		uint8_t counter[BlockType::TraitsType::blockSize];
		
		// Copy current plaintext block
		memcpy(plainBlock, plaintext + (blockCount - 1) * sizeof (plainBlock), sizeof (plainBlock));
		
		// Copy initialization vector in counter
		memcpy(counter, initializationVector, BlockType::TraitsType::blockSize);
		
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
	
	static void decrypt(const KeyType &key, const uint8_t *initializationVector, const uint8_t *ciphertext, const size_t size, uint8_t *plaintext)
	{
		// CTR mode uses encryption for decryption
		encrypt(key, initializationVector, ciphertext, size, plaintext);
	}
};

} // namespace Crypto::Mode

#endif // CTRMODE_H
