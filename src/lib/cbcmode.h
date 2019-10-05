#ifndef CBCMODE_H
#define CBCMODE_H

#include <stdint.h>
#include <string.h>

#include "cipherkey.h"
#include "ciphermode.h"
#include "cryptoutilities.h"
#include "paddingtype.h"

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
class Cbc
{
public:
	using KeyType = typename BlockType::KeyType;
	
	Cbc() = delete;
	~Cbc() = delete;
	
	static void encrypt(const KeyType &key, const uint8_t *initializationVector, const uint8_t *plaintext, const size_t size, uint8_t *ciphertext,
						const PaddingType padding = PaddingType::Nulls)
	{
		BlockType block(key);
		
		// Calculate block count
		uint64_t blockCount = calculateBlockCount<BlockType>(size);
		
		// Encrypt first complete block
		if (blockCount > 0)
		{
			
		}
		
		// Encrypt intermediate blocks
		for (uint64_t blockIndex = 0; blockIndex < blockCount - 1; blockIndex++)
		{
			uint8_t cipherBlock[BlockType::TraitsType::blockSize];
			uint8_t plainBlock[BlockType::TraitsType::blockSize];
			
			// Copy current plaintext block
			memcpy(plainBlock, plaintext + blockIndex * sizeof (plainBlock), sizeof (plainBlock));
			
			// Copy initialization vector in counter
			memcpy(cipherBlock, initializationVector, (BlockType::TraitsType::blockSize));
		}
		
		// Encrypt last possibly incomplete block
		if (blockCount == 0)
		{
			
		}
		else
		{
			
		}
	}
	
	static void decrypt(const KeyType &key, const uint8_t *initializationVector, const uint8_t *ciphertext, const size_t size, uint8_t *plaintext,
						const PaddingType padding = PaddingType::Nulls)
	{
		
	}
};

} // namespace Crypto::Mode

#endif // CBCMODE_H
