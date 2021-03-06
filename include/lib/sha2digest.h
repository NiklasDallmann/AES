#ifndef SHA2DIGEST_H
#define SHA2DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "cryptoglobals.h"
#include "cryptoutilities.h"
#include "sha2traits.h"

namespace Crypto::Hash::Sha2
{

///
/// \brief	Implements the SHA2 hash algorithm for the desired \a digestSize.
/// 
/// \since	1.0
///
template <uint32_t digestSize>
class Digest
{
public:
	///
	/// \brief	The corresponding traits type.
	/// 
	/// \since	1.0
	///
	using TraitsType = Sha2::Traits<digestSize>;
	
	///
	/// \brief	Constructs the digest and initializes the internal state.
	/// 
	/// \since	1.0
	///
	Digest()
	{
		this->_initializeState();
	}
	
	///
	/// \brief	Updates the internal state using \a block.
	/// 
	///			\a block must have a size of the required block size.
	/// 
	/// \since	1.0
	///
	void update(const uint8_t *block);
	
	///
	/// \brief	Finalizes the hash using \a block of \a size.
	/// 
	///			If necessary \a block is padded to the required block size.
	/// 
	/// \since	1.0
	///
	void finalize(const uint8_t *block, const size_t size)
	{
		uint8_t paddedBlock[TraitsType::blockSize * 2];
		
		// Calculations
//		const size_t paddingBytes = (TraitsType::blockSize - sizeof (WordType) * 2) - size;
		const size_t paddedBlockSize = (size <= (TraitsType::blockSize - sizeof (WordType) - 1)) ? TraitsType::blockSize : (TraitsType::blockSize * 2);
		
		// Word-sized pointers
		WordType *paddedBlockWords = reinterpret_cast<WordType *>(paddedBlock);
		const WordType *blockWords = reinterpret_cast<const WordType *>(block);
		
		// Set padded block zero and copy existing data from partial block
		memset(paddedBlock, '\0', sizeof (paddedBlock));
		for (size_t byte = 0; byte < size; byte++)
		{
			paddedBlock[byte] = block[byte];
		}
		
		// Set first byte after block end
		paddedBlock[size] = 0x80;
		
		// Add size to the end
		this->_messageSize += size * 8;
		*(reinterpret_cast<size_t *>(paddedBlock + (paddedBlockSize / sizeof (WordType))) - 1) = this->_messageSize;
		
		DEBUG("size added 0x" << std::hex << this->_messageSize)
		printBuffer(paddedBlock, paddedBlockSize);
		
		// Update digest
		if (paddedBlockSize == TraitsType::blockSize)
		{
			this->update(paddedBlock);
		}
		else
		{
			this->update(paddedBlock);
			this->update(paddedBlock + TraitsType::blockSize);
		}
	}
	
	///
	/// \brief	Hashes \a message with an arbitraty \a messageSize.
	/// 
	/// \since	1.0
	///
	void hash(const uint8_t *message, const size_t messageSize)
	{
		const size_t blocks = messageSize / TraitsType::blockSize;
		const size_t remainingBytes = messageSize % TraitsType::blockSize;
		
		DEBUG("blocks=" << blocks)
		DEBUG("remainingBytes=" << remainingBytes)
		
		for (size_t block = 0; block < blocks; block++)
		{
			this->update(message + block * TraitsType::blockSize);
		}
		
		this->finalize(message + blocks * TraitsType::blockSize, remainingBytes);
	}
	
	///
	/// \brief	Resets the digest to its initial state as if it were default constructed.
	/// 
	/// \since	1.0
	///
	void reset()
	{
		this->_initializeState();
	}
	
	///
	/// \brief	Copies the computed hash value into \a digest.
	/// 
	///			\a digest must be of the specified digest size.
	/// 
	/// \since	1.0
	///
	void extract(uint8_t *digest)
	{
//		memcpy(digest, reinterpret_cast<uint8_t *>(this->_state), TraitsType::digestSize);
		WordType *digestWords = reinterpret_cast<WordType *>(digest);
		
		for (size_t word = 0; word < TraitsType::stateSize; word++)
		{
			*(reinterpret_cast<WordType *>(digest) + word) = changeEndianness(this->_state[word]);
		}
	}
	
private:
	using WordType = typename TraitsType::WordType;
	WordType _state[TraitsType::stateSize];
	size_t _messageSize = 0;
	
	void _initializeState();
};

using Digest224 = Digest<SHA224_DIGEST_SIZE>;
using Digest256 = Digest<SHA256_DIGEST_SIZE>;
using Digest384 = Digest<SHA384_DIGEST_SIZE>;
using Digest512 = Digest<SHA512_DIGEST_SIZE>;

} // namespace Crypto::Hash::Sha2

#endif // SHA2DIGEST_H
