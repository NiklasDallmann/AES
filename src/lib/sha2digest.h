#ifndef SHA2DIGEST_H
#define SHA2DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "cryptoglobals.h"
#include "sha2constants.h"
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
		uint8_t localBlock[TraitsType::blockSize];
		
		this->_paddBlock(localBlock, block, size);
		
		this->update(localBlock);
	}
	
	///
	/// \brief	Hashes \a message with a size of an arbitraty \a messageSize.
	/// 
	/// \since	1.0
	///
	void hash(const uint8_t *message, const size_t messageSize)
	{
		const size_t blocks = messageSize / TraitsType::blockSize;
		const size_t remainingBytes = messageSize % TraitsType::blockSize;
		
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
		memcpy(digest, reinterpret_cast<uint8_t *>(this->_state), TraitsType::digestSize);
	}
	
private:
	using WordType = typename TraitsType::WordType;
	WordType _state[TraitsType::stateSize];
	
	void _initializeState();
	static void _paddBlock(uint8_t *paddedBlock, size_t *paddedSize, const uint8_t *block, const size_t size);
};

} // namespace Crypto::Hash::Sha2

#endif // SHA2DIGEST_H
