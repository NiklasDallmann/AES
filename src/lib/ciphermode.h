#ifndef CIPHERMODE_H
#define CIPHERMODE_H

#include <stdint.h>
#include <stddef.h>

namespace Crypto::Mode
{

template <typename BlockType>
static inline size_t calculateBlockCount(const size_t size)
{
	size_t returnValue = (size / (BlockType::TraitsType::keySize * sizeof (uint32_t)));
	
	if (size % (BlockType::TraitsType::keySize * sizeof (uint32_t)) != 0)
	{
		returnValue++;
	}
	
	return returnValue;
}

} // namespace Crypto::Mode

#endif // CIPHERMODE_H
