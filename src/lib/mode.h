#ifndef MODE_H
#define MODE_H

#include <stdint.h>
#include <stddef.h>

#include "constants.h"

namespace Aes::Mode
{

static inline size_t calculateBlockCount(const size_t size)
{
	size_t returnValue = (size / (AES_BLOCK_SIZE * sizeof (uint32_t)));
	
	if (size % (AES_BLOCK_SIZE * sizeof (uint32_t)) != 0)
	{
		returnValue++;
	}
	
	return returnValue;
}

} // namespace Aes::Mode

#endif // MODE_H
