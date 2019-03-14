#ifndef CIPHERKEY_H
#define CIPHERKEY_H

#include <stdint.h>
#include <string.h>
#include <type_traits>

#include "aesconstants.h"
#include "cryptoglobals.h"

namespace Crypto
{

template <uint32_t keySize>
class Key
{
public:
	Key() = default;
	
	Key(uint8_t *key)
	{
		memcpy(this->key, key, keySize * sizeof (uint32_t));
	}
	
	Key(const Key &other)
	{
		*this = other;
	}
	
	~Key()
	{
		safeSetZero(this->key, keySize * sizeof (uint32_t));
	}
	
	Key &operator=(const Key &other)
	{
		memcpy(this->key, other.key, keySize * sizeof (uint32_t));
		
		return *this;
	}
	
	uint8_t key[keySize * sizeof (uint32_t)];
};

} // namespace Crypto

#endif // CIPHERKEY_H
