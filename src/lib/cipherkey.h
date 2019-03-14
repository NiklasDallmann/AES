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
		memcpy(this->key, key, keySize);
	}
	
	Key(const Key &other)
	{
		*this = other;
	}
	
	~Key()
	{
		safeSetZero(this->key, keySize);
	}
	
	Key &operator=(const Key &other)
	{
		memcpy(this->key, other.key, keySize);
		
		return *this;
	}
	
	uint8_t key[keySize];
};

} // namespace Crypto

#endif // CIPHERKEY_H
