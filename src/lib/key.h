#ifndef KEY_H
#define KEY_H

#include <stdint.h>
#include <string.h>
#include <type_traits>

#include "constants.h"
#include "utilities.h"

namespace Aes
{

template <uint8_t keySize>
struct KeySizeType;

template <>
struct KeySizeType<AES_128_KEY_SIZE>
{
	static constexpr uint8_t value = AES_128_KEY_SIZE;
	static constexpr uint8_t rounds = AES_128_ROUND_COUNT;
};

template <>
struct KeySizeType<AES_192_KEY_SIZE>
{
	static constexpr uint8_t value = AES_192_KEY_SIZE;
	static constexpr uint8_t rounds = AES_192_ROUND_COUNT;
};

template <>
struct KeySizeType<AES_256_KEY_SIZE>
{
	static constexpr uint8_t value = AES_256_KEY_SIZE;
	static constexpr uint8_t rounds = AES_256_ROUND_COUNT;
};

template <uint8_t keySize>
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
	
	uint8_t key[KeySizeType<keySize>::value * sizeof (uint32_t)];
};

using Key128 = Key<AES_128_KEY_SIZE>;
using Key192 = Key<AES_192_KEY_SIZE>;
using Key256 = Key<AES_256_KEY_SIZE>;

} // namespace Aes

#endif // KEY_H
