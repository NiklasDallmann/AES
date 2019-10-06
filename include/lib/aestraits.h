#ifndef AESTRAITS_H
#define AESTRAITS_H

#include <stdint.h>

#include "aesconstants.h"

namespace Crypto::BlockCipher::Aes
{

template <uint8_t keySize>
struct Traits;

template <>
struct Traits<AES_128_KEY_SIZE>
{
	static constexpr uint8_t blockSize = AES_BLOCK_SIZE;
	static constexpr uint8_t keySize = AES_128_KEY_SIZE;
	static constexpr uint8_t rounds = AES_128_ROUND_COUNT;
};

template <>
struct Traits<AES_192_KEY_SIZE>
{
	static constexpr uint8_t blockSize = AES_BLOCK_SIZE;
	static constexpr uint8_t keySize = AES_192_KEY_SIZE;
	static constexpr uint8_t rounds = AES_192_ROUND_COUNT;
};

template <>
struct Traits<AES_256_KEY_SIZE>
{
	static constexpr uint8_t blockSize = AES_BLOCK_SIZE;
	static constexpr uint8_t keySize = AES_256_KEY_SIZE;
	static constexpr uint8_t rounds = AES_256_ROUND_COUNT;
};

} // namespace Crypto::BlockCipher::Aes

#endif // AESTRAITS_H
