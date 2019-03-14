#ifndef SHA2TRAITS_H
#define SHA2TRAITS_H

#include <stdint.h>

#include "sha2constants.h"

namespace Crypto::Hash::Sha2
{

template <uint32_t outputSize>
struct Traits;

template <>
struct Traits<SHA224_DIGEST_SIZE>
{
	using WordType = uint32_t;
	static constexpr uint32_t digestSize = SHA224_DIGEST_SIZE;
	static constexpr uint32_t blockSize = 512;
};

template <>
struct Traits<SHA256_DIGEST_SIZE>
{
	using WordType = uint32_t;
	static constexpr uint32_t digestSize = SHA256_DIGEST_SIZE;
	static constexpr uint32_t blockSize = 512;
};

template <>
struct Traits<SHA384_DIGEST_SIZE>
{
	using WordType = uint64_t;
	static constexpr uint32_t digestSize = SHA384_DIGEST_SIZE;
	static constexpr uint32_t blockSize = 1024;
};

template <>
struct Traits<SHA512_DIGEST_SIZE>
{
	using WordType = uint64_t;
	static constexpr uint32_t digestSize = SHA512_DIGEST_SIZE;
	static constexpr uint32_t blockSize = 1024;
};

} // namespace Hash

#endif // SHA2TRAITS_H
