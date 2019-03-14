#ifndef CIPHERGLOBALS_H
#define CIPHERGLOBALS_H

///
/// \file
/// \author	Niklas Dallmann
/// \brief	CRYPTO's utility header.
/// \since	1.0
///

#ifdef CRYPTO_NO_DEBUG
#define INFO(text)
#define DEBUG(text)
#define WARN(text)
#define ERROR(text)
#else

#include <bitset>
#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <type_traits>

#include "aesconstants.h"

///
/// \internal
/// 
/// \brief	Implements CRYPTO's info output.
/// 
/// \since	3.0
///
#define INFO(text) \
	std::cout << "[\x1B[34mINFO\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements CRYPTO's debug output.
/// 
/// \since	3.0
///
#define DEBUG(text) \
	std::cout << "[\x1B[36mDEBUG\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements CRYPTO's warning output.
/// 
/// \since	3.0
///
#define WARN(text) \
	std::cout << "[\x1B[33mWARN\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements CRYPTO's error output.
/// 
/// \since	3.0
///
#define ERROR(text) \
	std::cout << "[\x1B[31mERROR\x1B[0m]	" << text << std::endl;

#endif

///
/// \internal
/// 
/// \brief	Signalizes the compiler that \a arg is intentionally unused.
/// 
/// \since	1.0
///
#define CRYPTO_UNUSED(arg) (void)arg;

#ifdef __AVX2__
///
/// \internal
/// 
/// \brief	Defined if compiler and platform support AVX2.
/// 
/// \since	1.0
///
#define CRYPTO_AVX2_SUPPORT
#endif

#ifdef __SSE2__
///
/// \internal
/// 
/// \brief	Defined if compiler and platform support AVX2.
/// 
/// \since	1.0
///
#define CRYPTO_SSE2_SUPPORT
#endif

#if defined(__GNUC__) && !defined(__clang__)
///
/// \brief	Defined if compiler is GCC.
/// 
/// \since	1.0
///
#define CRYPTO_COMPILER_GCC

#elif defined(__clang__)
///
/// \brief	Defined if compiler is Clang.
/// 
/// \since	1.0
///
#define CRYPTO_COMPILER_CLANG

#elif defined(_MSC_VER)
///
/// \brief	Defined if compiler is MSVC.
/// 
/// \since	1.0
///
#define CRYPTO_COMPILER_MSVC
#endif

#if defined(CRYPTO_COMPILER_GCC) && !defined(CRYPTO_LITTLE_ENDIAN)
#define CRYPTO_LITTLE_ENDIAN
#endif

static inline void safeSetZero(void *source, size_t size)
{
#ifdef CRYPTO_COMPILER_GCC
		explicit_bzero(source, size);
#elif
		static_assert (false, "Compiler not supported.");
#endif
}

template <typename T>
T rotateLeft(T value, size_t bitCount)
{
	static_assert (std::is_integral<T>::value, "Type is no integral type");
	
	return (value << bitCount | value >> (((sizeof (T) * 8)) - bitCount));
}

template <typename T>
T rotateRight(T value, size_t bitCount)
{
	static_assert (std::is_integral<T>::value, "Type is no integral type");
	
	return (value >> bitCount | value << (((sizeof (T) * 8)) - bitCount));
}

template <typename T>
inline T changeEndianness(const T value);

template <>
inline uint32_t changeEndianness<uint32_t>(const uint32_t value)
{
#if defined(CRYPTO_LITTLE_ENDIAN) && defined(CRYPTO_COMPILER_GCC)
	return __builtin_bswap32(value);
#else
	return value;
#endif
}

template <>
inline uint64_t changeEndianness<uint64_t>(const uint64_t value)
{
#if defined(CRYPTO_LITTLE_ENDIAN) && defined(CRYPTO_COMPILER_GCC)
	return __builtin_bswap64(value);
#else
	return value;
#endif
}

#endif // CIPHERGLOBALS_H
