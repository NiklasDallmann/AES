#ifndef UTILITIES_H
#define UTILITIES_H


///
/// \file
/// \author	Niklas Dallmann
/// \brief	AES's utility header.
/// \since	1.0
///

#ifdef AES_NO_DEBUG
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

#include "constants.h"

///
/// \internal
/// 
/// \brief	Implements AES's info output.
/// 
/// \since	3.0
///
#define INFO(text) \
	std::cout << "[\x1B[34mINFO\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements AES's debug output.
/// 
/// \since	3.0
///
#define DEBUG(text) \
	std::cout << "[\x1B[36mDEBUG\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements AES's warning output.
/// 
/// \since	3.0
///
#define WARN(text) \
	std::cout << "[\x1B[33mWARN\x1B[0m]	" << text << std::endl;

///
/// \internal
/// 
/// \brief	Implements AES's error output.
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
#define AES_UNUSED(arg) (void)arg;

#ifdef __AVX2__
///
/// \internal
/// 
/// \brief	Defined if compiler and platform support AVX2.
/// 
/// \since	1.0
///
#define AES_AVX2_SUPPORT
#endif

#ifdef __SSE2__
///
/// \internal
/// 
/// \brief	Defined if compiler and platform support AVX2.
/// 
/// \since	1.0
///
#define AES_SSE2_SUPPORT
#endif

#if defined(__GNUC__) && !defined(__clang__)
///
/// \brief	Defined if compiler is GCC.
/// 
/// \since	1.0
///
#define AES_COMPILER_GCC

#elif defined(__clang__)
///
/// \brief	Defined if compiler is Clang.
/// 
/// \since	1.0
///
#define AES_COMPILER_CLANG

#elif defined(_MSC_VER)
///
/// \brief	Defined if compiler is MSVC.
/// 
/// \since	1.0
///
#define AES_COMPILER_MSVC
#endif

#if defined(AES_COMPILER_GCC) && !defined(AES_LITTLE_ENDIAN)
#define AES_LITTLE_ENDIAN
#endif

static inline void safeSetZero(void *source, size_t size)
{
#ifdef AES_COMPILER_GCC
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
#if defined(AES_LITTLE_ENDIAN) && defined(AES_COMPILER_GCC)
	return __builtin_bswap32(value);
#else
	return value;
#endif
}

template <>
inline uint64_t changeEndianness<uint64_t>(const uint64_t value)
{
#if defined(AES_LITTLE_ENDIAN) && defined(AES_COMPILER_GCC)
	return __builtin_bswap64(value);
#else
	return value;
#endif
}

static inline void printBuffer(const uint8_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::setw(sizeof (uint8_t) * 2) << std::setfill('0') << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

static inline void printBuffer(const uint32_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::setw(sizeof (uint32_t) * 2) << std::setfill('0') << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

static inline void printState(const uint8_t *state)
{
	uint8_t stateData[4][4];
	
	// Transform state to row-major for simpler access
	for (uint8_t row = 0; row < 4; row++)
	{
		for (uint8_t column = 0; column < 4; column++)
		{
			stateData[row][column] = state[column * 4 + row];
		}
	}
	
	// Print rows
	for (uint8_t row = 0; row < 4; row++)
	{
		printBuffer(stateData[row], 4);
	}
	
	std::cout << std::endl;
}

void generateTTable()
{
	std::stringstream table;
	
	INFO("BEGIN T TABLE")
	
	for (uint32_t a = 0; a <= 0xff; a++)
	{
		uint32_t word = 0;
		
		// Generate table entry
		uint8_t *ptr = reinterpret_cast<uint8_t *>(&word);
		
		ptr[0] = Aes::galoisMultiply_9[Aes::sBox_dec[a]];
		ptr[1] = Aes::galoisMultiply_d[Aes::sBox_dec[a]];
		ptr[2] = Aes::galoisMultiply_b[Aes::sBox_dec[a]];
		ptr[3] = Aes::galoisMultiply_e[Aes::sBox_dec[a]];
		
		word = __builtin_bswap32(word);
		
		if (a % 8 == 0 && a != 0)
		{
			table << "\n";
		}
		
		table << "0x" << std::hex << std::setw(8) << std::setfill('0') << word;
		
		if (a != 0xff)
		{
			table << ", ";
		}
	}
	
	std::cout << table.str() << std::endl;
	
	INFO("END T TABLE")
}

#endif // UTILITIES_H
