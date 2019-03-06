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
#include <iostream>
#include <stdint.h>
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

static inline void printBuffer(const uint8_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

static inline void printBuffer(const uint32_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

template <uint8_t keySize>
static inline void printState(const uint8_t *state)
{
	uint8_t stateData[4][keySize];
	
	// Transform state to row-major for simpler access
	for (uint8_t row = 0; row < 4; row++)
	{
		for (uint8_t column = 0; column < keySize; column++)
		{
			stateData[row][column] = state[column * keySize + row];
		}
	}
	
	// Print rows
	for (uint8_t row = 0; row < 4; row++)
	{
		printBuffer(stateData[row], keySize);
	}
	
	std::cout << std::endl;
}

#endif // UTILITIES_H
