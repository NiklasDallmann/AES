#ifndef CIPHERUTILITIES_H
#define CIPHERUTILITIES_H

///
/// \file
/// \author	Niklas Dallmann
/// \brief	Crypto's utility header.
/// \since	1.0
///

#include <iostream>
#include <iomanip>
#include <stdint.h>

#include "cryptoglobals.h"

[[maybe_unused]] static inline void printBuffer(const uint8_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::setw(sizeof (uint8_t) * 2) << std::setfill('0') << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

[[maybe_unused]] static inline void printBuffer(const uint32_t *buffer, size_t size)
{
	for (uint8_t i = 0; i < size; i++)
	{
		std::cout << "0x" << std::setw(sizeof (uint32_t) * 2) << std::setfill('0') << std::hex << uint32_t(buffer[i]) << " ";
	}
	
	std::cout << std::endl;
}

[[maybe_unused]] static inline void printState(const uint8_t *state)
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

[[maybe_unused]] static void generateTTable()
{
	std::stringstream table;
	
	INFO("BEGIN T TABLE")
	
	for (uint32_t a = 0; a <= 0xff; a++)
	{
		uint32_t word = 0;
		
		// Generate table entry
		uint8_t *ptr = reinterpret_cast<uint8_t *>(&word);
		
		ptr[0] = Crypto::BlockCipher::Aes::galoisMultiply_9[Crypto::BlockCipher::Aes::sBox_dec[a]];
		ptr[1] = Crypto::BlockCipher::Aes::galoisMultiply_d[Crypto::BlockCipher::Aes::sBox_dec[a]];
		ptr[2] = Crypto::BlockCipher::Aes::galoisMultiply_b[Crypto::BlockCipher::Aes::sBox_dec[a]];
		ptr[3] = Crypto::BlockCipher::Aes::galoisMultiply_e[Crypto::BlockCipher::Aes::sBox_dec[a]];
		
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

#endif // CIPHERUTILITIES_H
