#ifndef UTILITIES_H
#define UTILITIES_H

#include <iostream>
#include <stdint.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
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

static inline void printState(const uint8_t *state, size_t keySize)
{
	for (uint8_t i = 0; i < 4; i++)
	{
		printBuffer(state + i * keySize, keySize);
	}
	
	std::cout << std::endl;
}

//static uint64_t bigToLittleEndian(const uint64_t dword)
//{
//	uint64_t returnValue = dword <<
//}

#endif // UTILITIES_H
