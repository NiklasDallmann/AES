#ifndef PRIMITIVEBLOCK_H
#define PRIMITIVEBLOCK_H

#define AES_BLOCK_SIZE			4
#define AES_128_KEY_SIZE		4
#define AES_192_KEY_SIZE		6
#define AES_256_KEY_SIZE		8
#define AES_128_ROUND_COUNT		10
#define AES_192_ROUND_COUNT		12
#define AES_256_ROUND_COUNT		14

#include <stdint.h>
#include <string.h>
#include <type_traits>

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

template <uint8_t keySize>
void circularShiftRowLeft(uint8_t *row, uint8_t byteCount);

template <>
void circularShiftRowLeft<AES_128_KEY_SIZE>(uint8_t *row, uint8_t byteCount)
{
	uint32_t *currentRow = reinterpret_cast<uint32_t *>(row);
	
#ifdef AES_LITTLE_ENDIAN
	currentRow[0] = __builtin_bswap32(rotateLeft(__builtin_bswap32(currentRow[0]), byteCount * 8));
#else
	currentRow[0] = rotateLeft(currentRow[0], byteCount * 8);
#endif
}

template <>
void circularShiftRowLeft<AES_192_KEY_SIZE>(uint8_t *row, uint8_t byteCount)
{
	uint32_t *currentRow = reinterpret_cast<uint32_t *>(row);
	
	// Load first four bytes
	uint64_t tmp = currentRow[0] << (sizeof (uint16_t) * 8);
	
	// Load the last two bytes and extend them to four
	uint64_t thirdHalf = uint64_t(*reinterpret_cast<uint16_t *>(row + sizeof (uint16_t)));
	
	tmp |= thirdHalf;
	
#ifdef AES_LITTLE_ENDIAN
	tmp = __builtin_bswap64(rotateLeft(__builtin_bswap64(tmp), byteCount * 8));
#else
	tmp = rotateLeft(tmp, byteCount * 8);
#endif
	
	// Write back last two bytes
	thirdHalf = uint16_t(tmp);
	
	// Write back first four bytes
	currentRow[0] = uint32_t(tmp >> (sizeof (uint16_t) * 8));
}

template <>
void circularShiftRowLeft<AES_256_KEY_SIZE>(uint8_t *row, uint8_t byteCount)
{
	uint64_t *currentRow = reinterpret_cast<uint64_t *>(row);
	
#ifdef AES_LITTLE_ENDIAN
	currentRow[0] = __builtin_bswap64(rotateLeft(__builtin_bswap64(currentRow[0]), byteCount * 8));
#else
	currentRow[0] = rotateLeft(currentRow[0], byteCount * 8);
#endif
}

template <uint8_t keySize>
void gatherRow(const uint8_t *state, const uint8_t rowIndex, uint8_t *row)
{
	for (uint8_t column = 0; column < KeySizeType<keySize>::value; column++)
	{
		row[column] = state[column + AES_BLOCK_SIZE * rowIndex];
	}
}

template <uint8_t keySize>
void writeBackRow(uint8_t *state, const uint8_t rowIndex, const uint8_t *row)
{
	for (uint8_t column = 0; column < KeySizeType<keySize>::value; column++)
	{
		state[column + AES_BLOCK_SIZE * rowIndex] = row[column];
	}
}

template <uint8_t keySize>
class PrimitiveBlock
{
public:
	PrimitiveBlock(uint8_t *key)
	{
		this->_expandKey(key);
		
#ifdef AES_COMPILER_GCC
		explicit_bzero(key, keySize * sizeof (uint32_t));
#elif
		static_assert (false, "Compiler not supported.");
#endif
	}
	
	~PrimitiveBlock()
	{
#ifdef AES_COMPILER_GCC
		explicit_bzero(this->_state, this->_rowCount * this->_columnCount * sizeof (uint8_t));
#elif
		static_assert (false, "Compiler not supported.");
#endif
	}
	
	void encrypt(const uint8_t *inputBlock, uint8_t *outputBlock)
	{
		// Copy input data into state
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			for (uint8_t row = 0; row < _rowCount; row++)
			{
				this->_state[column][row] = *inputBlock;
				inputBlock++;
			}
		}
		
		this->_addRoundKey(0);
		
		for (uint8_t round = 1; round < _roundCount; round++)
		{
			this->_subBytes();
			this->_shiftRows();
			this->_mixCollumns();
			this->_addRoundKey(round);
		}
		
		this->_subBytes();
		this->_shiftRows();
		this->_addRoundKey(_roundCount);
		
		// Write state into output
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			for (uint8_t row = 0; row < _rowCount; row++)
			{
				*outputBlock = this->_state[column][row];
				outputBlock++;
			}
		}
	}
	
	void decrypt(const uint8_t *inputBlock, uint8_t *outputBlock)
	{
		
	}
	
private:
	static const uint8_t _sBoxLut[];
	static const uint8_t _rCon[];
	
	static constexpr uint8_t _rowCount = AES_BLOCK_SIZE;
	static constexpr uint8_t _columnCount = KeySizeType<keySize>::value;
	static constexpr uint8_t _roundCount = KeySizeType<keySize>::rounds;
	
	uint8_t _state[_columnCount][_rowCount];
	
	uint32_t _expandedKey[AES_BLOCK_SIZE * (_roundCount + 1)];
	
	void _expandKey(const uint8_t *key)
	{
		uint32_t tmp = 0;
		
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			this->_expandedKey[column] = ((((((key[4 * column] << 8) | key[4 * column + 1]) << 8) | key[4 * column + 2]) << 8) | key[4 * column + 3]);
		}
		
		for (uint8_t column = _columnCount; column < (_rowCount * (_roundCount + 1)); column++)
		{
			tmp = _expandedKey[column - 1];
			
			if ((column % _columnCount) == 0)
			{
				tmp = this->_subWord(this->_rotWord(tmp)) ^ (_rCon[column / _columnCount] << (sizeof (uint32_t) - sizeof(uint8_t)) * 8);
			}
			else if ((_columnCount > 6) & ((column % _columnCount) == 4))
			{
				tmp = this->_subWord(tmp);
			}
			
			this->_expandedKey[column] = this->_expandedKey[column - _columnCount] ^ tmp;
		}
	}
	
	void _addRoundKey(const uint8_t round)
	{
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			uint32_t word = *reinterpret_cast<uint32_t *>(this->_state[column]);
			
#ifdef AES_LITTLE_ENDIAN
			word = __builtin_bswap32(word);
#endif
			word ^= this->_expandedKey[round * _rowCount + column];
			
#ifdef AES_LITTLE_ENDIAN
			word = __builtin_bswap32(word);
#endif
			
			// Write back word
			*reinterpret_cast<uint32_t *>(this->_state[column]) = word;
		}
	}
	
	constexpr uint8_t _xtime(const uint8_t value) const
	{
		// First left shift by one bit to achieve a multiplication by 2. Then XOR conditionally with 0x1b. That is achieved by shifting the MSB to the LSB and
		// AND with 1. Then multiply that by 0x1b.
		return uint8_t((value << uint8_t(1)) ^ ((value >> uint8_t(7) & uint8_t(1)) * uint8_t(0x1b)));
	}
	
	void _mixCollumns()
	{
		uint8_t word[] = {0x00, 0x00, 0x00, 0x00};
		
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			// No endian conversion needed because the loaded value is stored immediantely
			*reinterpret_cast<uint32_t *>(&word[0]) = *reinterpret_cast<uint32_t *>(&this->_state[column]);
			
			this->_state[column][0] = _xtime(word[0]) ^ _xtime(word[1]) ^ word[1] ^ word[2] ^ word[3];
			this->_state[column][1] = word[0] ^ _xtime(word[1]) ^ _xtime(word[2]) ^ word[2] ^ word[3];
			this->_state[column][2] = word[0] ^ word[1] ^ _xtime(word[2]) ^ _xtime(word[3]) ^ word[3];
			this->_state[column][3] = _xtime(word[0]) ^ word[0] ^ word[1] ^ word[2] ^ _xtime(word[3]);
		}
	}
	
	void _inverseMixCollumns();
	
	void _shiftRows()
	{
		// Create a copy of the state
		uint8_t stateCopy[_columnCount][_rowCount];
		
		for (uint8_t row = 1; row < _rowCount; row++)
		{
			for (uint8_t column = 0; column < _columnCount; column++)
			{
				stateCopy[column][row] = this->_state[column][row];
			}
		}
		
		// Perform transformation
		for (uint8_t row = 1; row < _rowCount; row++)
		{
			for (uint8_t column = 0; column < _columnCount; column++)
			{
				this->_state[column][row] = stateCopy[(column + row) % _rowCount][row];
			}
		}
	}
	
	void _inverseShiftRows();
	
	void _subBytes()
	{
		// Set each element of the state to the value of the corresponding SBox LUT element
		for (uint8_t column = 0; column < _columnCount; column++)
		{
			for (uint8_t row = 0; row < _rowCount; row++)
			{
				this->_state[column][row] = _sBoxLut[this->_state[column][row]];
			}
		}
	}
	
	void _inverseSubBytes();
	
	uint32_t _subWord(const uint32_t word)
	{
		uint32_t returnValue = 0;
		
		reinterpret_cast<uint8_t *>(&returnValue)[0] = _sBoxLut[reinterpret_cast<const uint8_t *>(&word)[0]];
		reinterpret_cast<uint8_t *>(&returnValue)[1] = _sBoxLut[reinterpret_cast<const uint8_t *>(&word)[1]];
		reinterpret_cast<uint8_t *>(&returnValue)[2] = _sBoxLut[reinterpret_cast<const uint8_t *>(&word)[2]];
		reinterpret_cast<uint8_t *>(&returnValue)[3] = _sBoxLut[reinterpret_cast<const uint8_t *>(&word)[3]];
		
		return returnValue;
	}
	
	uint32_t _rotWord(const uint32_t word)
	{
		return rotateLeft(word, 8);
	}
};

template <uint8_t keySize>
const uint8_t PrimitiveBlock<keySize>::_sBoxLut[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

template <uint8_t keySize>
const uint8_t PrimitiveBlock<keySize>::_rCon[] = {
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

} // namespace Aes

#endif // PRIMITIVEBLOCK_H
