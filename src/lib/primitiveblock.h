#ifndef PRIMITIVEBLOCK_H
#define PRIMITIVEBLOCK_H

#include <stdint.h>
#include <string.h>
#include <type_traits>

#include "constants.h"
#include "key.h"
#include "utilities.h"

namespace Aes
{

template <uint8_t keySize>
class PrimitiveBlock
{
public:
	explicit PrimitiveBlock(const Key<keySize> &key)
	{
		this->_expandKey(key.key);
	}
	
	explicit PrimitiveBlock(uint8_t *key)
	{
		this->_expandKey(key);
		
		safeSetZero(key, keySize * sizeof (uint32_t));
	}
	
	~PrimitiveBlock()
	{
		safeSetZero(this->_state, AES_BLOCK_SIZE * AES_BLOCK_SIZE * sizeof (uint8_t));
	}
	
	void encrypt(const uint8_t *plainBlock, uint8_t *cipherBlock)
	{
		// Copy plain text into state
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				this->_state[column][row] = *plainBlock;
				plainBlock++;
			}
		}
		
		this->_addRoundKey(0);
		
		for (uint8_t round = 1; round < KeySizeType<keySize>::rounds; round++)
		{
			this->_subBytes();
			this->_shiftRows();
			this->_mixCollumns();
			this->_addRoundKey(round);
			
//			// Create a copy of the state
//			alignas(uint32_t) uint8_t stateCopy[AES_BLOCK_SIZE][AES_BLOCK_SIZE];
			
//			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
//			{
//				for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
//				{
//					stateCopy[column][row] = this->_state[column][row];
//				}
//			}
			
//			uint32_t columnVector0 = changeEndianness(*reinterpret_cast<uint32_t *>(&stateCopy[0][0]));
//			uint32_t columnVector1 = changeEndianness(*reinterpret_cast<uint32_t *>(&stateCopy[1][0]));
//			uint32_t columnVector2 = changeEndianness(*reinterpret_cast<uint32_t *>(&stateCopy[2][0]));
//			uint32_t columnVector3 = changeEndianness(*reinterpret_cast<uint32_t *>(&stateCopy[3][0]));
			
//			columnVector0 = _t0_enc[stateCopy[0][0]] ^ _t1_enc[stateCopy[3][1]] ^ _t2_enc[stateCopy[2][2]] ^ _t3_enc[stateCopy[1][3]];
//			columnVector1 = _t0_enc[stateCopy[1][0]] ^ _t1_enc[stateCopy[0][1]] ^ _t2_enc[stateCopy[3][2]] ^ _t3_enc[stateCopy[2][3]];
//			columnVector2 = _t0_enc[stateCopy[2][0]] ^ _t1_enc[stateCopy[1][1]] ^ _t2_enc[stateCopy[0][2]] ^ _t3_enc[stateCopy[3][3]];
//			columnVector3 = _t0_enc[stateCopy[3][0]] ^ _t1_enc[stateCopy[2][1]] ^ _t2_enc[stateCopy[1][2]] ^ _t3_enc[stateCopy[0][3]];
			
//			columnVector0 = changeEndianness(columnVector0);
//			columnVector1 = changeEndianness(columnVector1);
//			columnVector2 = changeEndianness(columnVector2);
//			columnVector3 = changeEndianness(columnVector3);
			
//			*reinterpret_cast<uint32_t *>(&this->_state[0][0]) = columnVector0;
//			*reinterpret_cast<uint32_t *>(&this->_state[1][0]) = columnVector1;
//			*reinterpret_cast<uint32_t *>(&this->_state[2][0]) = columnVector2;
//			*reinterpret_cast<uint32_t *>(&this->_state[3][0]) = columnVector3;
			
//			this->_addRoundKey(round);
		}
		
		this->_subBytes();
		this->_shiftRows();
		this->_addRoundKey(KeySizeType<keySize>::rounds);
		
		// Write state into cipher text
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				*cipherBlock = this->_state[column][row];
				cipherBlock++;
			}
		}
	}
	
	void decrypt(const uint8_t *cipherBlock, uint8_t *plainBlock)
	{
		// Copy plain text into state
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				this->_state[column][row] = *cipherBlock;
				cipherBlock++;
			}
		}
		
		this->_addRoundKey(KeySizeType<keySize>::rounds);
		
		for (uint8_t round = KeySizeType<keySize>::rounds - 1; round > 0; round--)
		{
			this->_inverseShiftRows();
			this->_inverseSubBytes();
			this->_addRoundKey(round);
			this->_inverseMixCollumns();
		}
		
		this->_inverseShiftRows();
		this->_inverseSubBytes();
		this->_addRoundKey(0);
		
		// Write state into cipher text
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				*plainBlock = this->_state[column][row];
				plainBlock++;
			}
		}
	}
	
private:
	alignas(uint32_t) uint8_t _state[AES_BLOCK_SIZE][AES_BLOCK_SIZE];
	
	uint32_t _expandedKey[AES_BLOCK_SIZE * (KeySizeType<keySize>::rounds + 1)];
	
	void _expandKey(const uint8_t *key)
	{
		uint32_t tmp = 0;
		
		for (uint8_t column = 0; column < KeySizeType<keySize>::value; column++)
		{
			this->_expandedKey[column] = ((((((key[4 * column] << 8) | key[4 * column + 1]) << 8) | key[4 * column + 2]) << 8) | key[4 * column + 3]);
		}
		
		for (uint8_t column = KeySizeType<keySize>::value; column < (AES_BLOCK_SIZE * (KeySizeType<keySize>::rounds + 1)); column++)
		{
			tmp = _expandedKey[column - 1];
			
			if ((column % KeySizeType<keySize>::value) == 0)
			{
				tmp = this->_subWord(this->_rotWord(tmp)) ^ (rCon[column / KeySizeType<keySize>::value] << (sizeof (uint32_t) - sizeof(uint8_t)) * 8);
			}
			else if ((KeySizeType<keySize>::value > 6) & ((column % KeySizeType<keySize>::value) == 4))
			{
				tmp = this->_subWord(tmp);
			}
			
			this->_expandedKey[column] = this->_expandedKey[column - KeySizeType<keySize>::value] ^ tmp;
		}
	}
	
	void _addRoundKey(const uint8_t round)
	{
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			uint32_t roundKey = *reinterpret_cast<uint32_t *>(this->_state[column]);
			
			roundKey = changeEndianness(roundKey);
			roundKey ^= this->_expandedKey[round * AES_BLOCK_SIZE + column];
			roundKey = changeEndianness(roundKey);
			
			// Write back word
			*reinterpret_cast<uint32_t *>(this->_state[column]) = roundKey;
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
		alignas(uint32_t) uint8_t word[] = {0x00, 0x00, 0x00, 0x00};
		
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			// No endian conversion needed because the loaded value is stored immediantely
			*reinterpret_cast<uint32_t *>(&word[0]) = *reinterpret_cast<uint32_t *>(&this->_state[column]);
			
			this->_state[column][0] = word[2] ^ word[3] ^ galoisMultiply_2[word[0]] ^ galoisMultiply_3[word[1]];
			this->_state[column][1] = word[0] ^ word[3] ^ galoisMultiply_2[word[1]] ^ galoisMultiply_3[word[2]];
			this->_state[column][2] = word[0] ^ word[1] ^ galoisMultiply_2[word[2]] ^ galoisMultiply_3[word[3]];
			this->_state[column][3] = word[1] ^ word[2] ^ galoisMultiply_2[word[3]] ^ galoisMultiply_3[word[0]];
		}
	}
	
	void _inverseMixCollumns()
	{
		alignas(uint32_t) uint8_t word[] = {0x00, 0x00, 0x00, 0x00};
		
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			// No endian conversion needed because the loaded value is stored immediantely
			*reinterpret_cast<uint32_t *>(&word[0]) = *reinterpret_cast<uint32_t *>(&this->_state[column]);
			
			this->_state[column][0] = galoisMultiply_9[word[3]] ^ galoisMultiply_b[word[1]] ^ galoisMultiply_d[word[2]] ^ galoisMultiply_e[word[0]];
			this->_state[column][1] = galoisMultiply_9[word[0]] ^ galoisMultiply_b[word[2]] ^ galoisMultiply_d[word[3]] ^ galoisMultiply_e[word[1]];
			this->_state[column][2] = galoisMultiply_9[word[1]] ^ galoisMultiply_b[word[3]] ^ galoisMultiply_d[word[0]] ^ galoisMultiply_e[word[2]];
			this->_state[column][3] = galoisMultiply_9[word[2]] ^ galoisMultiply_b[word[0]] ^ galoisMultiply_d[word[1]] ^ galoisMultiply_e[word[3]];
		}
	}
	
	void _shiftRows()
	{
		uint8_t tmp = 0;
		
		// Row 1
		tmp = this->_state[0][1];
		this->_state[0][1] = this->_state[1][1];
		this->_state[1][1] = this->_state[2][1];
		this->_state[2][1] = this->_state[3][1];
		this->_state[3][1] = tmp;
		
		// Row 2
		tmp = this->_state[0][2];
		this->_state[0][2] = this->_state[2][2];
		this->_state[2][2] = tmp;
		
		tmp = this->_state[1][2];
		this->_state[1][2] = this->_state[3][2];
		this->_state[3][2] = tmp;
		
		// Row 3
		tmp = this->_state[0][3];
		this->_state[0][3] = this->_state[3][3];
		this->_state[3][3] = this->_state[2][3];
		this->_state[2][3] = this->_state[1][3];
		this->_state[1][3] = tmp;
	}
	
	void _inverseShiftRows()
	{
		uint8_t tmp = 0;
		
		// Row 1
		tmp = this->_state[0][1];
		this->_state[0][1] = this->_state[3][1];
		this->_state[3][1] = this->_state[2][1];
		this->_state[2][1] = this->_state[1][1];
		this->_state[1][1] = tmp;
		
		// Row 2
		tmp = this->_state[0][2];
		this->_state[0][2] = this->_state[2][2];
		this->_state[2][2] = tmp;
		
		tmp = this->_state[1][2];
		this->_state[1][2] = this->_state[3][2];
		this->_state[3][2] = tmp;
		
		// Row 3
		tmp = this->_state[0][3];
		this->_state[0][3] = this->_state[1][3];
		this->_state[1][3] = this->_state[2][3];
		this->_state[2][3] = this->_state[3][3];
		this->_state[3][3] = tmp;
	}
	
	void _subBytes()
	{
		// Set each element of the state to the value of the corresponding SBox LUT element
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				this->_state[column][row] = sBox_enc[this->_state[column][row]];
			}
		}
	}
	
	void _inverseSubBytes()
	{
		// Set each element of the state to the value of the corresponding SBox LUT element
		for (uint8_t column = 0; column < AES_BLOCK_SIZE; column++)
		{
			for (uint8_t row = 0; row < AES_BLOCK_SIZE; row++)
			{
				this->_state[column][row] = sBox_dec[this->_state[column][row]];
			}
		}
	}
	
	uint32_t _subWord(const uint32_t word)
	{
		uint32_t returnValue = 0;
		
		reinterpret_cast<uint8_t *>(&returnValue)[0] = sBox_enc[reinterpret_cast<const uint8_t *>(&word)[0]];
		reinterpret_cast<uint8_t *>(&returnValue)[1] = sBox_enc[reinterpret_cast<const uint8_t *>(&word)[1]];
		reinterpret_cast<uint8_t *>(&returnValue)[2] = sBox_enc[reinterpret_cast<const uint8_t *>(&word)[2]];
		reinterpret_cast<uint8_t *>(&returnValue)[3] = sBox_enc[reinterpret_cast<const uint8_t *>(&word)[3]];
		
		return returnValue;
	}
	
	uint32_t _rotWord(const uint32_t word)
	{
		return rotateLeft(word, 8);
	}
};

using Block128 = PrimitiveBlock<AES_128_KEY_SIZE>;
using Block192 = PrimitiveBlock<AES_192_KEY_SIZE>;
using Block256 = PrimitiveBlock<AES_256_KEY_SIZE>;

} // namespace Aes

#endif // PRIMITIVEBLOCK_H
