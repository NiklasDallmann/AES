#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "key.h"
#include "utilities.h"

namespace Aes
{

template <uint8_t keySize>
class Block
{
public:
	explicit Block(const Key<keySize> &key)
	{
		this->_expandKey(key.key);
	}
	
	explicit Block(uint8_t *key)
	{
		this->_expandKey(key);
		
		safeSetZero(key, keySize * sizeof (uint32_t));
	}
	
	~Block()
	{
		safeSetZero(this->_expandedKey, sizeof (this->_expandedKey));
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
			uint32_t s0 = changeEndianness(*reinterpret_cast<uint32_t *>(&this->_state[0][0]));
			uint32_t s1 = changeEndianness(*reinterpret_cast<uint32_t *>(&this->_state[1][0]));
			uint32_t s2 = changeEndianness(*reinterpret_cast<uint32_t *>(&this->_state[2][0]));
			uint32_t s3 = changeEndianness(*reinterpret_cast<uint32_t *>(&this->_state[3][0]));
			
			uint32_t t0 = 0;
			uint32_t t1 = 0;
			uint32_t t2 = 0;
			uint32_t t3 = 0;
			
			t0 = t0_enc[uint8_t(s0 >> 24)] ^ t1_enc[uint8_t(s1 >> 16)] ^ t2_enc[uint8_t(s2 >> 8)] ^ t3_enc[uint8_t(s3)];
			t1 = t0_enc[uint8_t(s1 >> 24)] ^ t1_enc[uint8_t(s2 >> 16)] ^ t2_enc[uint8_t(s3 >> 8)] ^ t3_enc[uint8_t(s0)];
			t2 = t0_enc[uint8_t(s2 >> 24)] ^ t1_enc[uint8_t(s3 >> 16)] ^ t2_enc[uint8_t(s0 >> 8)] ^ t3_enc[uint8_t(s1)];
			t3 = t0_enc[uint8_t(s3 >> 24)] ^ t1_enc[uint8_t(s0 >> 16)] ^ t2_enc[uint8_t(s1 >> 8)] ^ t3_enc[uint8_t(s2)];
			
			s0 = changeEndianness(t0);
			s1 = changeEndianness(t1);
			s2 = changeEndianness(t2);
			s3 = changeEndianness(t3);
			
			*reinterpret_cast<uint32_t *>(&this->_state[0][0]) = s0;
			*reinterpret_cast<uint32_t *>(&this->_state[1][0]) = s1;
			*reinterpret_cast<uint32_t *>(&this->_state[2][0]) = s2;
			*reinterpret_cast<uint32_t *>(&this->_state[3][0]) = s3;
			
			this->_addRoundKey(round);
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
	
	inline void _addRoundKey(const uint8_t round)
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

using Block128 = Block<AES_128_KEY_SIZE>;
using Block192 = Block<AES_192_KEY_SIZE>;
using Block256 = Block<AES_256_KEY_SIZE>;

} // namespace Aes

#endif // BLOCK_H
