#ifndef AESBLOCK_H
#define AESBLOCK_H

#include <stdint.h>
#include <string.h>

#include "aesconstants.h"
#include "cipherkey.h"
#include "aestraits.h"
#include "cryptoutilities.h"

namespace Crypto
{

using Aes128Key = Key<AES_128_KEY_SIZE>;
using Aes192Key = Key<AES_192_KEY_SIZE>;
using Aes256Key = Key<AES_256_KEY_SIZE>;

} // namespace Crypto

namespace Crypto::Aes
{

template <uint32_t keySize>
class Block
{
public:
	using TraitsType = Traits<keySize>;
	using KeyType = Key<keySize>;
	
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
	}
	
	void encrypt(const uint8_t *plainBlock, uint8_t *cipherBlock)
	{
		// Column vectors
		uint32_t s0 = changeEndianness(*reinterpret_cast<const uint32_t *>(plainBlock));
		uint32_t s1 = changeEndianness(*reinterpret_cast<const uint32_t *>(plainBlock + sizeof (uint32_t)));
		uint32_t s2 = changeEndianness(*reinterpret_cast<const uint32_t *>(plainBlock + sizeof (uint32_t) * 2));
		uint32_t s3 = changeEndianness(*reinterpret_cast<const uint32_t *>(plainBlock + sizeof (uint32_t) * 3));
		
		// Temporaries
		uint32_t t0 = 0;
		uint32_t t1 = 0;
		uint32_t t2 = 0;
		uint32_t t3 = 0;
		
		// Key index
		uint32_t k = 0;
		
		// Add round key; first round
		s0 ^= this->_expandedKey[k + 0];
		s1 ^= this->_expandedKey[k + 1];
		s2 ^= this->_expandedKey[k + 2];
		s3 ^= this->_expandedKey[k + 3];
		k += 4;
		
		// Perform transformation on middle rounds
		for (uint8_t round = 1; round < Traits<keySize>::rounds; round++)
		{
			t0 = t0_enc[uint8_t(s0 >> 24)] ^ t1_enc[uint8_t(s1 >> 16)] ^ t2_enc[uint8_t(s2 >> 8)] ^ t3_enc[uint8_t(s3)] ^ this->_expandedKey[k + 0];
			t1 = t0_enc[uint8_t(s1 >> 24)] ^ t1_enc[uint8_t(s2 >> 16)] ^ t2_enc[uint8_t(s3 >> 8)] ^ t3_enc[uint8_t(s0)] ^ this->_expandedKey[k + 1];
			t2 = t0_enc[uint8_t(s2 >> 24)] ^ t1_enc[uint8_t(s3 >> 16)] ^ t2_enc[uint8_t(s0 >> 8)] ^ t3_enc[uint8_t(s1)] ^ this->_expandedKey[k + 2];
			t3 = t0_enc[uint8_t(s3 >> 24)] ^ t1_enc[uint8_t(s0 >> 16)] ^ t2_enc[uint8_t(s1 >> 8)] ^ t3_enc[uint8_t(s2)] ^ this->_expandedKey[k + 3];
			
			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;
			
			k += 4;
		}
		
		// Final round
		s0 = (uint32_t(sBox_enc[uint8_t(t0 >> 24)]) << 24) | (uint32_t(sBox_enc[uint8_t(t1 >> 16)]) << 16) | (uint32_t(sBox_enc[uint8_t(t2 >> 8)]) << 8) | (uint32_t(sBox_enc[uint8_t(t3)]));
		s1 = (uint32_t(sBox_enc[uint8_t(t1 >> 24)]) << 24) | (uint32_t(sBox_enc[uint8_t(t2 >> 16)]) << 16) | (uint32_t(sBox_enc[uint8_t(t3 >> 8)]) << 8) | (uint32_t(sBox_enc[uint8_t(t0)]));
		s2 = (uint32_t(sBox_enc[uint8_t(t2 >> 24)]) << 24) | (uint32_t(sBox_enc[uint8_t(t3 >> 16)]) << 16) | (uint32_t(sBox_enc[uint8_t(t0 >> 8)]) << 8) | (uint32_t(sBox_enc[uint8_t(t1)]));
		s3 = (uint32_t(sBox_enc[uint8_t(t3 >> 24)]) << 24) | (uint32_t(sBox_enc[uint8_t(t0 >> 16)]) << 16) | (uint32_t(sBox_enc[uint8_t(t1 >> 8)]) << 8) | (uint32_t(sBox_enc[uint8_t(t2)]));
		
		s0 ^= this->_expandedKey[k + 0];
		s1 ^= this->_expandedKey[k + 1];
		s2 ^= this->_expandedKey[k + 2];
		s3 ^= this->_expandedKey[k + 3];
		
		*reinterpret_cast<uint32_t *>(cipherBlock) = changeEndianness(s0);
		*reinterpret_cast<uint32_t *>(cipherBlock + sizeof (uint32_t)) = changeEndianness(s1);
		*reinterpret_cast<uint32_t *>(cipherBlock + sizeof (uint32_t) * 2) = changeEndianness(s2);
		*reinterpret_cast<uint32_t *>(cipherBlock + sizeof (uint32_t) * 3) = changeEndianness(s3);
	}
	
	void decrypt(const uint8_t *cipherBlock, uint8_t *plainBlock)
	{
		alignas(uint32_t) StateType state;
		
		// Copy plain text into state
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			for (uint8_t row = 0; row < TraitsType::blockSize; row++)
			{
				state[column][row] = *cipherBlock;
				cipherBlock++;
			}
		}
		
		this->_addRoundKey(state, Traits<keySize>::rounds);
		
		for (uint8_t round = Traits<keySize>::rounds - 1; round > 0; round--)
		{
			this->_inverseShiftRows(state);
			this->_inverseSubBytes(state);
			this->_addRoundKey(state, round);
			this->_inverseMixCollumns(state);
		}
		
		this->_inverseShiftRows(state);
		this->_inverseSubBytes(state);
		this->_addRoundKey(state, 0);
		
		// Write state into cipher text
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			for (uint8_t row = 0; row < TraitsType::blockSize; row++)
			{
				*plainBlock = state[column][row];
				plainBlock++;
			}
		}
		
		safeSetZero(state, TraitsType::blockSize * TraitsType::blockSize * sizeof (uint8_t));
	}
	
private:
	using StateType = uint8_t [TraitsType::blockSize][TraitsType::blockSize];
	
	uint32_t _expandedKey[TraitsType::blockSize * (Traits<keySize>::rounds + 1)];
	
	void _expandKey(const uint8_t *key)
	{
		uint32_t tmp = 0;
		
		for (uint8_t column = 0; column < Traits<keySize>::keySize; column++)
		{
			this->_expandedKey[column] = ((((((key[4 * column] << 8) | key[4 * column + 1]) << 8) | key[4 * column + 2]) << 8) | key[4 * column + 3]);
		}
		
		for (uint8_t column = Traits<keySize>::keySize; column < (TraitsType::blockSize * (Traits<keySize>::rounds + 1)); column++)
		{
			tmp = _expandedKey[column - 1];
			
			if ((column % Traits<keySize>::keySize) == 0)
			{
				tmp = this->_subWord(this->_rotWord(tmp)) ^ (rCon[column / Traits<keySize>::keySize] << (sizeof (uint32_t) - sizeof(uint8_t)) * 8);
			}
			else if ((Traits<keySize>::keySize > 6) & ((column % Traits<keySize>::keySize) == 4))
			{
				tmp = this->_subWord(tmp);
			}
			
			this->_expandedKey[column] = this->_expandedKey[column - Traits<keySize>::keySize] ^ tmp;
		}
	}
	
	inline void _addRoundKey(StateType &state, const uint8_t round)
	{
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			uint32_t roundKey = *reinterpret_cast<uint32_t *>(state[column]);
			
			roundKey ^= changeEndianness(this->_expandedKey[round * TraitsType::blockSize + column]);
			
			// Write back word
			*reinterpret_cast<uint32_t *>(state[column]) = roundKey;
		}
	}
	
	constexpr uint8_t _xtime(const uint8_t value) const
	{
		// First left shift by one bit to achieve a multiplication by 2. Then XOR conditionally with 0x1b. That is achieved by shifting the MSB to the LSB and
		// AND with 1. Then multiply that by 0x1b.
		return uint8_t((value << uint8_t(1)) ^ ((value >> uint8_t(7) & uint8_t(1)) * uint8_t(0x1b)));
	}
	
	void _mixCollumns(StateType &state)
	{
		alignas(uint32_t) uint8_t word[] = {0x00, 0x00, 0x00, 0x00};
		
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			// No endian conversion needed because the loaded value is stored immediantely
			*reinterpret_cast<uint32_t *>(&word[0]) = *reinterpret_cast<uint32_t *>(&state[column][0]);
			
			state[column][0] = word[2] ^ word[3] ^ galoisMultiply_2[word[0]] ^ galoisMultiply_3[word[1]];
			state[column][1] = word[0] ^ word[3] ^ galoisMultiply_2[word[1]] ^ galoisMultiply_3[word[2]];
			state[column][2] = word[0] ^ word[1] ^ galoisMultiply_2[word[2]] ^ galoisMultiply_3[word[3]];
			state[column][3] = word[1] ^ word[2] ^ galoisMultiply_2[word[3]] ^ galoisMultiply_3[word[0]];
		}
	}
	
	void _inverseMixCollumns(StateType &state)
	{
		alignas(uint32_t) uint8_t word[] = {0x00, 0x00, 0x00, 0x00};
		
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			// No endian conversion needed because the loaded value is stored immediantely
			*reinterpret_cast<uint32_t *>(&word[0]) = *reinterpret_cast<uint32_t *>(&state[column][0]);
			
			state[column][0] = galoisMultiply_9[word[3]] ^ galoisMultiply_b[word[1]] ^ galoisMultiply_d[word[2]] ^ galoisMultiply_e[word[0]];
			state[column][1] = galoisMultiply_9[word[0]] ^ galoisMultiply_b[word[2]] ^ galoisMultiply_d[word[3]] ^ galoisMultiply_e[word[1]];
			state[column][2] = galoisMultiply_9[word[1]] ^ galoisMultiply_b[word[3]] ^ galoisMultiply_d[word[0]] ^ galoisMultiply_e[word[2]];
			state[column][3] = galoisMultiply_9[word[2]] ^ galoisMultiply_b[word[0]] ^ galoisMultiply_d[word[1]] ^ galoisMultiply_e[word[3]];
		}
	}
	
	void _shiftRows(StateType &state)
	{
		uint8_t tmp = 0;
		
		// Row 1
		tmp = state[0][1];
		state[0][1] = state[1][1];
		state[1][1] = state[2][1];
		state[2][1] = state[3][1];
		state[3][1] = tmp;
		
		// Row 2
		tmp = state[0][2];
		state[0][2] = state[2][2];
		state[2][2] = tmp;
		
		tmp = state[1][2];
		state[1][2] = state[3][2];
		state[3][2] = tmp;
		
		// Row 3
		tmp = state[0][3];
		state[0][3] = state[3][3];
		state[3][3] = state[2][3];
		state[2][3] = state[1][3];
		state[1][3] = tmp;
	}
	
	void _inverseShiftRows(StateType &state)
	{
		uint8_t tmp = 0;
		
		// Row 1
		tmp = state[0][1];
		state[0][1] = state[3][1];
		state[3][1] = state[2][1];
		state[2][1] = state[1][1];
		state[1][1] = tmp;
		
		// Row 2
		tmp = state[0][2];
		state[0][2] = state[2][2];
		state[2][2] = tmp;
		
		tmp = state[1][2];
		state[1][2] = state[3][2];
		state[3][2] = tmp;
		
		// Row 3
		tmp = state[0][3];
		state[0][3] = state[1][3];
		state[1][3] = state[2][3];
		state[2][3] = state[3][3];
		state[3][3] = tmp;
	}
	
	void _subBytes(StateType &state)
	{
		// Set each element of the state to the value of the corresponding SBox LUT element
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			for (uint8_t row = 0; row < TraitsType::blockSize; row++)
			{
				state[column][row] = sBox_enc[state[column][row]];
			}
		}
	}
	
	void _inverseSubBytes(StateType &state)
	{
		// Set each element of the state to the value of the corresponding SBox LUT element
		for (uint8_t column = 0; column < TraitsType::blockSize; column++)
		{
			for (uint8_t row = 0; row < TraitsType::blockSize; row++)
			{
				state[column][row] = sBox_dec[state[column][row]];
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

} // namespace Crypto::Aes

#endif // AESBLOCK_H
