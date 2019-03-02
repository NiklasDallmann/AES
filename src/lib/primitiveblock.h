#ifndef PRIMITIVEBLOCK_H
#define PRIMITIVEBLOCK_H

#define AES_BLOCK_SIZE			4
#define AES_128_KEY_SIZE		4
#define AES_192_KEY_SIZE		6
#define AES_256_KEY_SIZE		8

#include <stdint.h>

namespace Aes
{

template <uint8_t keySize>
struct KeySizeType;

template <>
struct KeySizeType<AES_128_KEY_SIZE>
{
	static constexpr uint8_t value = AES_128_KEY_SIZE;
};

template <>
struct KeySizeType<AES_192_KEY_SIZE>
{
	static constexpr uint8_t value = AES_192_KEY_SIZE;
};

template <>
struct KeySizeType<AES_256_KEY_SIZE>
{
	static constexpr uint8_t value = AES_256_KEY_SIZE;
};

template <uint8_t keySize>
class PrimitiveBlock
{
public:
	void encrypt(const uint8_t *key, const uint8_t *inputBlock, uint8_t *outputBlock);
	void decrypt(const uint8_t *key, const uint8_t *inputBlock, uint8_t *outputBlock);
	
private:
	static const uint8_t _sBoxLut[];
	
	uint8_t _state[AES_BLOCK_SIZE][KeySizeType<keySize>::value];
	
	void _addRoundKey();
	
	void _mixCollumns();
	void _inverseMixCollumns();
	void _shiftRows();
	void _inverseShiftRows();
	
	void _subBytes()
	{
		for (uint8_t x = 0; x < AES_BLOCK_SIZE; x++)
		{
			for (uint8_t y = 0; y < KeySizeType<keySize>::value; y++)
			{
				this->_state[x][y] = _sBoxLut[this->_state[x][y]];
			}
		}
	}
	
	void _inverseSubBytes();
	
	void _subWord();
	void _rotWord();
};

} // namespace Aes

#endif // PRIMITIVEBLOCK_H
