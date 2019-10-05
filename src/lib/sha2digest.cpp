#include "sha2digest.h"

#include <cassert>
#include <string.h>

#include "sha2constants.h"

namespace Crypto::Hash::Sha2
{

template <>
void Digest<SHA224_DIGEST_SIZE>::_initializeState()
{
	this->_state[0] = 0xc1059ed8;
	this->_state[1] = 0x367cd507;
	this->_state[2] = 0x3070dd17;
	this->_state[3] = 0xf70e5939;
	this->_state[4] = 0xffc00b31;
	this->_state[5] = 0x68581511;
	this->_state[6] = 0x64f98fa7;
	this->_state[7] = 0xbefa4fa4;
}

template <>
void Digest<SHA256_DIGEST_SIZE>::_initializeState()
{
	DEBUG("Initialize SHA256")
	this->_state[0] = 0x6a09e667;
	this->_state[1] = 0xbb67ae85;
	this->_state[2] = 0x3c6ef372;
	this->_state[3] = 0xa54ff53a;
	this->_state[4] = 0x510e527f;
	this->_state[5] = 0x9b05688c;
	this->_state[6] = 0x1f83d9ab;
	this->_state[7] = 0x5be0cd19;
}

template <>
void Digest<SHA384_DIGEST_SIZE>::_initializeState()
{
	this->_state[0] = 0xcbbb9d5dc1059ed8;
	this->_state[1] = 0x629a292a367cd507;
	this->_state[2] = 0x9159015a3070dd17;
	this->_state[3] = 0x152fecd8f70e5939;
	this->_state[4] = 0x67332667ffc00b31;
	this->_state[5] = 0x8eb44a8768581511;
	this->_state[6] = 0xdb0c2e0d64f98fa7;
	this->_state[7] = 0x47b5481dbefa4fa4;
}

template <>
void Digest<SHA512_DIGEST_SIZE>::_initializeState()
{
	this->_state[0] = 0x6a09e667f3bcc908;
	this->_state[1] = 0xbb67ae8584caa73b;
	this->_state[2] = 0x3c6ef372fe94f82b;
	this->_state[3] = 0xa54ff53a5f1d36f1;
	this->_state[4] = 0x510e527fade682d1;
	this->_state[5] = 0x9b05688c2b3e6c1f;
	this->_state[6] = 0x1f83d9abfb41bd6b;
	this->_state[7] = 0x5be0cd19137e2179;
}

template <typename WordType>
inline static constexpr WordType _ch(const WordType x, const WordType y, const WordType z)
{
	return ((x ^ y) ^ (~x ^ z));
}

template <typename WordType>
inline static constexpr WordType _maj(const WordType x, const WordType y, const WordType z)
{
	return ((x ^ y) ^ (x ^ z) ^ (y ^ z));
}

template <typename WordType>
inline static constexpr WordType _sigma0(const WordType x)
{
	return (rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22));
}

template <typename WordType>
inline static constexpr WordType _sigma1(const WordType x)
{
	return (rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25));
}

template <typename WordType>
inline static constexpr WordType _phi0(const WordType x)
{
	return (rotateRight(x, 7) ^ rotateRight(x, 18) ^ shiftRight(x, 3));
}

template <typename WordType>
inline static constexpr WordType _phi1(const WordType x)
{
	return (rotateRight(x, 17) ^ rotateRight(x, 19) ^ shiftRight(x, 10));
}

inline void _sha256Update(Sha2::Traits<SHA256_DIGEST_SIZE>::WordType *state, const uint8_t *block)
{
	using WordType = Sha2::Traits<SHA256_DIGEST_SIZE>::WordType;
//	DEBUG("STATE")
//	printBuffer(state, 8);
	// Prepare message schedule
	WordType w[64];
	
	for (uint32_t t = 0; t < 16; t++)
	{
		w[t] = changeEndianness(reinterpret_cast<const WordType *>(block)[t]);
	}
	
	for (uint32_t t = 16; t < 64; t++)
	{
		w[t] = _phi1(w[t - 2]) + w[t - 7] + _phi0(w[t - 15]) + w[t - 16];
	}
	
//	DEBUG("W")
//	printBuffer(w, 64);
	
	// Working variables
	WordType a, b, c, d, e, f, g, h;
	
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
	
	for (uint32_t t = 0; t < 64; t++)
	{
		WordType T1, T2;
		
		T1 = h + _sigma1(e) + _ch(e, f, g) + Sha2::sha256Constants[t] + w[t];
		T2 = _sigma0(a) + _maj(a, b, c);
		
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	
	// Compute intermediate hash value
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
	
	DEBUG("STATE")
	printBuffer(state, 8);
}

inline void _sha512Update(Sha2::Traits<SHA512_DIGEST_SIZE>::WordType *state, const uint8_t *block)
{
	using WordType = Sha2::Traits<SHA512_DIGEST_SIZE>::WordType;
	
	// Prepare message schedule
	WordType w[80];
	
	for (uint32_t t = 0; t < 16; t++)
	{
		w[t] = changeEndianness(reinterpret_cast<const WordType *>(block)[t]);
	}
	
	for (uint32_t t = 16; t < 80; t++)
	{
		w[t] = _phi1(w[t - 2]) + w[t - 7] + _phi0(w[t - 15]) + w[t - 16];
	}
	
	// Working variables
	WordType a, b, c, d, e, f, g, h;
	
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
	
	for (uint32_t t = 0; t < 80; t++)
	{
		WordType T1, T2;
		
		T1 = h + _sigma1(e) + _ch(e, f, g) + Sha2::sha512Constants[t] + w[t];
		T2 = _sigma0(a) + _maj(a, b, c);
		
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	
	// Compute intermediate hash value
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

template <>
void Digest<SHA224_DIGEST_SIZE>::update(const uint8_t *block)
{
	this->_messageSize += TraitsType::blockSize * 8;
	_sha256Update(this->_state, block);
}

template <>
void Digest<SHA256_DIGEST_SIZE>::update(const uint8_t *block)
{
	this->_messageSize += TraitsType::blockSize * 8;
	_sha256Update(this->_state, block);
}

template <>
void Digest<SHA384_DIGEST_SIZE>::update(const uint8_t *block)
{
	this->_messageSize += TraitsType::blockSize * 8;
	_sha512Update(this->_state, block);
}

template <>
void Digest<SHA512_DIGEST_SIZE>::update(const uint8_t *block)
{
	this->_messageSize += TraitsType::blockSize * 8;
	_sha512Update(this->_state, block);
}

}
