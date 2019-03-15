#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#include "cryptoglobals.h"
#include "sha2constants.h"
#include "sha2traits.h"

namespace Crypto::Hash
{

template <uint32_t digestSize>
class Sha2Digest
{
public:
	using TraitsType = Sha2::Traits<digestSize>;
	
	Sha2Digest()
	{
		this->_initializeState();
	}
	
	void add(const uint8_t *block)
	{
		// Prepare message schedule
		WordType w[TraitsType::blockSize];
		
		for (uint32_t t = 0; t < 16; t++)
		{
			w[t] = changeEndianness(reinterpret_cast<WordType *>(block)[t]);
		}
		
		for (uint32_t t = 16; t < TraitsType::blockSize; t++)
		{
			w[t] = this->_phi1(w[t - 2]) + w[t - 7] + this->_phi0(w[t - 15]) + w[t - 16];
		}
		
		// Working variables
		WordType a, b, c, d, e, f, g, h;
		
		a = this->_state[0];
		b = this->_state[1];
		c = this->_state[2];
		d = this->_state[3];
		e = this->_state[4];
		f = this->_state[5];
		g = this->_state[6];
		h = this->_state[7];
		
		for (uint32_t t = 0; t < 64; t++)
		{
			WordType T1, T2;
			
			T1 = h + this->_sigma1(e) + this->_ch(e, f, g) + Sha2::sha224_256Constants[t] + w[t];
			T2 = this->_sigma0(a) + this->_maj(a, b, c);
			
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
		this->_state[0] += a;
		this->_state[1] += b;
		this->_state[2] += c;
		this->_state[3] += d;
		this->_state[4] += e;
		this->_state[5] += f;
		this->_state[6] += g;
		this->_state[7] += h;
	}
	
	void finalize(const uint8_t *partialBlock, const size_t size)
	{
		
	}
	
	void hash(const uint8_t *message, const size_t messageSize)
	{
		
	}
	
	void reset()
	{
		this->_initializeState();
	}
	
private:
	using WordType = typename TraitsType::WordType;
	WordType _state[TraitsType::stateSize];
	
	void _initializeState();
	
	void _paddBlock();
	
	constexpr WordType _ch(const WordType x, const WordType y, const WordType z)
	{
		return ((x ^ y) ^ (~x ^ z));
	}
	
	constexpr WordType _maj(const WordType x, const WordType y, const WordType z)
	{
		return ((x ^ y) ^ (x ^ z) ^ (y ^ z));
	}
	
	constexpr WordType _sigma0(const WordType x)
	{
		return (rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22));
	}
	
	constexpr WordType _sigma1(const WordType x)
	{
		return (rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25));
	}
	
	constexpr WordType _phi0(const WordType x)
	{
		return (rotateRight(x, 7) ^ rotateRight(x, 18) ^ shiftRight(x, 3));
	}
	
	constexpr WordType _phi1(const WordType x)
	{
		return (rotateRight(x, 17) ^ rotateRight(x, 19) ^ shiftRight(x, 10));
	}
};

template <>
void Sha2Digest<SHA224_DIGEST_SIZE>::_initializeState()
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
void Sha2Digest<SHA256_DIGEST_SIZE>::_initializeState()
{
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
void Sha2Digest<SHA384_DIGEST_SIZE>::_initializeState()
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
void Sha2Digest<SHA512_DIGEST_SIZE>::_initializeState()
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

template <>
void Sha2Digest<SHA256_DIGEST_SIZE>::add(const uint8_t *block)
{
	// Prepare message schedule
	WordType w[TraitsType::blockSize];
	
	for (uint32_t t = 0; t < 16; t++)
	{
		w[t] = changeEndianness(reinterpret_cast<const WordType *>(block)[t]);
	}
	
	for (uint32_t t = 16; t < TraitsType::blockSize; t++)
	{
		w[t] = this->_phi1(w[t - 2]) + w[t - 7] + this->_phi0(w[t - 15]) + w[t - 16];
	}
	
	// Working variables
	WordType a, b, c, d, e, f, g, h;
	
	a = this->_state[0];
	b = this->_state[1];
	c = this->_state[2];
	d = this->_state[3];
	e = this->_state[4];
	f = this->_state[5];
	g = this->_state[6];
	h = this->_state[7];
	
	for (uint32_t t = 0; t < 64; t++)
	{
		WordType T1, T2;
		
		T1 = h + this->_sigma1(e) + this->_ch(e, f, g) + Sha2::sha224_256Constants[t] + w[t];
		T2 = this->_sigma0(a) + this->_maj(a, b, c);
		
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
	this->_state[0] += a;
	this->_state[1] += b;
	this->_state[2] += c;
	this->_state[3] += d;
	this->_state[4] += e;
	this->_state[5] += f;
	this->_state[6] += g;
	this->_state[7] += h;
}

} // namespace Crypto::Hash

#endif // SHA2_H
