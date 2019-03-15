#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>

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
	
private:
	typename TraitsType::WordType _state[TraitsType::stateSize];
	
	void _initializeState();
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

} // namespace Crypto::Hash

#endif // SHA2_H
