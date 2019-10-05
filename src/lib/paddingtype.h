#ifndef PADDINGTYPE_H
#define PADDINGTYPE_H

namespace Crypto::Mode
{

///
/// \brief	Defines padding algorithm names.
/// 
/// \since	1.0
///
enum class PaddingType
{
	///	Padd the block with null bytes.
	Nulls,
	
	///	Padd the block with \f$n\f$ remaining bytes of the value \f$n\f$.
	NBytes,
	
	/// Padd the block using the last complete blocks ciphertext.
	CipherTextStealing
};

} // namespace Crypto::Mode

#endif // PADDINGTYPE_H
