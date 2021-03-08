#ifndef _CRYPTO__H_
#define _CRYPTO__H_
namespace crypto__ {
	enum class cryptoType {
		Encrypt = 1, Decrypt
	};
	enum class cryptoGraphic {
		AES = 1, ECC, ECDSA, ElGamal, SHA256, RC4, SM3, SM4, ZUC
	};
	class CRYPTO__
	{
	public:
		CRYPTO__(enum cryptoType ct,enum cryptoGraphic cg);

		~CRYPTO__()
		{
		}
		void encrypt() {

		}
		void decrypt() {

		}
	private:

	};

}
#endif // !_CRYPTO__H_
