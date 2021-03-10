#ifndef _CRYPTO__H_
#define _CRYPTO__H_
namespace crypto__ {
	enum class cryptoType {
		Encrypt = 1, Decrypt, Hash
	};
	enum class contentsType {
		File = 1, Message
	};
	enum class cryptoGraphic {
		AES = 1, ECC, ECDSA, ElGamal, SHA256, RC4, SM3, SM4, ZUC
	};
	static struct config {
		cryptoType cryptoTypeMode;
		contentsType contentsTypeMode;
		cryptoGraphic cryptoGraphicMode;
	}config;
	class CRYPTO__
	{
	public:
		CRYPTO__();

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
