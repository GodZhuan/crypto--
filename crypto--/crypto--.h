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
		void encrypt(FileProc& fp, string& keyStr,size_t keyLen) {
			if (keyStr.size() == keyLen) {
				switch (config.cryptoGraphicMode)
				{
				case cryptoGraphic::AES: {
					AES aes((unsigned char*)keyStr.c_str());
					while (fp.read(plain16, sizeof(plain16))) {
						memcpy(plain16, aes.Cipher(plain16, sizeof(plain16)), sizeof(plain16));
						fp.write(plain16, sizeof(plain16));
					}
				}break;
				case cryptoGraphic::ECC: {

				}break;
				case cryptoGraphic::ECDSA: {

				}break;
				case cryptoGraphic::ElGamal: {

				}break;
				case cryptoGraphic::RC4: {
				}break;
				case cryptoGraphic::SM3: {
				}break;
				case cryptoGraphic::SM4: {
				}break;
				case cryptoGraphic::ZUC: {
				}break;
				}
			}
		}
		void decrypt(FileProc& fp, string& keyStr, size_t keyLen) {
			if (keyStr.size() == keyLen) {
				switch (config.cryptoGraphicMode)
				{
				case cryptoGraphic::AES: {
					AES aes((unsigned char*)keyStr.c_str());
					while (fp.read(plain16, sizeof(plain16))) {
						memcpy(plain16, aes.InvCipher(plain16, sizeof(plain16)), sizeof(plain16));
						fp.write(plain16, sizeof(plain16));
					}
				}break;
				case cryptoGraphic::ECC: {

				}break;
				case cryptoGraphic::ECDSA: {

				}break;
				case cryptoGraphic::ElGamal: {

				}break;
				case cryptoGraphic::RC4: {
				}break;
				case cryptoGraphic::SM3: {
				}break;
				case cryptoGraphic::SM4: {
				}break;
				case cryptoGraphic::ZUC: {
				}break;
				}
			}
		}
	private:
		char plain16[16] = { 0 };
	};

}
#endif // !_CRYPTO__H_
