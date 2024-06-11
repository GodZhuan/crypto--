#ifndef _CRYPTO__H_
#define _CRYPTO__H_
#include "aes.h"
#include "fileproc.h"
#include <cstring>
#include <string>
#include <unordered_map>
namespace crypto__ {
enum class cryptoType { Encrypt = 1, Decrypt, Hash };
enum class contentsType { File = 1, Message };
enum class cryptoGraphic {
  AES = 1,
  ECC,
  ECDSA,
  ElGamal,
  SHA256,
  RC4,
  SM3,
  SM4,
  ZUC
};
static struct config {
  cryptoType cryptoTypeMode;
  contentsType contentsTypeMode;
  cryptoGraphic cryptoGraphicMode;
  std::string inText;
} config;

const static std::unordered_map<std::string, cryptoGraphic> cryptoMap = {
    {"aes", cryptoGraphic::AES},
    {"ecc", cryptoGraphic::ECC},
    {"ecdsa", cryptoGraphic::ECDSA},
    {"ElGamal", cryptoGraphic::ElGamal},
    {"rc4", cryptoGraphic::RC4},
    {"sm3", cryptoGraphic::SM3},
    {"sm4", cryptoGraphic::SM4},
    {"zuc", cryptoGraphic::ZUC},
    {"sha256", cryptoGraphic::SHA256}
};

class CRYPTO__ {
public:
  CRYPTO__();

  ~CRYPTO__() {}
  void encrypt(FileProc &fp, std::string &keyStr, size_t keyLen) {
    if (keyStr.size() == keyLen) {
      switch (config.cryptoGraphicMode) {
      case cryptoGraphic::AES: {
        AES aes((unsigned char *)keyStr.c_str());
        while (fp.read(plain16, sizeof(plain16))) {
          memcpy(plain16, aes.Cipher(plain16, sizeof(plain16)),
                 sizeof(plain16));
          fp.write(plain16, sizeof(plain16));
        }
      } break;
      case cryptoGraphic::ECC: {

      } break;
      case cryptoGraphic::ECDSA: {

      } break;
      case cryptoGraphic::ElGamal: {

      } break;
      case cryptoGraphic::RC4: {
      } break;
      case cryptoGraphic::SM3: {
      } break;
      case cryptoGraphic::SM4: {
      } break;
      case cryptoGraphic::ZUC: {
      } break;
      case cryptoGraphic::SHA256:
        break;
      }
    }
  }
  void decrypt(FileProc &fp, std::string &keyStr, size_t keyLen) {
    if (keyStr.size() == keyLen) {
      switch (config.cryptoGraphicMode) {
      case cryptoGraphic::AES: {
        AES aes((unsigned char *)keyStr.c_str());
        while (fp.read(plain16, sizeof(plain16))) {
          memcpy(plain16, aes.InvCipher(plain16, sizeof(plain16)),
                 sizeof(plain16));
          fp.write(plain16, sizeof(plain16));
        }
      } break;
      case cryptoGraphic::ECC: {

      } break;
      case cryptoGraphic::ECDSA: {

      } break;
      case cryptoGraphic::ElGamal: {

      } break;
      case cryptoGraphic::RC4: {
      } break;
      case cryptoGraphic::SM3: {
      } break;
      case cryptoGraphic::SM4: {
      } break;
      case cryptoGraphic::ZUC: {
      } break;
      case cryptoGraphic::SHA256:
        break;
      }
    }
  }

private:
  char plain16[16] = {0};
};

} // namespace crypto__
#endif // !_CRYPTO__H_
