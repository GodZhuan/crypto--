#include "../include/crypto--.h"
#include "../include/ecc.h"
#include "../include/ecdsa.h"
#include "../include/fileproc.h"
#include "../include/sha256.h"
#include "../include/sm3.h"
#include "../include/sm4.h"
#include "../include/sts.h"
#include "../include/tools.h"
#include "../include/zuc.h"
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
using namespace crypto__;
using std::cin;
using std::cout;
namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " aes|des|...\n";
    return 1;
  }
  auto *argvTemp = argv[1];
  if (strcmp(argvTemp, "test") == 0) {
    config.contentsTypeMode = contentsType::File;
    config.cryptoTypeMode = cryptoType::Encrypt;
    config.cryptoGraphicMode = cryptoGraphic::AES;
    config.inText = "../tests/demo.txt";
  }

  // 选择处理文件或者是消息
  for (auto index = 1; index < argc; index++) {
    auto *argvTemp = argv[index];
    if (strcmp(argvTemp, "-f") == 0) {
      config.contentsTypeMode = contentsType::File;
      index++;
      config.inText = argvTemp;
    } else if (strcmp(argvTemp, "-m") == 0) {
      config.contentsTypeMode = contentsType::Message;
      index++;
      config.inText = argvTemp;
    }
    // 选择加密或者是解密或者是哈希
    if (strcmp(argvTemp, "-e") == 0) {
      config.cryptoTypeMode = cryptoType::Encrypt;
      index++;
      argvTemp = argv[index];
      // 选择算法
      if (index < argc && cryptoMap.find(argvTemp) != cryptoMap.end()) {
        config.cryptoGraphicMode = cryptoMap.at(argvTemp);
      } else {
        std::cerr << "Error: -d requires a valid decryption algorithm.\n";
        return 1;
      }
    } else if (strcmp(argvTemp, "-d") == 0) {
      config.cryptoTypeMode = cryptoType::Decrypt;
      ++index;
      argvTemp = argv[index];
      // 选择算法
      if (index < argc && cryptoMap.find(argvTemp) != cryptoMap.end()) {
        config.cryptoGraphicMode = cryptoMap.at(argvTemp);
      } else {
        std::cerr << "Error: -d requires a valid decryption algorithm.\n";
        return 1;
      }
    } else if (strcmp(argvTemp, "-h") == 0) {
      config.cryptoTypeMode = cryptoType::Hash;
      index++;
      argvTemp = argv[index];
      if (index < argc && cryptoMap.find(argvTemp) != cryptoMap.end()) {
        config.cryptoGraphicMode = cryptoMap.at(argvTemp);
      } else {
        std::cerr << "Error: -d requires a valid decryption algorithm.\n";
        return 1;
      }
    }
  }
  CRYPTO__ c;
}

CRYPTO__::CRYPTO__() {
  SHA256 sha256;
  int ret;
  std::string dirPath;
  std::string fileName;
  std::string ext;
  std::string msg;
  fs::path fullPath;
  switch (config.contentsTypeMode) {
  case contentsType::File: {
    fullPath = config.inText;
    dirPath = fullPath.parent_path();
    fileName = fullPath.filename();
    ext = fullPath.stem();
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt: {
      fullPath = dirPath + fileName + "cipher.txt";
    } break;
    case cryptoType::Decrypt: {
      fullPath = dirPath + fileName + "invcipher" + ext;
    } break;
    case cryptoType::Hash:
      break;
    }

  } break;
  case contentsType::Message: {
    msg = config.inText;
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt:
      break;
    case cryptoType::Decrypt:
      break;
    case cryptoType::Hash:
      break;
    }
  } break;
  }

  switch (config.cryptoGraphicMode) {
  case cryptoGraphic::AES: {
    string keyStr;
    cout << "请输入密钥：";
    cin >> keyStr;
    FileProc fp(config.inText, fullPath);
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt:
      encrypt(fp, keyStr, 16);
      break;
    case cryptoType::Decrypt:
      decrypt(fp, keyStr, 16);
      break;
    case cryptoType::Hash:
      break;
    }
  } break;
  case cryptoGraphic::ECC: {
    ECC e;

    cout << "\n          本程序实现椭圆曲线的加密解密" << endl;
    cout << "\n----------------------------------------------------------------"
            "--------\n"
         << endl;
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt:
      time_t t;
      srand((unsigned)time(&t));
      e.BuildParameters();
      e.PrintParameters();
      // 传入密钥和密钥文件所在文件夹
      e.Ecc_saveKey(dirPath);

      cout
          << "\n---------------------------------------------------------------"
             "---------\n";
      e.Ecc_encipher(config.inText.data(), fullPath); // 加密
      break;
    case cryptoType::Decrypt:
      cout
          << "\n---------------------------------------------------------------"
             "---------\n";
      e.Ecc_loadKey(dirPath);
      e.Ecc_decipher(config.inText.data(), fullPath); // 解密

      break;
    case cryptoType::Hash:
      break;
    }

  } break;
  case cryptoGraphic::ECDSA: {
    ECDSA ecdsa;
    ecdsa.printECDSA(sha256.ShaFile(config.inText));
  } break;
  case cryptoGraphic::ElGamal: {
    ECC ecc;
    STS sts;

    int lon = 0;
    string path; // 消息m的路径
    size_t written;
    mp_int p;   // p为安全素数
    mp_int a;   // 生成元
    mp_int p_1; // p-1
    mp_int x;   // 随机数x
    mp_int y;   // a**x mod p
    mp_int k;   // k属于Zp* 且k与p-1互素
    mp_int r;   // a**k mod p
    mp_int s;   // a**x mod p
    mp_int sha; // sha256的散列值
    mp_int a1;  // k的逆元
    mp_int b1;  // p-1的逆元
    mp_int temp3;
    mp_err err = MP_OKAY;

    std::unique_ptr<char[]> tempY(new char[800]());
    std::unique_ptr<char[]> tempR(new char[800]());
    std::unique_ptr<char[]> tempSHA(new char[800]());
    std::unique_ptr<char[]> tempA1(new char[800]());
    std::unique_ptr<char[]> tempT(new char[800]());

    try {
      if ((err = mp_init(&p)); err != MP_OKAY) {
        cerr << (format("Error initializing the p. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&a)); err != MP_OKAY) {
        cerr << (format("Error initializing the a. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&p_1)); err != MP_OKAY) {
        cerr << (format("Error initializing the p_1. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&x)); err != MP_OKAY) {
        cerr << (format("Error initializing the x. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&y)); err != MP_OKAY) {
        cerr << (format("Error initializing the y. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&a)); err != MP_OKAY) {
        cerr << (format("Error initializing the a. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&k)); err != MP_OKAY) {
        cerr << (format("Error initializing the k. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&r)); err != MP_OKAY) {
        cerr << (format("Error initializing the r. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&s)); err != MP_OKAY) {
        cerr << (format("Error initializing the s. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&sha)); err != MP_OKAY) {
        cerr << (format("Error initializing the sha. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&a1)); err != MP_OKAY) {
        cerr << (format("Error initializing the a1. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&b1)); err != MP_OKAY) {
        cerr << (format("Error initializing the b1. {}",
                        mp_error_to_string(err)));
      }
      if ((err = mp_init(&temp3)); err != MP_OKAY) {
        cerr << (format("Error initializing the temp3. {}",
                        mp_error_to_string(err)));
      }

    } catch (const char *init_err) {
      cout << init_err << endl;
    }

    cout << "请输入大素数的位数：";
    cin >> lon;
    sts.GetPrime(&p, &a, lon);
    err = mp_sub_d(&p, 1, &p_1);
    do {
      err = mp_rand(&x, lon);
    } while (err == MP_OKAY && mp_cmp(&x, &p_1) != -1 &&
             mp_cmp_d(&x, 1) != 1); // 1<=x<p-1

    err = mp_exptmod(&a, &x, &p, &y);
    err = mp_to_radix(&y, tempY.get(), SIZE_MAX, &written, 10);
    cout << (format("y是:\n{}\n", tempY.get()));

    do {
      err = mp_rand(&k, lon / 26);
      if (err == MP_OKAY) {
        err = mp_gcd(&k, &p_1, &r); // 互素
      }
    } while (err == MP_OKAY &&
             (mp_cmp(&k, &p_1) != -1 || mp_cmp_d(&k, 1) != 1 ||
              mp_cmp_d(&r, 1) != 0)); // 1<=k<p-1且k与p-1互素
    err = mp_exptmod(&a, &k, &p, &r);
    err = mp_to_radix(&r, tempR.get(), SIZE_MAX, &written, 10);
    cout << (format("a**k mod p是:\n{}\n", tempR.get()));

    string str = sha256.ShaFile(config.inText);
    err = mp_read_radix(&sha, str.c_str(), 10);

    err = mp_to_radix(&sha, tempSHA.get(), SIZE_MAX, &written, 0x10);
    cout << (format("SHA是:\n{}\n", tempSHA.get()));

    err = mp_mul(&x, &r, &s);
    err = mp_sub(&sha, &s, &s);
    ex_Eulid(&k, &p_1, &a1, &b1, &temp3);
    while (mp_cmp_d(&a1, 0) != 1 && err == MP_OKAY) {
      err = mp_add(&a1, &p_1, &a1);
    }

    err = mp_to_radix(&a1, tempA1.get(), SIZE_MAX, &written, 10);
    cout << (format("k**-1是:\n{}\n", tempA1.get()));

    err = mp_mulmod(&k, &a1, &p_1, &temp3);
    err = mp_to_radix(&a1, tempT.get(), SIZE_MAX, &written, 10);
    cout << (format("k*k**-1 mod p是:\n{}\n", tempT.get()));
  } break;
  case cryptoGraphic::SHA256: {
    mp_int s;
    size_t written = 0;
    mp_err err = mp_init(&s);
    string a = sha256.ShaFile(config.inText);
    if (err == MP_OKAY) {
      err = mp_read_radix(&s, a.c_str(), 10);
    }
    char tempSHA[800] = {0};
    err = mp_to_radix(&s, tempSHA, SIZE_MAX, &written, 0x10);
    cout << (format("SHA是:\n{}\n", tempSHA));

  } break;
  case cryptoGraphic::RC4: {

  } break;
    // case 7: {
    //	DES d;
    //	string keyStr;
    //	ifstream in;
    //	ofstream out;
    //	bitset<64> data;
    //	uint8_t plain[8];
    //	switch (enDoIndex)
    //	{
    //	case 1:
    //		//keyStr = GetRandList(8);
    //		keyStr = "12345678";
    //		cout << "密钥为：" << keyStr << "(请注意复制保存)" << endl;
    //		in.open(szFullPath, ios::binary);
    //		out.open(fullPath, ios::binary | ios::ate);
    //		if (in.is_open() && out.is_open()) {
    //			string buf((std::istreambuf_iterator<char>(in)),
    //				std::istreambuf_iterator<char>());
    //			buf=d.Encrypt(buf, keyStr);
    //			out.write(buf.c_str(),buf.length());
    //			in.close();
    //			out.close();
    //		}
    //		break;
    //	case 2:
    //		/*cout << "请输入密钥：";
    //		cin >> keyStr;*/
    //		keyStr = "12345678";
    //		if (keyStr.size() == 8) {
    //			in.open(szFullPath, ios::binary);
    //			out.open(fullPath, ios::binary | ios::ate);
    //			if (in.is_open()&&out.is_open()) {
    //				string buf((std::istreambuf_iterator<char>(in)),
    //					std::istreambuf_iterator<char>());
    //				buf = d.Decrypt(buf, keyStr);
    //				out.write(buf.c_str(), buf.length());
    //				in.close();
    //				out.close();
    //			}
    //			cout << "press any key to shutdown" << endl;
    //			std::cin.get();
    //		}
    //		else {
    //			cout << "密钥长度有误";
    //			cout << "press any key to shutdown" << endl;
    //			std::cin.get();
    //		}
    //		break;
    //	}
    // }break;
  case cryptoGraphic::SM3: {
    SM3 sm3;
    FileProc fp(config.inText, fullPath);
    uint8_t hash[32];
    sm3.SM3_HASH256(fp, hash);
    for (unsigned char &i : hash) {
      cout << (format("{}", i));
    }

  } break;
  case cryptoGraphic::SM4: {
    SM4 sm4;
    string key;
    uint8_t *keyStr;
    uint8_t plain[16] = {0};
    uint8_t cipher[16] = {
        0,
    };
    cout << "请输入密钥：";
    cin >> key;
    if (key.size() == 16) {
      keyStr = (uint8_t *)key.c_str();
      FileProc fp(config.inText, fullPath);
      switch (config.cryptoTypeMode) {
      case cryptoType::Encrypt:
        while (fp.read(reinterpret_cast<char *>(plain), sizeof(plain)) != 0) {
          sm4.SM4_Encrypt(keyStr, plain, cipher);
          fp.write((char *)cipher, sizeof(cipher));
        }
        break;
      case cryptoType::Decrypt:
        // 解密 cipher.txt，并写入图片 flower1.jpg
        while (fp.read((char *)cipher, sizeof(cipher)) != 0) {
          sm4.SM4_Decrypt(keyStr, cipher, plain);
          fp.write((char *)plain, sizeof(plain));
        }
        break;
      case cryptoType::Hash:
        break;
      }
    }
  } break;
  case cryptoGraphic::ZUC: {
    ZUC zuc;
    string key;
    uint8_t *keyStr = nullptr;
    uint8_t plain[16] = {0};
    uint8_t cipher[16] = {
        0,
    };
    cout << "请输入密钥：";
    cin >> key;
    if (key.size() == 16) {
      keyStr = (uint8_t *)key.c_str();
      FileProc fp(config.inText, fullPath);
      unsigned seed =
          std::chrono::system_clock::now().time_since_epoch().count();
      std::mt19937 g1(seed);
      uint32_t u32Random = g1();
      switch (config.cryptoTypeMode) {
      case cryptoType::Encrypt:
        while (fp.read((char *)(plain), sizeof(plain)) != 0) {
          // zuc.ZUC_Confidentiality(keyStr, u32Random, );
          fp.write((char *)cipher, sizeof(cipher));
        }
        break;
      case cryptoType::Decrypt:
        // 解密 cipher.txt，并写入图片 flower1.jpg
        while (fp.read((char *)cipher, sizeof(cipher)) != 0) {
          // sm4.SM4_Decrypt(keyStr, cipher, plain);
          fp.write((char *)plain, sizeof(plain));
        }
        break;
      case cryptoType::Hash:
        break;
      }
    }
  } break;
  default:
    break;
  }
}
