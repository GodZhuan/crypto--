#include "../include/crypto--.h"
#include "../include/aes.h"
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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdlib.h>
using namespace crypto__;
using std::cin;
using std::cout;
namespace fs = std::filesystem;
mp_err err;

int main(int argc, char *argv[]) {
  if (argc < 4)
    return 1;
  // 选择处理文件或者是消息
  if (!strcmp(argv[1], "-f"))
    config.contentsTypeMode = contentsType::File;
  else if (!strcmp(argv[1], "-m"))
    config.contentsTypeMode = contentsType::Message;

  // 选择加密或者是解密或者是哈希
  if (!strcmp(argv[2], "-e"))
    config.cryptoTypeMode = cryptoType::Encrypt;
  else if (!strcmp(argv[2], "-d"))
    config.cryptoTypeMode = cryptoType::Decrypt;
  else if (!strcmp(argv[2], "-h"))
    config.cryptoTypeMode = cryptoType::Hash;

  switch (config.cryptoTypeMode) {
  case cryptoType::Hash: {
    if (!strcmp(argv[3], "sha256"))
      config.cryptoGraphicMode = cryptoGraphic::SHA256;
    else if (!strcmp(argv[3], "zuc"))
      config.cryptoGraphicMode = cryptoGraphic::ZUC;
  } break;
  case cryptoType::Encrypt:
  case cryptoType::Decrypt: {
    // 选择算法
    if (!strcmp(argv[3], "aes"))
      config.cryptoGraphicMode = cryptoGraphic::AES;
    else if (!strcmp(argv[3], "ecc"))
      config.cryptoGraphicMode = cryptoGraphic::ECC;
    else if (!strcmp(argv[3], "ecdsa"))
      config.cryptoGraphicMode = cryptoGraphic::ECDSA;
    else if (!strcmp(argv[3], "ElGamal"))
      config.cryptoGraphicMode = cryptoGraphic::ElGamal;
    else if (!strcmp(argv[3], "rc4"))
      config.cryptoGraphicMode = cryptoGraphic::RC4;
    else if (!strcmp(argv[3], "sm3"))
      config.cryptoGraphicMode = cryptoGraphic::SM3;
    else if (!strcmp(argv[3], "sm4"))
      config.cryptoGraphicMode = cryptoGraphic::SM4;
    else if (!strcmp(argv[3], "zuc"))
      config.cryptoGraphicMode = cryptoGraphic::ZUC;
  } break;
  }
  CRYPTO__ c;
}

CRYPTO__::CRYPTO__() {
  SHA256 sha256;
  int ret;
  std::string szFullPath, dirPath, fileName, ext, msg;
  fs::path fullPath;
  switch (config.contentsTypeMode) {
  case contentsType::File: {
    cout << "请输入要计算文件的位置" << endl;
    cin >> szFullPath;
    fullPath = szFullPath;
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
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt:
      cout << "请输入要加密消息:" << endl;
      cin >> msg;
      break;
    case cryptoType::Decrypt:
      cout << "请输入要解密消息:" << endl;
      cin >> msg;
      break;
    }
  } break;
  }

  switch (config.cryptoGraphicMode) {
  case cryptoGraphic::AES: {
    string keyStr;
    cout << "请输入密钥：";
    cin >> keyStr;
    FileProc fp(szFullPath, fullPath);
    switch (config.cryptoTypeMode) {
    case cryptoType::Encrypt:
      encrypt(fp, keyStr, 16);
      break;
    case cryptoType::Decrypt:
      decrypt(fp, keyStr, 16);
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

      printf("\n---------------------------------------------------------------"
             "---------\n");
      e.Ecc_encipher(szFullPath.data(), fullPath); // 加密
      break;
    case cryptoType::Decrypt:
      printf("\n---------------------------------------------------------------"
             "---------\n");
      e.Ecc_loadKey(dirPath);
      e.Ecc_decipher(szFullPath.data(), fullPath); // 解密

      break;
    }

  } break;
  case cryptoGraphic::ECDSA: {
    ECDSA ecdsa;
    ecdsa.printECDSA(sha256.ShaFile(szFullPath));
  } break;
  case cryptoGraphic::ElGamal: {
    ECC ecc;
    STS sts;

    int lon;
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

    std::unique_ptr<char[]> tempY(new char[800]());
    std::unique_ptr<char[]> tempR(new char[800]());
    std::unique_ptr<char[]> tempSHA(new char[800]());
    std::unique_ptr<char[]> tempA1(new char[800]());
    std::unique_ptr<char[]> tempT(new char[800]());

    try {
      if ((err = mp_init(&p)) != MP_OKAY) {
        throw("Error initializing the p. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&a)) != MP_OKAY) {
        throw("Error initializing the a. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&p_1)) != MP_OKAY) {
        throw("Error initializing the p_1. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&x)) != MP_OKAY) {
        throw("Error initializing the x. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&y)) != MP_OKAY) {
        throw("Error initializing the y. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&a)) != MP_OKAY) {
        throw("Error initializing the a. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&k)) != MP_OKAY) {
        throw("Error initializing the k. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&r)) != MP_OKAY) {
        throw("Error initializing the r. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&s)) != MP_OKAY) {
        throw("Error initializing the s. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&sha)) != MP_OKAY) {
        throw("Error initializing the sha. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&a1)) != MP_OKAY) {
        throw("Error initializing the a1. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&b1)) != MP_OKAY) {
        throw("Error initializing the b1. %s", mp_error_to_string(err));
      }
      if ((err = mp_init(&temp3)) != MP_OKAY) {
        throw("Error initializing the temp3. %s", mp_error_to_string(err));
      }

    } catch (const char *init_err) {
      cout << init_err << endl;
    }

    cout << "请输入大素数的位数：";
    cin >> lon;
    sts.GetPrime(&p, &a, lon);
    mp_sub_d(&p, 1, &p_1);
    do {
      mp_rand(&x, lon);
    } while (mp_cmp(&x, &p_1) != -1 && mp_cmp_d(&x, 1) != 1); // 1<=x<p-1
    mp_exptmod(&a, &x, &p, &y);
    printf("y是:\n");
    mp_to_radix(&y, tempY.get(), SIZE_MAX, &written, 10);
    printf("%s\n", tempY.get());
    do {
      mp_rand(&k, lon / 26);
      mp_gcd(&k, &p_1, &r); // 互素
    } while (mp_cmp(&k, &p_1) != -1 || mp_cmp_d(&k, 1) != 1 ||
             mp_cmp_d(&r, 1) != 0); // 1<=k<p-1且k与p-1互素
    mp_exptmod(&a, &k, &p, &r);
    printf("a**k mod p是:\n");
    mp_to_radix(&r, tempR.get(), SIZE_MAX, &written, 10);
    printf("%s\n", tempR.get());
    string str = sha256.ShaFile(szFullPath);
    mp_read_radix(&sha, str.c_str(), 10);
    printf("SHA是:\n");
    mp_to_radix(&sha, tempSHA.get(), SIZE_MAX, &written, 0x10);
    printf("%s\n", tempSHA.get());
    mp_mul(&x, &r, &s);
    mp_sub(&sha, &s, &s);
    ex_Eulid(&k, &p_1, &a1, &b1, &temp3);
    while (mp_cmp_d(&a1, 0) != 1)
      mp_add(&a1, &p_1, &a1);
    printf("k**-1是:\n");
    mp_to_radix(&a1, tempA1.get(), SIZE_MAX, &written, 10);
    printf("%s\n", tempA1.get());
    mp_mulmod(&k, &a1, &p_1, &temp3);
    printf("k*k**-1 mod p是:\n");
    mp_to_radix(&a1, tempT.get(), SIZE_MAX, &written, 10);
    printf("%s\n", tempT.get());
  } break;
  case cryptoGraphic::SHA256: {
    mp_int s;
    size_t written;
    mp_init(&s);
    string a = sha256.ShaFile(szFullPath);
    mp_read_radix(&s, a.c_str(), 10);
    char tempSHA[800] = {0};
    printf("SHA是:\n");
    mp_to_radix(&s, tempSHA, SIZE_MAX, &written, 0x10);
    printf("%s\n", tempSHA);

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
    FileProc fp(szFullPath, fullPath);
    uint8_t hash[32];
    sm3.SM3_HASH256(fp, hash);
    for (auto i = 0; i < sizeof(hash); i++) {
      printf("%x", hash[i]);
    }

  } break;
  case cryptoGraphic::SM4: {
    SM4 sm4;
    string key;
    uint8_t *keyStr, plain[16] = {0},
                     cipher[16] = {
                         0,
                     };
    cout << "请输入密钥：";
    cin >> key;
    if (key.size() == 16) {
      keyStr = (uint8_t *)key.c_str();
      FileProc fp(szFullPath, fullPath);
      switch (config.cryptoTypeMode) {
      case cryptoType::Encrypt:
        while (fp.read((char *)(plain), sizeof(plain))) {
          sm4.SM4_Encrypt(keyStr, plain, cipher);
          fp.write((char *)cipher, sizeof(cipher));
        }
        break;
      case cryptoType::Decrypt:
        // 解密 cipher.txt，并写入图片 flower1.jpg
        while (fp.read((char *)cipher, sizeof(cipher))) {
          sm4.SM4_Decrypt(keyStr, cipher, plain);
          fp.write((char *)plain, sizeof(plain));
        }
        break;
      }
    }
  } break;
  case cryptoGraphic::ZUC: {
    ZUC zuc;
    string key;
    uint8_t *keyStr, plain[16] = {0},
                     cipher[16] = {
                         0,
                     };
    cout << "请输入密钥：";
    cin >> key;
    if (key.size() == 16) {
      keyStr = (uint8_t *)key.c_str();
      FileProc fp(szFullPath, fullPath);
      unsigned seed =
          std::chrono::system_clock::now().time_since_epoch().count();
      std::mt19937 g1(seed);
      uint32_t u32Random = g1();
      switch (config.cryptoTypeMode) {
      case cryptoType::Encrypt:
        while (fp.read((char *)(plain), sizeof(plain))) {
          // zuc.ZUC_Confidentiality(keyStr, u32Random, );
          fp.write((char *)cipher, sizeof(cipher));
        }
        break;
      case cryptoType::Decrypt:
        // 解密 cipher.txt，并写入图片 flower1.jpg
        while (fp.read((char *)cipher, sizeof(cipher))) {
          // sm4.SM4_Decrypt(keyStr, cipher, plain);
          fp.write((char *)plain, sizeof(plain));
        }
        break;
      }
    }
  } break;
  default:
    break;
  }
}
