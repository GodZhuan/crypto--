#include <cstdint>
#define _CRT_RAND_S
#include "../include/rc4.h"
#include <fstream>
#include <iostream>
#include <stdlib.h>
using namespace std;
const char *WordList =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

int *RC4::init_Key() {
  uint32_t number;
  rand_r(&number);
  int keylen = static_cast<int>(static_cast<double>(number) / static_cast<double>(RAND_MAX) * 256);
  for (int i = 0; i < keylen; i++) {
    rand_r(&number);
    auto index = static_cast<int>(static_cast<double>(number) / static_cast<double>(RAND_MAX) * 63);
    Key[i] = WordList[index];
  }
  for (int i = 0; i < 256; i++) {
    S[i] = i;
    T[i] = Key[i % keylen];
  }
  return Key;
}

void RC4::permute_S() {
  auto temp = 0;
  auto j = 0;
  for (auto i = 0; i < 256; i++) {
    j = (j + S[i] + T[i]) % 256;
    temp = S[i];
    S[i] = S[j];
    S[j] = temp;
  }
}

string RC4::create_key_stream(string text, string KeyStream) {
  // 生成密钥流
  int i = 0;
  int j = 0;
  int temp = 0;
  int t = 0;
  int textLength = text.length();
  while ((textLength--) != 0) { // 生成密钥流
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    temp = S[i];
    S[i] = S[j];
    S[j] = temp;
    t = (S[i] + S[j]) % 256;
    KeyStream.push_back(S[t]);
  }
  return KeyStream;
}

void RC4::Rc4EncryptText(string text, string KeyStream, string PlainText,
                         string CryptoText, string strPath) {
  cout << this->init_Key() << endl;
  this->permute_S();
  KeyStream = create_key_stream(text, KeyStream);
  cout << "============开始加密============:\n 密文：" << endl;
  ;
  ofstream out;
  out.open(strPath + "textcipher.txt", ios::trunc);
  for (uint32_t i = 0; i < KeyStream.length(); i++) {
    CryptoText.push_back(char(KeyStream[i] ^ text[i])); // 加密
    out << CryptoText[i];
  }
  out.close();
  cout << "\n============加密完成============\n============开始解密============"
          "\n明文："
       << endl;
  out.open(strPath + "textcipherencipher.txt", ios::trunc);
  for (uint32_t i = 0; i < KeyStream.length(); i++) {
    PlainText.push_back(static_cast<char>(KeyStream[i] ^ CryptoText[i])); // 解密
    out << PlainText[i];
  }
  out.close();
  cout << "\n============解密完成============\n\n" << endl;
}

RC4::RC4() = default;

RC4::~RC4() = default;
