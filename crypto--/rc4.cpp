#define _CRT_RAND_S  
#include <stdlib.h>  
#include<iostream>
#include<fstream>
#include<bitset>
#include<time.h>
#include<string>
#include "rc4.h"
using namespace std;
const char* WordList = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

int* RC4::init_Key() {
    int index;
    unsigned int number;
    rand_s(&number);
    int keylen = int(double(number) / double(RAND_MAX) * 256);
    for (int i = 0; i < keylen; i++) {
        rand_s(&number);
        index = int(double(number) / double(RAND_MAX) * 63);
        Key[i] = WordList[index];
    }
    for (int i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = Key[i % keylen];
    }
    return Key;
}

void  RC4::permute_S()
{
    int temp;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

string RC4::create_key_stream(string text, string KeyStream)
{
    // 生成密钥流
    int i, j;
    int temp, t;
    i = j = 0;
    int textLength = text.length();
    while (textLength--) {   //生成密钥流
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


void RC4::Rc4EncryptText(string text, string KeyStream, string PlainText, string CryptoText, string strPath)
{
    cout << this->init_Key() << endl;
    this->permute_S();
    KeyStream = create_key_stream(text, KeyStream);
    cout << "============开始加密============:\n 密文：" << endl;;
    ofstream out;
    out.open(strPath + "textcipher.txt", ios::trunc);
    for (unsigned int i = 0; i < KeyStream.length(); i++) {
        CryptoText.push_back(char(KeyStream[i] ^ text[i])); //加密
        out << CryptoText[i];
    }
    out.close();
    cout << "\n============加密完成============\n============开始解密============\n明文：" << endl;
    out.open(strPath + "textcipherencipher.txt", ios::trunc);
    for (unsigned int i = 0; i < KeyStream.length(); i++) {
        PlainText.push_back(char(KeyStream[i] ^ CryptoText[i]));   //解密
        out << PlainText[i];
    }
    out.close();
    cout << "\n============解密完成============\n" << endl;
    printf("\n");

}

RC4::RC4()
{
}

RC4::~RC4()
{
}
