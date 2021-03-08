#ifndef _AES_H_
#define _AES_H_

#include <bitset> 
using std::bitset;
#include"tommath.h"
namespace crypto__ {
	typedef bitset<8> byte;
	typedef bitset<32> word;

	const unsigned char Nr = 10; // AES-128需要 10 轮加密 
	const unsigned char Nk = 4; // Nk 表示输入密钥的 word 个数 


	class AES
	{
	public:
		//密钥扩展算法
		void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]);

		//加密
		void encrypt(byte in[4 * 4], word w[4 * (Nr + 1)]);

		//解密
		void decrypt(byte in[4 * 4], word w[4 * (Nr + 1)]);
		AES();
		~AES();
	private:

		byte GFMul(byte a, byte b);
		void AddRoundKey(byte mtx[4 * 4], word k[4]);
		//----------------------------------转换工具-----------------------------------------------

		//字节替换变换
		void SubBytes(byte mtx[4 * 4]);
		void InvSubBytes(byte mtx[4 * 4]);

		//行移位变换
		void ShiftRows(byte mtx[4 * 4]);
		void InvShiftRows(byte mtx[4 * 4]);

		//列混合变换
		void MixColumns(byte mtx[4 * 4]);
		void InvMixColumns(byte mtx[4 * 4]);

	private:
		//----------------------------------基础工具------------------------------------------------

		//将4个 byte 转换为一个 word
		word Word(byte& k1, byte& k2, byte& k3, byte& k4);

		//按字节 循环左移一位，
		//即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]
		word RotWord(word& rw);

		//对输入word中的每一个字节进行S-盒变换	 
		word SubWord(word& sw);
	};
}
#endif