#ifndef _DES_H_
#define _DES_H_

#include <string>

const unsigned BITS_PER_CHAR = 8;
const unsigned KEY_SZIE = 8;
const unsigned SUBKEY_NUM = 16;
const unsigned SUBKEY_LENGHT = 48;
const unsigned EXPAND_SIZE = 48;
const unsigned PC_2_SIZE = 48;
const unsigned PC_1_SIZE = 56;
const unsigned BIT_STR_SIZE = 64;
const unsigned HALF_BIT_STR_SIZE=BIT_STR_SIZE / 2;

class DES
{
private:
	//------------------------------------生成秘钥需要的表----------------------------------------
	//置换选择表1
	//压缩换位去掉每个字节的第8位，用作奇偶校检，基本上第8位可忽略
	static const unsigned int PC1_Table[PC_1_SIZE];
	//左循环距离表
	static const unsigned int Move_Table[SUBKEY_NUM];
	//置换选择表2
	//选择其中的某些位将其减少到48位
	static const unsigned int PC2_Table[PC_2_SIZE];
	//子密钥
	volatile bool subKeys[SUBKEY_NUM][SUBKEY_LENGHT];
	//----------------------------------加密或解密需要的表--------------------------------------------
	//初始置换表
	//表中的数值表示输入为被置换后的新位置
	static const unsigned int IP_Table[BIT_STR_SIZE];
	//扩展表
	//通过重复某些位将32位的右半部分按照表扩展成48位
	static const unsigned int Expand_Table[EXPAND_SIZE];
	//单纯置换表
	static const unsigned int Permute_Table[BIT_STR_SIZE / 2];
	//反置换表
	static const unsigned int IP_1_Table[BIT_STR_SIZE];
	//置换盒
	static const unsigned int SBox_Table[KEY_SZIE][4][16];
private:
	//生成16个子秘钥
	bool CreateSubKey(const std::string& key);

	//加密8字节数据块
	bool EncryptBlock(std::string& block);
	//解密8字节数据块
	bool DecryptBlock(std::string& block);

	//----------------------------------转换工具-----------------------------------------------
	bool PC1_Transform(const std::string& bitStr, std::string& PC1BitStr);
	void PC1_Transform(const bool bitStr[BIT_STR_SIZE], bool PC1bitStr[PC_1_SIZE]);

	void PC2_Transform(const bool PC1bitStr[PC_1_SIZE], volatile bool subKey[SUBKEY_LENGHT]);

	bool IP_Transform(bool bitStr[BIT_STR_SIZE]);

	void Expand_Transform(bool eBitStr[EXPAND_SIZE]);

	void SBox_Transform(bool eBitStr[EXPAND_SIZE]);

	void Permute_Transform(bool halfBitStr[HALF_BIT_STR_SIZE]);

	void IP_1_Transform(bool bitStr[BIT_STR_SIZE]);

	//------------------------------------基础工具------------------------------------------------
	void CharToBit(const std::string& str, bool* bitStr, int bits);
	void BitToChar(const bool* bitStr, std::string& str);

	void XOR(bool strFirst[EXPAND_SIZE], bool strSecond[EXPAND_SIZE], size_t num);

	bool LeftCycle(bool str[PC_1_SIZE], size_t step);
public:
	DES();
	~DES();

	std::string Encrypt(const std::string& plain, const std::string& key);
	std::string Decrypt(const std::string& cipher, const std::string& key);
};

#endif
