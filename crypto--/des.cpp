#include "des.h"
const char DES::PC1_Table[PC_1_SIZE] = {                               //密钥第一次置换矩阵
57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};
const char DES::Move_Table[SUBKEY_NUM] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

const char DES::PC2_Table[PC_2_SIZE] = {
14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const char DES::IP_Table[BIT_STR_SIZE] = {                                     //IP置换矩阵
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

const char DES::Expand_Table[EXPAND_SIZE] = {                                  //扩展矩阵
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1 };

const char DES::Permute_Table[BIT_STR_SIZE / 2] = {                            //  P 盒
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25 };

const char DES::IP_1_Table[BIT_STR_SIZE] = {                                    //逆IP置换矩阵
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25 };

const char DES::SBox_Table[KEY_SZIE][4][16] = {                     //8个S盒   三维数组
// S1
{
14, 4,  13,     1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},
// S2
{
15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},
// S3
{
10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},
// S4
{
7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},
// S5
{
2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},
// S6
{
12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},
// S7
{
4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},
// S8
{
13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}
};

char subKeys[SUBKEY_NUM][SUBKEY_LENGHT];

DES::DES(){}

DES::~DES(){}

std::string DES::Encrypt(const std::string& plain, const std::string& key)
{
	std::string result;
	if (plain.empty() || key.empty())return result;
	if (!CreateSubKey(key))return result;

	for (size_t i = 0; i < plain.size() / 8; ++i)
	{
		std::string block = plain.substr(i * 8, 8);
		EncryptBlock(block);
		result.append(block);
	}
	int remainder = plain.size() % 8;
	if (remainder)
	{
		std::string block = plain.substr(plain.size() - remainder, remainder);
		block.append(8 - remainder, '\0');
		EncryptBlock(block);
		result.append(block);
	}

	return result;
}

std::string DES::Decrypt(const std::string& cipher, const std::string& key)
{
	std::string result;
	if (cipher.empty() || key.empty()|| cipher.size() % 8|| !CreateSubKey(key))return result;

	for (size_t i = 0; i < cipher.size() / 8; ++i)
	{
		std::string block = cipher.substr(i * 8, 8);
		DecryptBlock(block);
		result.append(block);
	}

	return result;
}

bool DES::CreateSubKey(const std::string& key)
{	
	bool bitStr[BIT_STR_SIZE];// 64
	CharToBit(key, bitStr, BIT_STR_SIZE);

	bool PC1BitStr[PC_1_SIZE];//56

	PC1_Transform(bitStr, PC1BitStr);

	for (int i = 0; i < SUBKEY_NUM; ++i)
	{
		LeftCycle(PC1BitStr, Move_Table[i]);

		PC2_Transform(PC1BitStr, subKeys[i]); // 48
	}
	return true;
}

bool DES::EncryptBlock(std::string& block)
{
	if (block.size() != KEY_SZIE)return false;
	bool bitStr[BIT_STR_SIZE];
	CharToBit(block, bitStr, BIT_STR_SIZE);
	IP_Transform(bitStr);
	bool eBitStr[EXPAND_SIZE];

	for (size_t i = 0; i < SUBKEY_NUM; ++i)
	{
		memcpy(eBitStr, bitStr + BIT_STR_SIZE / 2, BIT_STR_SIZE / 2);
		Expand_Transform(eBitStr);

		bool subKey[SUBKEY_LENGHT] = { subKeys[i] };

		XOR(eBitStr, subKey, SUBKEY_LENGHT);

		SBox_Transform(eBitStr);

		Permute_Transform(eBitStr);

		XOR(bitStr, eBitStr, HALF_BIT_STR_SIZE);

		if (i != SUBKEY_NUM - 1) {
				bool temp[HALF_BIT_STR_SIZE];
				memcpy(temp, bitStr, HALF_BIT_STR_SIZE);
				memcpy(bitStr, bitStr+HALF_BIT_STR_SIZE, HALF_BIT_STR_SIZE);
				memcpy(bitStr+HALF_BIT_STR_SIZE, temp, HALF_BIT_STR_SIZE);
		}
	}
	IP_1_Transform(bitStr);

	BitToChar(bitStr, block);

	return false;
}

bool DES::DecryptBlock(std::string& block)
{
	if (block.size() != KEY_SZIE)
		return false;

	bool bitStr[BIT_STR_SIZE];
	CharToBit(block, bitStr,BIT_STR_SIZE);

	IP_Transform(bitStr);
	bool eBitStr[EXPAND_SIZE];
	for (int i = SUBKEY_NUM - 1; i >= 0; --i)
	{
		Expand_Transform(eBitStr);

		bool subKey[SUBKEY_LENGHT] = { subKeys[i] };

		XOR(eBitStr, subKey, SUBKEY_LENGHT);

		SBox_Transform(eBitStr);
		Permute_Transform(eBitStr);

		XOR(bitStr, eBitStr, HALF_BIT_STR_SIZE);

		if (i != 0) {
			bool temp[HALF_BIT_STR_SIZE];
			memcpy(temp, bitStr, HALF_BIT_STR_SIZE);
			memcpy(bitStr, bitStr + HALF_BIT_STR_SIZE, HALF_BIT_STR_SIZE);
			memcpy(bitStr + HALF_BIT_STR_SIZE, temp, HALF_BIT_STR_SIZE);
		}
	}
	IP_1_Transform(bitStr);
	BitToChar(bitStr, block);

	return true;
}

bool DES::PC1_Transform(const std::string& bitStr, std::string& PC1BitStr)
{
	std::string tmpStr;
	tmpStr.resize(PC_1_SIZE);
	for (size_t i = 0; i < PC_1_SIZE; ++i)
		tmpStr[i] = bitStr[PC1_Table[i]];

	PC1BitStr.swap(tmpStr);

	return true;
}

void DES::PC1_Transform(const bool bitStr[BIT_STR_SIZE], bool PC1bitStr[PC_1_SIZE])
{
	for (size_t i = 0; i < PC_1_SIZE; ++i)
		PC1bitStr[i] = bitStr[PC1_Table[i]];
}

void DES::PC2_Transform(const bool PC1bitStr[PC_1_SIZE], bool subKey[SUBKEY_LENGHT])
{
	std::string tmpStr;
	tmpStr.resize(PC_2_SIZE);
	for (size_t i = 0; i < PC_2_SIZE; ++i)
		subKey[i] = PC1bitStr[PC2_Table[i]];
}

bool DES::IP_Transform(bool bitStr[BIT_STR_SIZE])
{
	bool tmpBitStr[BIT_STR_SIZE];
	for (size_t i = 0; i < BIT_STR_SIZE; ++i)
		tmpBitStr[i] = bitStr[IP_Table[i]];
	memcpy(bitStr, tmpBitStr, BIT_STR_SIZE);
	return true;
}

void DES::Expand_Transform(bool eBitStr[EXPAND_SIZE])
{
	bool temp[EXPAND_SIZE];
	for (size_t i = 0; i < EXPAND_SIZE; ++i)
		temp[i] = eBitStr[Expand_Table[i]];
	memcpy(eBitStr, temp, EXPAND_SIZE);
}

void DES::SBox_Transform(bool eBitStr[EXPAND_SIZE])
{
	for (size_t i = 0; i < KEY_SZIE; ++i)
	{
		size_t j = i * 6;
		size_t row = (eBitStr[j] << 1) + eBitStr[j + EXPAND_SIZE / KEY_SZIE - 1];
		size_t column = (eBitStr[j + 1] << 3) + (eBitStr[j + 2] << 2) + (eBitStr[j + 3] << 1) + eBitStr[j + 4];

		int x = SBox_Table[i][row][column];


		eBitStr[i * 4] = x >> 3;
		eBitStr[i * 4 + 1] = (x >> 2) & 0x1;
		eBitStr[i * 4 + 2] = (x >> 1) & 0x1;
		eBitStr[i * 4 + 3] = x & 0x1;

	}
}

void DES::Permute_Transform(bool halfBitStr[HALF_BIT_STR_SIZE])
{
	bool tmpStr[HALF_BIT_STR_SIZE];

	for (size_t i = 0; i < HALF_BIT_STR_SIZE; ++i)
		tmpStr[i] = halfBitStr[Permute_Table[i]];

	memcpy(halfBitStr, tmpStr, HALF_BIT_STR_SIZE);
}

void DES::IP_1_Transform(bool bitStr[BIT_STR_SIZE])
{
	bool tmpStr[BIT_STR_SIZE];
	for (size_t i = 0; i < BIT_STR_SIZE; ++i)
		tmpStr[i] = bitStr[IP_1_Table[i]];
	memcpy(bitStr, tmpStr, BIT_STR_SIZE);
}


void DES::CharToBit(const std::string& str, bool* bitStr, int bits)
{
	for (size_t i = 0; i < bits; ++i)
		bitStr[i] = ((str[i / BITS_PER_CHAR] >> i % BITS_PER_CHAR) & 0x1);
}

void DES::BitToChar(const bool* bitStr, std::string& str)
{
	for (size_t i = 0; i < KEY_SZIE; ++i)
		for (size_t j = 0; j < BITS_PER_CHAR; ++j)
			str[i] |= bitStr[i * KEY_SZIE + j] << j;
}

void DES::XOR(bool strFirst[EXPAND_SIZE], bool strSecond[EXPAND_SIZE], size_t num)
{
	for (size_t i = 0; i < num; ++i)
		strFirst[i] ^= strSecond[i];
}

bool DES::LeftCycle(bool str[PC_1_SIZE], size_t step)
{
	bool temp[PC_1_SIZE];

	//保存将要循环移动到右边的位  
	memcpy(temp, str, step);
	memcpy(temp + step, str + 28, step);

	//前28位移动  
	memcpy(str, str + step, 28 - step);
	memcpy(str + 28 - step, temp, step);

	//后28位移动  
	memcpy(str + 28, str + 28 + step, 28 - step);
	memcpy(str + PC_1_SIZE - step, temp + step, step);

	return true;
}
