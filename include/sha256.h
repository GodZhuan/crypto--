#ifndef SHA256_H_
#define SHA256_H_

#include "tommath.h"
#include<iostream>
#include <string>
#include <fstream>

using std::string;
// ∧ 按位“与”
// ¬  按位“补”
// ⊕ 按位“异或”
// Sn 循环右移n个bit 由于uint32_t为三十二位无符号整数所以Sn=x>>n|x<<32-n
// Rn 右移n个bit


//SHA256函数所使用的6个逻辑内联函数
//Ch(x, y, z) = (x∧y)⊕(¬x∧z)
uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ ((~x) & z);
}

//Maj(x, y, z) = (x∧y)⊕(x∧z)⊕(y∧z)Ma(x, y, z)
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

//Σ0(x) = S^2(x)⊕S^13(x)⊕S^22(x)
uint32_t inline Sigma0(uint32_t x)
{
	return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
}

//Σ1(x) = S^6(x)⊕S^11(x)⊕S^25(x)
uint32_t inline Sigma1(uint32_t x)
{
	return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
}

//σ0(x) = S ^ 7(x)⊕S ^ 18(x)⊕R ^ 3(x)
uint32_t inline sigma0(uint32_t x)
{
	return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
}

//σ1(x) = S ^ 17(x)⊕S ^ 19(x)⊕R ^ 10(x)
uint32_t inline sigma1(uint32_t x)
{
	return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
}

// 将变量转换为小端(little endia),因为x86是小端系统
uint32_t static inline ReadLE32(const uint8_t* ptr)
{
	uint32_t x;
	memcpy((char*)&x, ptr, 4);
	return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) |
		((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
}

class SHA256
{
public:
	SHA256();
	~SHA256();
	void Transform(uint32_t* s, const uint8_t* chunk, size_t blocks);
	void Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k, uint32_t w);
	string ShaFile(string path);
	string ShaStr(string path);
private:

};
#endif // !SHA256_H_

