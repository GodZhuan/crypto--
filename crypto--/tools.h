#ifndef _TOOLS_H_
#define _TOOLS_H_ 
#include "aes.h"
#include<time.h>
#include <random>
namespace crypto__ {
	//循环左移n位
	inline unsigned int rotl32(unsigned int buf, int n) {
		return (buf << n) | (buf >> (32 - n));
	}
	/**
	 *  将一个char字符数组转化为二进制
	 *  存到一个 byte 数组中
	 */
	bool charToByte(byte out[16], std::string& s);

	/**
	 *  将连续的128位分成16组，存到一个 byte 数组中
	 */
	void divideToByte(byte out[16], bitset<128>& data);


	/**
	 *  将16个 byte 合并成连续的128位
	 */
	bitset<128> mergeByte(byte in[16]);
	int myrng(unsigned char* dst, int len, void* dat);

	//生成指定字长的随机字符串
	std::string GetRandList(int len);

	void ex_Eulid(mp_int* a, mp_int* b, mp_int* a1, mp_int* b1, mp_int* temp3);
	mp_err constmp_to_radix(const mp_int* a, const char* str, size_t maxlen, size_t* written, int radix);
}
#endif
