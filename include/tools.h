#ifndef _TOOLS_H_
#define _TOOLS_H_ 
#include "aes.h"
#include "tommath.h"
#include<time.h>
#include <random>
namespace crypto__ {
	//循环左移n位
	inline uint32_t rotl32(uint32_t buf, int n) {
		return (buf << n) | (buf >> (32 - n));
	}

	/**
	* 将数组中的元素循环左移step位
	*/
	static void leftLoop4int(uint8_t array[4], int step) {
		uint8_t temp[4];
		for (int i = 0; i < 4; i++)
			temp[i] = array[i];

		int index = step % 4 == 0 ? 0 : step % 4;
		for (int i = 0; i < 4; i++) {
			array[i] = temp[index];
			index++;
			index = index % 4;
		}
	}
	/**
	 *  将一个char字符数组转化为二进制
	 *  存到一个 Byte 数组中
	 */
	void charToByte(uint8_t out[4][4], std::string& s);

	int myrng(uint8_t* dst, int len, void* dat);

	//生成指定字长的随机字符串
	std::string GetRandList(int len);

	void ex_Eulid(mp_int* a, mp_int* b, mp_int* a1, mp_int* b1, mp_int* temp3);
	mp_err constmp_to_radix(const mp_int* a, const char* str, size_t maxlen, size_t* written, int radix);
}
#endif
