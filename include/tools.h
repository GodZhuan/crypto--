#ifndef _TOOLS_H_
#define _TOOLS_H_ 
#include "aes.h"
#include "tommath.h"
#include<time.h>
#include <random>
namespace crypto__ {
	//ѭ������nλ
	inline uint32_t rotl32(uint32_t buf, int n) {
		return (buf << n) | (buf >> (32 - n));
	}

	/**
	* �������е�Ԫ��ѭ������stepλ
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
	 *  ��һ��char�ַ�����ת��Ϊ������
	 *  �浽һ�� Byte ������
	 */
	void charToByte(uint8_t out[4][4], std::string& s);

	int myrng(uint8_t* dst, int len, void* dat);

	//����ָ���ֳ�������ַ���
	std::string GetRandList(int len);

	void ex_Eulid(mp_int* a, mp_int* b, mp_int* a1, mp_int* b1, mp_int* temp3);
	mp_err constmp_to_radix(const mp_int* a, const char* str, size_t maxlen, size_t* written, int radix);
}
#endif
