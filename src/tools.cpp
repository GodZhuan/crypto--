#include"../include/tools.h"
namespace crypto__ {
	/**
	 *  将一个char字符数组转化为二进制
	 *  存到一个 Byte 数组中
	 */
	void charToByte(uint8_t out[4][4], std::string& s)
	{
		for (size_t i = 0; i < 4; ++i)
			for (size_t j = 0; j < 4; ++j)
				out[i][j] = s[i * 4 + j];
	}

	int myrng(uint8_t* dst, int len, void* dat)
	{
		int x;
		for (x = 0; x < len; x++) dst[x] = rand() & 0xFF;
		return len;
	}

	//生成指定字长的随机字符串
	std::string GetRandList(int len)
	{
		char strRandomList[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '@', '#', '$', '%', '&', '*', '_' };
		std::string pwd = "";
		std::mt19937 e(static_cast<uint32_t>(time(NULL)));
		std::uniform_int_distribution<unsigned> u(0, 69);
		for (int i = 0; i < len; i++)
		{
			pwd += strRandomList[u(e)];//随机取strRandomList 的项值
		}
		return pwd;
	}

	void ex_Eulid(mp_int* a, mp_int* b, mp_int* a1, mp_int* b1, mp_int* temp3) {
		if (mp_cmp_d(b, 0) == 0) {
			mp_set(a1, 1);
			mp_set(b1, 0);
			mp_copy(temp3, a);
		}
		else {
			mp_int temp1;
			mp_int temp2;
			mp_init(&temp1);
			mp_init(&temp2);
			mp_mod(a, b, &temp1);
			ex_Eulid(b, &temp1, a1, b1, temp3);
			mp_copy(a1, &temp1);
			mp_copy(b1, a1);
			mp_div(a, b, temp3, &temp2);
			mp_mul(temp3, b1, temp3);
			mp_sub(&temp1, temp3, b1);
		}
	}
	mp_err constmp_to_radix(const mp_int* a, const char* str, size_t maxlen, size_t* written, int radix) {
		return mp_to_radix(a, const_cast<char*>(str), maxlen, written, radix);
	}
}