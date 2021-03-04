#include"sha256.h"
#include<iostream>
#include <string>
#include <fstream>
/**SHA256函数所使用的8个32bit初始化哈希值
		自然数前六十四个质数的立方根方根的小数部分取前32bit
		*/
uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

SHA256::SHA256()
{

}

SHA256::~SHA256()
{
}

//轮函数
void SHA256::Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k, uint32_t w)
{
	uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
	uint32_t t2 = Sigma0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
}

std::string SHA256::ShaFile(string path)
{
	/**SHA256函数所使用的8个32bit初始化哈希值
	自然数前八个质数的平方根的小数部分取前32bit
	*/
	static const uint32_t init[8] = { 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul };
	uint32_t buf[8];
	memcpy(buf, init, sizeof(buf));

	std::ifstream in;
	in.open(path);
	in.seekg(0, std::ios::end);
	unsigned int length = in.tellg();
	in.seekg(0, std::ios::beg);
	int l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
	std::unique_ptr<char[]> input(new char[l]());
	char ch;
	int i = 0;
	while (!in.eof())
	{
		in.get(ch);
		input.get()[i++] = ch;
	}
	input.get()[i] = 0x80;
	i = l - 1;
	while ((length & 0xff) != 0) {
		int b = length & 0xff;//低八位
		input.get()[i--] = (char)b;
		length = length >> 8;
	}
	Transform(buf, (const unsigned char*)input.get(), l / 64);

	string shaStr;
	for (int i = 0; i < 8; i++)
		shaStr += std::to_string(buf[i]);
	return shaStr;
}

string SHA256::ShaStr(string Str)
{
	/**SHA256函数所使用的8个32bit初始化哈希值
		自然数前八个质数的平方根的小数部分取前32bit
		*/
	static const uint32_t init[8] = { 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul };
	uint32_t buf[8];
	int i = 0;
	memcpy(buf, init, sizeof(buf));
	int length = Str.length();
	int l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
	std::unique_ptr<char[]> input(new char[l]());
	for (; i < length; i++) {
		input.get()[i] = Str.at(i);
	}
	input.get()[i] = 0x80;
	i = l - 1;
	while ((length & 0xff) != 0) {
		int b = length & 0xff;//低八位
		input[i--] = (char)b;
		length = length >> 8;
	}
	const unsigned char* it = (const unsigned char*)input.get();
	Transform(buf, it, l / 64);
	string shaStr;
	for (int i = 0; i < 8; i++)
		shaStr += std::to_string(buf[i]);
	return shaStr;
}
// SHA-256所需要做的64次轮函数 
void  SHA256::Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
	while (blocks--) {
		uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7], i;
		uint32_t w[16];
		for (int j = 0; j < 16; j++) {
			Round(a, b, c, d, e, f, g, h, K[j], w[j] = ReadLE32(chunk + 4 * j));
			i = a; a = h; h = g;
			g = f; f = e; e = d;
			d = c; c = b; b = i;
		}
		for (int j = 0; j < 48; j++) {
			Round(a, b, c, d, e, f, g, h, K[16 + j], w[j % 16] += sigma1(w[(14 + j) % 16]) + w[(9 + j) % 16] + sigma0(w[(1 + j) % 16]));
			i = a; a = h; h = g;
			g = f; f = e; e = d;
			d = c; c = b; b = i;
		}

		s[0] += a;
		s[1] += b;
		s[2] += c;
		s[3] += d;
		s[4] += e;
		s[5] += f;
		s[6] += g;
		s[7] += h;
		chunk += 64;
	}
}
