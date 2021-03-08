#ifndef _SM3_H_
#define _SM3_H_
#include <string.h>
#include "tools.h"
namespace crypto__ {
	class SM3
	{
	private:
		typedef struct {
			unsigned int state[8];
			unsigned int length;
			unsigned int curlen;
			unsigned char buf[64];
		} SM3_STATE;
		constexpr static unsigned int SM3_len = 256;
		constexpr static unsigned int SM3_T1 = 0x79CC4519;
		constexpr static unsigned int SM3_T2 = 0x7A879D8A;
		constexpr static unsigned int SM3_IVA = 0x7380166f;
		constexpr static unsigned int SM3_IVB = 0x4914b2b9;
		constexpr static unsigned int SM3_IVC = 0x172442d7;
		constexpr static unsigned int SM3_IVD = 0xda8a0600;
		constexpr static unsigned int SM3_IVE = 0xa96f30bc;
		constexpr static unsigned int SM3_IVF = 0x163138aa;
		constexpr static unsigned int SM3_IVG = 0xe38dee4d;
		constexpr static unsigned int SM3_IVH = 0xb0fb0e4e;
		/* Various logical functions */
		/*inline unsigned int SM3_rotl32(unsigned int x, int n) {
			return (x << n) | (x >> (32 - n));
		}*/
		inline unsigned int SM3_rotr32(unsigned int x, int n) {
			return(x >> n) | (x << (32 - n));
		}
		inline unsigned int SM3_p1(unsigned int x) {
			return x ^ rotl32(x, 15) ^ rotl32(x, 23);
		}
		inline unsigned int SM3_p0(unsigned int x) {
			return x ^ rotl32(x, 9) ^ rotl32(x, 17);
		}
		inline unsigned int SM3_ff0(unsigned int a, unsigned int b, unsigned int c) {
			return a ^ b ^ c;
		}
		inline unsigned int SM3_ff1(unsigned int a, unsigned int b, unsigned int c) {
			return(a & b) | (a & c) | (b & c);
		}
		inline unsigned int SM3_gg0(unsigned int e, unsigned int f, unsigned int g) {
			return e ^ f ^ g;
		}
		inline unsigned int SM3_gg1(unsigned int e, unsigned int f, unsigned int g) {
			return (e & f) | ((~e) & g);
		}
	private:
		void BiToW(unsigned int Bi[], unsigned int W[]);
		void WToW1(unsigned int W[], unsigned int W1[]);
		void CF(unsigned int W[], unsigned int W1[], unsigned int V[]);
		void BigEndian(unsigned char src[], unsigned int bytelen, unsigned char des[]);
		void SM3_init(SM3_STATE* md);
		void SM3_compress(SM3_STATE* md);
		void SM3_process(SM3_STATE* md, unsigned char buf[], int len);
		void SM3_done(SM3_STATE* md, unsigned char hash[]);
		void SM3_256(unsigned char buf[], int len, unsigned char hash[]);
		
	public:
		SM3() {};
		~SM3() {};
		int SM3_SelfTest();
	};
}
#endif