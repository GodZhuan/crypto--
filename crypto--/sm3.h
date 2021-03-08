#ifndef _SM3_H_
#define _SM3_H_
#include <string.h>
#include "tools.h"
namespace crypto__ {
	class SM3
	{
	private:
		typedef struct {
			uint32_t state[8];
			uint32_t length;
			uint32_t curlen;
			uint8_t buf[64];
		} SM3_STATE;
		constexpr static uint32_t SM3_len = 256;
		constexpr static uint32_t SM3_T1 = 0x79CC4519;
		constexpr static uint32_t SM3_T2 = 0x7A879D8A;
		constexpr static uint32_t SM3_IVA = 0x7380166f;
		constexpr static uint32_t SM3_IVB = 0x4914b2b9;
		constexpr static uint32_t SM3_IVC = 0x172442d7;
		constexpr static uint32_t SM3_IVD = 0xda8a0600;
		constexpr static uint32_t SM3_IVE = 0xa96f30bc;
		constexpr static uint32_t SM3_IVF = 0x163138aa;
		constexpr static uint32_t SM3_IVG = 0xe38dee4d;
		constexpr static uint32_t SM3_IVH = 0xb0fb0e4e;
		/* Various logical functions */
		/*inline uint32_t SM3_rotl32(uint32_t x, int n) {
			return (x << n) | (x >> (32 - n));
		}*/
		inline uint32_t SM3_rotr32(uint32_t x, int n) {
			return(x >> n) | (x << (32 - n));
		}
		inline uint32_t SM3_p1(uint32_t x) {
			return x ^ rotl32(x, 15) ^ rotl32(x, 23);
		}
		inline uint32_t SM3_p0(uint32_t x) {
			return x ^ rotl32(x, 9) ^ rotl32(x, 17);
		}
		inline uint32_t SM3_ff0(uint32_t a, uint32_t b, uint32_t c) {
			return a ^ b ^ c;
		}
		inline uint32_t SM3_ff1(uint32_t a, uint32_t b, uint32_t c) {
			return(a & b) | (a & c) | (b & c);
		}
		inline uint32_t SM3_gg0(uint32_t e, uint32_t f, uint32_t g) {
			return e ^ f ^ g;
		}
		inline uint32_t SM3_gg1(uint32_t e, uint32_t f, uint32_t g) {
			return (e & f) | ((~e) & g);
		}
	private:
		void BiToW(uint32_t Bi[], uint32_t W[]);
		void WToW1(uint32_t W[], uint32_t W1[]);
		void CF(uint32_t W[], uint32_t W1[], uint32_t V[]);
		void BigEndian(uint8_t src[], uint32_t uint8_tlen, uint8_t des[]);
		void SM3_init(SM3_STATE* md);
		void SM3_compress(SM3_STATE* md);
		void SM3_process(SM3_STATE* md, uint8_t buf[], int len);
		void SM3_done(SM3_STATE* md, uint8_t hash[]);
		void SM3_256(uint8_t buf[], int len, uint8_t hash[]);
		
	public:
		SM3() {};
		~SM3() {};
		int SM3_SelfTest();
	};
}
#endif