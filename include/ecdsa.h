#ifndef _ECDSA_H_
#define _ECDSA_H_
#include<string>
#include "tommath.h"
#include "ecc.h"
#include "sts.h"
namespace crypto__ {
	static const char* rP = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	static const char* rGX = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	static const char* rGY = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	static const char* rn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	class ECDSA
	{
	private:
		mp_err err;
		ECC ecc;
		STS sts;
		int lon;
		size_t written;

		mp_int p;//p为安全素数
		mp_int a;//生成元
		mp_int p_1;//p-1

		mp_int rA;//随机数rA
		mp_int sA;//a**rA mod p

		mp_int rB;//随机数rB
		mp_int sB;//a**rB mod p

		mp_int K;//sA**rB mod p

		mp_int GX;//基点G的x坐标
		mp_int GY;//基点G的y坐标
		mp_int n;//基点G的阶
		mp_int d;//私有密钥
		mp_int h;//h是椭圆曲线上所有点的个数m与n相除的商的整数部分
		mp_int k;//随机数(2 to n-2)
		mp_int A;//曲线Ep系数A
		mp_int B;//曲线Ep系数B
		mp_int PX;//dG的x坐标
		mp_int PY;//dG的x坐标
		mp_int X1;//kG的x坐标
		mp_int Y1;//kG的y坐标
		mp_int u1X;//u1.GX的x坐标
		mp_int u1Y;//u1.GY的y坐标
		mp_int u2X;//u2.PX的x坐标
		mp_int u2Y;//u2.PY的y坐标
		mp_int X2;//u1.GX+u2.PX的x坐标
		mp_int Y2;//u2.PY+u2.PX的y坐标
		mp_int v;//x2 mod n
		bool zero = false;

		mp_int r;//x1 mod n
		mp_int P;//Fp中的p(有限域P)

		mp_int k1;//k的逆元
		mp_int s1;//s的逆元
		mp_int n1;//n的逆元
		mp_int temp;
		mp_int Hm;//H(m)
		mp_int s;//k**-1(H(m)+dA*r) mod n

		mp_int u1;//H(m)s**(-1) mod n
		mp_int u2;//rs**(-1)mod n

		string path;
	public:
		ECDSA();
		~ECDSA();
		void printECDSA(const std::string& sh);
	};
}
#endif // !_ECDSA_H_

