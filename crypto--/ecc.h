#ifndef _ECC_H_
#define _ECC_H_
/*　1、用户A选定一条适合加密的椭圆曲线Ep(a,b)(如:y2=x3+ax+b)，并取椭圆曲线上一点，作为基点G。
　　2、用户A选择一个私有密钥k，并生成公开密钥K=kG。
　　3、用户A将Ep(a,b)和点K，G传给用户B。
　　4、用户B接到信息后 ，将待传输的明文编码到Ep(a,b)上一点M，并产生一个随机整数r（r<n）。
　　5、用户B计算点C1=M+rK；C2=rG。
　　6、用户B将C1、C2传给用户A。
　　7、用户A接到信息后，计算C1-kC2，结果就是点M。因为
		  C1-kC2=M+rK-k(rG)=M+rK-r(kG)=M
　　　再对点M进行解码就可以得到明文。

  　　密码学中，描述一条Fp上的椭圆曲线，常用到六个参量：
	   T=(p,a,b,G,n,h)。
　　（p 、a 、b 用来确定一条椭圆曲线，G为基点，n为点G的阶，h 是椭圆曲线上所有点的个数m与n相除的整数部分）

　　这几个参量取值的选择，直接影响了加密的安全性。参量值一般要求满足以下几个条件：

　　1、p 当然越大越安全，但越大，计算速度会变慢，200位左右可以满足一般安全要求；
　　2、p≠n×h；
　　3、pt≠1 (mod n)，1≤t<20；
　　4、4a3+27b2≠0 (mod p)；
　　5、n 为素数；
　　6、h≤4。
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "tommath.h"
#include <time.h>
using namespace std;


constexpr auto BIT_LEN = 800 ;
constexpr auto KEY_LONG = 256;  //私钥比特长;
constexpr auto P_LONG = 200;    //有限域P比特长;
constexpr auto EN_LONG = 40;    //一次取明文字节数(x,20)(y,20);

class ECC
{
private:
	mp_int GX;//基点G的x坐标
	mp_int GY;//基点G的y坐标
	mp_int K;//私有密钥
	mp_int A;//曲线参数A
	mp_int B;//曲线参数B
	mp_int QX;//公钥Q的x坐标
	mp_int QY;//公钥Q的y坐标
	mp_int P;//Fp中的p(有限域P)
	mp_err err;

	string temp;
	string tempA;
	string tempB;
	string tempGX;
	string tempGY;
	string tempK;
	string tempQX;
	string tempQY;
public:
	ECC();
	~ECC();
	//创建椭圆生成参数
	void BuildParameters(void);
	//打印椭圆曲线参数并保存到文件夹
	void PrintParameters(void);
	std::string Encrypt(const std::string& plain, const std::string& key);
	std::string Decrypt(const std::string& cipher, const std::string& key);

	//得到lon比特长素数
	int GetPrime(mp_int* m, int lon);
	//得到B和G点X坐标G点Y坐标
	void Get_B_X_Y(mp_int* x1, mp_int* y1, mp_int* b, mp_int* a, mp_int* p);
	//点乘
	bool Ecc_points_mul(mp_int* qx, mp_int* qy, mp_int* px, mp_int* py, mp_int* d, mp_int* a, mp_int* p);
	//点加
	int Two_points_add(mp_int* x1, mp_int* y1, mp_int* x2, mp_int* y2, mp_int* x3, mp_int* y3, mp_int* a, bool zero, mp_int* p);
	//二进制存储密文
	int chmistore(mp_int* a, FILE* fp);
	//把读取的字符存入mp_int型数
	int putin(mp_int* a, char* ch, int chlong);
	//ECC加密
	void Ecc_encipher(char* inPath,string outPath);
	//ECC密钥保存
	void Ecc_saveKey(string outPath);
	//ECC密钥读取
	void Ecc_loadKey(string inPath);
	//ECC解密
	void Ecc_decipher(char* inPath, string outPath);
	//实现将mp_int数a中的比特串还原为字符串并赋给字符串ch：
	int chdraw(mp_int* a, char* ch);
	//取密文
	int miwendraw(mp_int* a, char* ch, int chlong);

};
#endif // !_ECC_H_

