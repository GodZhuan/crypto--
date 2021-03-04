#define _CRT_RAND_S  
#include <stdlib.h> 
#include<iostream>
#include <fstream>
#include"aes.h"
#include"ecc.h"
#include"tools.h"
#include "sts.h"
#include "sha256.h"
#include "des.h"



mp_err(err);
int main(int argc, char* argv[])
{

	SHA256 sha256;
	int index,enDoIndex, ret;
	char szFullPath[_MAX_PATH], szDrive[_MAX_DRIVE], szDir[_MAX_DIR], szFileName[_MAX_FNAME], szExt[_MAX_EXT];
	std::string fullPath,dirPath;
	cout << "crypto--" << endl;
	cout << "1.AES加解密" << endl;
	cout << "2.ECC加解密" << endl;
	cout << "3.ECDSA签名及STS密钥协商协议" << endl;
	cout << "4.ElGamal数字签名" << endl;
	cout << "5.SHA256哈希散列" << endl;
	cout << "6.RC4流式加解密" << endl;
	cout << "7.DES加解密" << endl;
	cin >> index;
	cout << "请输入要计算文件的位置" << endl;
	cin >> szFullPath;
	ret = _splitpath_s(szFullPath, szDrive, szDrive ? _MAX_DRIVE : 0, szDir, szDir ? _MAX_DIR : 0, szFileName, szFileName ? _MAX_FNAME : 0, szExt, szExt ? _MAX_EXT : 0);
	if (ret)return ret;
	if (index != 5) {
		cout << "1.加密" << endl;
		cout << "2.解密" << endl;
		cin >> enDoIndex;
		dirPath += szDrive ? szDrive : "";
		dirPath += szDir ? szDir : "";
		fullPath = dirPath;
		switch (enDoIndex)
		{
		case 1:
			fullPath += szFileName ? szFileName : "";
			fullPath += "cipher.txt";
			break;
		case 2:
			std::string outFName;
			cout << "输入解密后的文件名（形似hello.cpp）" << endl;
			cin >> outFName;
			fullPath += outFName;
			break;
		}
	}
	switch (index)
	{
	case 1: {
		AES a;
		string keyStr;
		byte key[16];
		// 密钥扩展
		word w[4 * (Nr + 1)];
		bitset<128> data;
		byte plain[16];
		ifstream in;
		ofstream out;
		switch (enDoIndex)
		{
		case 1:
			keyStr = GetRandList(16);
			cout <<"密钥为："<< keyStr<<"(请注意复制保存)"<<endl;
			charToByte(key, keyStr);
			a.KeyExpansion(key, w);
			in.open(szFullPath, ios::binary);
			out.open(fullPath, ios::binary|ios::ate);
			while (in.read((char*)&data, sizeof(data)))
			{
				divideToByte(plain, data);
				a.encrypt(plain, w);
				data = mergeByte(plain);
				out.write((char*)&data, sizeof(data));
				data.reset();  // 置0
			}
			in.close();
			out.close();
			cout << "press any key to shutdown" << endl;
			std::cin.get();
			break;
		case 2:
			cout << "请输入密钥：";
			cin >> keyStr;
			if (keyStr.size() == 16) {
				charToByte(key, keyStr);
				a.KeyExpansion(key, w);
				// 解密 cipher.txt，并写入图片 flower1.jpg
				in.open(szFullPath, ios::binary);
				out.open(fullPath, ios::binary);
				while (in.read((char*)&data, sizeof(data)))
				{
					divideToByte(plain, data);
					a.decrypt(plain, w);
					data = mergeByte(plain);
					out.write((char*)&data, sizeof(data));
					data.reset();  // 置0
				}
				in.close();
				out.close();
				cout << "press any key to shutdown" << endl;
				std::cin.get();
			}
			else {
				cout << "密钥长度有误";
				cout << "press any key to shutdown" << endl;
				std::cin.get();
			}	
			break;
		}
	}
		  break;
	case 2: {
		ECC e;
		
		cout << "\n          本程序实现椭圆曲线的加密解密" << endl;
		cout << "\n------------------------------------------------------------------------\n" << endl;
		switch (enDoIndex)
		{
		case 1:
			time_t t;
			srand((unsigned)time(&t));
			e.BuildParameters();
			e.PrintParameters();
			//传入密钥和密钥文件所在文件夹
			e.Ecc_saveKey(dirPath);

			printf("\n------------------------------------------------------------------------\n");
			e.Ecc_encipher(szFullPath, fullPath);//加密
			break;
		case 2:
			printf("\n------------------------------------------------------------------------\n");
			e.Ecc_loadKey(dirPath);
			e.Ecc_decipher(szFullPath, fullPath);//解密

			break;
		}

	}break;
	case 3: {
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

		std::unique_ptr<char[]> tempN(new char[800]());
		std::unique_ptr<char[]> tempD(new char[800]());
		std::unique_ptr<char[]> tempK(new char[800]());
		std::unique_ptr<char[]> tempPX(new char[800]());
		std::unique_ptr<char[]> tempPY(new char[800]());
		std::unique_ptr<char[]> tempR(new char[800]());
		std::unique_ptr<char[]> tempK1(new char[800]());
		std::unique_ptr<char[]> tempT(new char[800]());
		std::unique_ptr<char[]> tempSHA(new char[800]());
		std::unique_ptr<char[]> tempS(new char[800]());
		std::unique_ptr<char[]> tempS1(new char[800]());
		std::unique_ptr<char[]> tempV(new char[800]());

		const char* rP = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
		const char* rGX = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
		const char* rGY = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
		const char* rn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";


		if ((err = mp_init(&Hm)) != MP_OKAY) {
			printf("Error initializing the Hm. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&s)) != MP_OKAY) {
			printf("Error initializing the s. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&p)) != MP_OKAY) {
			printf("Error initializing the p. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&a)) != MP_OKAY) {
			printf("Error initializing the a. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&rA)) != MP_OKAY) {
			printf("Error initializing the rA. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&sA)) != MP_OKAY) {
			printf("Error initializing the sA. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&rB)) != MP_OKAY) {
			printf("Error initializing the rB. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&sB)) != MP_OKAY) {
			printf("Error initializing the sB. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&K)) != MP_OKAY) {
			printf("Error initializing the K. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&GX)) != MP_OKAY) {
			printf("Error initializing the GX. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&GY)) != MP_OKAY) {
			printf("Error initializing the GY. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init_set(&n, 1)) != MP_OKAY) {
			printf("Error initializing the n. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init_set(&h, 1)) != MP_OKAY) {
			printf("Error initializing the h. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&d)) != MP_OKAY) {
			printf("Error initializing the d. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&k)) != MP_OKAY) {
			printf("Error initializing the k. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init_set(&A, 0)) != MP_OKAY) {
			printf("Error initializing the A. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init_set(&B, 7)) != MP_OKAY) {
			printf("Error initializing the B. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&PX)) != MP_OKAY) {
			printf("Error initializing the PX. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&PY)) != MP_OKAY) {
			printf("Error initializing the PY. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&X1)) != MP_OKAY) {
			printf("Error initializing the X1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&Y1)) != MP_OKAY) {
			printf("Error initializing the Y1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u1X)) != MP_OKAY) {
			printf("Error initializing the u1X. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u1Y)) != MP_OKAY) {
			printf("Error initializing the u1Y. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u2X)) != MP_OKAY) {
			printf("Error initializing the u2X. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u2Y)) != MP_OKAY) {
			printf("Error initializing the u2Y. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&X2)) != MP_OKAY) {
			printf("Error initializing the X2. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&Y2)) != MP_OKAY) {
			printf("Error initializing the Y2. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&v)) != MP_OKAY) {
			printf("Error initializing the v. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&r)) != MP_OKAY) {
			printf("Error initializing the r. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&P)) != MP_OKAY) {
			printf("Error initializing the P. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&k1)) != MP_OKAY) {
			printf("Error initializing the k1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&s1)) != MP_OKAY) {
			printf("Error initializing the s1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&n1)) != MP_OKAY) {
			printf("Error initializing the n1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&temp)) != MP_OKAY) {
			printf("Error initializing the temp. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u1)) != MP_OKAY) {
			printf("Error initializing the u1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&u2)) != MP_OKAY) {
			printf("Error initializing the u2. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		n.alloc = 512;
		if ((err = mp_read_radix(&P, rP, 0x10)) != MP_OKAY) {
			printf("mp_read_radix failed: \"%s\"\n",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_read_radix(&GX, rGX, 0x10)) != MP_OKAY) {
			printf("mp_read_radix failed: \"%s\"\n",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_read_radix(&GY, rGY, 0x10)) != MP_OKAY) {
			printf("mp_read_radix failed: \"%s\"\n",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_read_radix(&n, rn, 0x10)) != MP_OKAY) {
			printf("mp_read_radix failed: \"%s\"\n",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}



		cout << "请输入大素数的位数：";
		cin >> lon;
		sts.GetPrime(&p, &a, lon);
		mp_init_copy(&p_1, &p);
		mp_sub_d(&p_1, 2, &p_1);

		do { mp_rand(&rA, lon); } while (mp_cmp(&rA, &p_1) != -1 && mp_cmp_d(&rA, 1) != 1);
		do { mp_rand(&rB, lon); } while (mp_cmp(&rB, &p_1) != -1 && mp_cmp_d(&rB, 1) != 1);
		mp_exptmod(&a, &rA, &p, &sA);
		mp_exptmod(&a, &rB, &p, &sB);
		mp_exptmod(&sA, &rB, &p, &K);

		
		printf("基点G的阶 是:\n");
		mp_to_radix(&n, tempN.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempN.get());
		do {
			ecc.GetPrime(&d, KEY_LONG);
		} while (mp_cmp(&d, &n) != -1);

		
		printf("私钥 d 是:\n");
		mp_to_radix(&d, tempD.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempD.get());

	L:
		mp_rand(&k, 10);
		while (mp_cmp(&k, &n) == 1)
			mp_div_2(&k, &k);

		printf("随机数k是:\n");
		mp_to_radix(&k, tempK.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempK.get());

		ecc.Ecc_points_mul(&PX, &PY, &GX, &GY, &d, &A, &P);
		ecc.Ecc_points_mul(&X1, &Y1, &GX, &GY, &k, &A, &P);
		printf("公钥X坐标是:\n");
		mp_to_radix(&PX, tempPX.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempPX.get());

		printf("公钥Y坐标是:\n");
		mp_to_radix(&PY, tempPY.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempPY.get());

		mp_mod(&X1, &n, &r);
		if (mp_cmp_d(&r, 0) == 0)goto L;
		printf("x1 mod n是:\n");
		mp_to_radix(&r, tempR.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempR.get());

		ex_Eulid(&k, &n, &k1, &n1, &temp);

		printf("k**-1是:\n");
		while (mp_cmp_d(&k1, 0) != 1)
			mp_add(&k1, &n, &k1);
		mp_to_radix(&k1, tempK1.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempK1.get());

		mp_mulmod(&k, &k1, &n, &temp);
		printf("k*k**-1 mod n是:\n");
		mp_to_radix(&temp, tempT.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempT.get());

		string sh = sha256.ShaFile(szFullPath);
		mp_read_radix(&Hm, sh.c_str(), 10);
		printf("SHA是:\n");
		mp_to_radix(&Hm, tempSHA.get(), SIZE_MAX, &written, 0x10);
		printf("%s\n", tempSHA.get());

		mp_mul(&d, &r, &temp);
		mp_add(&Hm, &temp, &temp);
		mp_mulmod(&k1, &temp, &n, &s);
		printf("s 是:\n");
		mp_to_radix(&s, tempS.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempS.get());

		if (mp_cmp_d(&s, 0) == 0)goto L;
		ex_Eulid(&s, &n, &s1, &n1, &temp);

		mp_mulmod(&s, &s1, &n, &temp);
		printf("s*s**-1 mod n是:\n");
		mp_to_radix(&temp, tempS1.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempS1.get());

		if (mp_cmp(&r, &n) == -1 && mp_cmp_d(&r, 0) == 1) {
			if (mp_cmp(&s, &n) == -1 && mp_cmp_d(&s, 0) == 1) {
				mp_mulmod(&Hm, &s1, &n, &u1);
				mp_mulmod(&r, &s1, &n, &u2);
				ecc.Ecc_points_mul(&u1X, &u1Y, &GX, &GY, &u1, &A, &P);
				ecc.Ecc_points_mul(&u2X, &u2Y, &PX, &PY, &u2, &A, &P);
				ecc.Two_points_add(&u1X, &u1Y, &u2X, &u2Y, &X2, &Y2, &A, zero, &P);
				mp_mod(&X2, &n, &v);
				printf("v 是:\n");
				mp_to_radix(&v, tempV.get(), SIZE_MAX, &written, 10);
				printf("%s\n", tempV.get());
				printf("r 是:\n");
				mp_to_radix(&r, tempR.get(), SIZE_MAX, &written, 10);
				printf("%s\n", tempR.get());
				if (mp_cmp(&v, &r) == 0)cout << "接受签名";
			}
		}
		mp_clear(&Hm);
		mp_clear(&s);
		mp_clear(&p);
		mp_clear(&a);
		mp_clear(&rA);
		mp_clear(&sA);
		mp_clear(&rB);
		mp_clear(&sB);
		mp_clear(&K);
		mp_clear(&GX);
		mp_clear(&GY);
		mp_clear(&n);
		mp_clear(&h);
		mp_clear(&d);
		mp_clear(&k);
		mp_clear(&A);
		mp_clear(&B);
		mp_clear(&PX);
		mp_clear(&PY);
		mp_clear(&X1);
		mp_clear(&Y1);
		mp_clear(&u1X);
		mp_clear(&u1Y);
		mp_clear(&u2X);
		mp_clear(&u2Y);
		mp_clear(&X2);
		mp_clear(&Y2);
		mp_clear(&v);
		mp_clear(&r);
		mp_clear(&P);
		mp_clear(&k1);
		mp_clear(&s1);
		mp_clear(&n1);
		mp_clear(&temp);
		mp_clear(&u1);
		mp_clear(&u2);
	}break;
	case 4: {
		ECC ecc;
		STS sts;

		int lon;
		string path;//消息m的路径	
		size_t written;
		mp_int p;//p为安全素数
		mp_int a;//生成元
		mp_int p_1;//p-1
		mp_int x;//随机数x
		mp_int y;//a**x mod p
		mp_int k;//k属于Zp* 且k与p-1互素
		mp_int r;//a**k mod p
		mp_int s;//a**x mod p
		mp_int sha;//sha256的散列值
		mp_int a1;//k的逆元
		mp_int b1;//p-1的逆元
		mp_int temp3;

		std::unique_ptr<char[]> tempY(new char[800]());
		std::unique_ptr<char[]> tempR(new char[800]());
		std::unique_ptr<char[]> tempSHA(new char[800]());
		std::unique_ptr<char[]> tempA1(new char[800]());
		std::unique_ptr<char[]> tempT(new char[800]());


		if ((err = mp_init(&p)) != MP_OKAY) {
			printf("Error initializing the p. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&a)) != MP_OKAY) {
			printf("Error initializing the a. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&p_1)) != MP_OKAY) {
			printf("Error initializing the p_1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&x)) != MP_OKAY) {
			printf("Error initializing the x. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&y)) != MP_OKAY) {
			printf("Error initializing the y. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&a)) != MP_OKAY) {
			printf("Error initializing the a. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&k)) != MP_OKAY) {
			printf("Error initializing the k. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&r)) != MP_OKAY) {
			printf("Error initializing the r. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&s)) != MP_OKAY) {
			printf("Error initializing the s. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&sha)) != MP_OKAY) {
			printf("Error initializing the sha. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&a1)) != MP_OKAY) {
			printf("Error initializing the a1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&b1)) != MP_OKAY) {
			printf("Error initializing the b1. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = mp_init(&temp3)) != MP_OKAY) {
			printf("Error initializing the temp3. %s",
				mp_error_to_string(err));
			return EXIT_FAILURE;
		}

		
		cout << "请输入大素数的位数：";
		cin >> lon;
		sts.GetPrime(&p, &a, lon);
		mp_sub_d(&p, 1, &p_1);
		do { mp_rand(&x, lon); } while (mp_cmp(&x, &p_1) != -1 && mp_cmp_d(&x, 1) != 1);//1<=x<p-1
		mp_exptmod(&a, &x, &p, &y);
		printf("y是:\n");
		mp_to_radix(&y, tempY.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempY.get());
		do {
			mp_rand(&k, lon / 26);
			mp_gcd(&k, &p_1, &r);//互素
		} while (mp_cmp(&k, &p_1) != -1 || mp_cmp_d(&k, 1) != 1 || mp_cmp_d(&r, 1) != 0);//1<=k<p-1且k与p-1互素
		mp_exptmod(&a, &k, &p, &r);
		printf("a**k mod p是:\n");
		mp_to_radix(&r, tempR.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempR.get());
		string str = sha256.ShaFile(szFullPath);
		mp_read_radix(&sha, str.c_str(), 10);
		printf("SHA是:\n");
		mp_to_radix(&sha, tempSHA.get(), SIZE_MAX, &written, 0x10);
		printf("%s\n", tempSHA.get());
		mp_mul(&x, &r, &s);
		mp_sub(&sha, &s, &s);
		ex_Eulid(&k, &p_1, &a1, &b1, &temp3);
		while (mp_cmp_d(&a1, 0) != 1)
			mp_add(&a1, &p_1, &a1);
		printf("k**-1是:\n");
		mp_to_radix(&a1, tempA1.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempA1.get());
		mp_mulmod(&k, &a1, &p_1, &temp3);
		printf("k*k**-1 mod p是:\n");
		mp_to_radix(&a1, tempT.get(), SIZE_MAX, &written, 10);
		printf("%s\n", tempT.get());
	}break;
	case 5: {
		mp_int s;
		size_t written;
		mp_init(&s);
		string a = sha256.ShaFile(szFullPath);
		mp_read_radix(&s, a.c_str(), 10);
		char tempSHA[800] = { 0 };
		printf("SHA是:\n");
		mp_to_radix(&s, tempSHA, SIZE_MAX, &written, 0x10);
		printf("%s\n", tempSHA);

	}break;
	case 6: {
		std::string path;
		mp_int s;
		size_t written;
		mp_init(&s);
		cout << "请输入要计算散列值文件的位置：";
		cin >> path;
		std::string a = sha256.ShaFile(path);
		mp_read_radix(&s, a.c_str(), 10);
		char tempSHA[800] = { 0 };
		printf("SHA是:\n");
		mp_to_radix(&s, tempSHA, SIZE_MAX, &written, 0x10);
		printf("%s\n", tempSHA);

	}break;
	case 7: {
		DES d;
		string keyStr;
		ifstream in;
		ofstream out;
		switch (enDoIndex)
		{
		case 1:
			keyStr = GetRandList(16);
			cout << "密钥为：" << keyStr << "(请注意复制保存)" << endl;
			in.open(szFullPath, ios::binary);
			out.open(fullPath, ios::binary | ios::ate);
			if (in.is_open()) {
				string buf((std::istreambuf_iterator<char>(in)),
					std::istreambuf_iterator<char>());
				buf=d.Encrypt(buf, keyStr);
				out.write(buf.c_str(),buf.size());
			}	
			in.close();
			out.close();
			cout << "press any key to shutdown" << endl;
			std::cin.get();
			break;
		case 2:
			cout << "请输入密钥：";
			cin >> keyStr;
			if (keyStr.size() == 16) {
				in.open(szFullPath, ios::binary);
				out.open(fullPath, ios::binary | ios::ate);
				if (in.is_open()) {
					string buf((std::istreambuf_iterator<char>(in)),
						std::istreambuf_iterator<char>());
					buf = d.Decrypt(buf, keyStr);
					out.write(buf.c_str(), buf.size());
				}
				in.close();
				out.close();
				cout << "press any key to shutdown" << endl;
				std::cin.get();
			}
			else {
				cout << "密钥长度有误";
				cout << "press any key to shutdown" << endl;
				std::cin.get();
			}
			break;
		}
	}break;
	default:
		break;
	}
}