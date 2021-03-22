#include "ecdsa.h"
#include "tools.h"
namespace crypto__ {
	ECDSA::ECDSA()
	{
		try
		{
			if ((err = mp_init(&Hm)) != MP_OKAY) {
				throw("Error initializing the Hm. %s",
					mp_error_to_string(err));
			}
			if ((err = mp_init(&s)) != MP_OKAY) {
				throw("Error initializing the s. %s",
					mp_error_to_string(err));
			}
			if ((err = mp_init(&p)) != MP_OKAY) {
				throw("Error initializing the p. %s",
					mp_error_to_string(err));
			}
			if ((err = mp_init(&a)) != MP_OKAY) {
				throw("Error initializing the a. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&rA)) != MP_OKAY) {
				throw("Error initializing the rA. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&sA)) != MP_OKAY) {
				throw("Error initializing the sA. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&rB)) != MP_OKAY) {
				throw("Error initializing the rB. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&sB)) != MP_OKAY) {
				throw("Error initializing the sB. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&K)) != MP_OKAY) {
				throw("Error initializing the K. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&GX)) != MP_OKAY) {
				throw("Error initializing the GX. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&GY)) != MP_OKAY) {
				throw("Error initializing the GY. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init_set(&n, 1)) != MP_OKAY) {
				throw("Error initializing the n. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init_set(&h, 1)) != MP_OKAY) {
				throw("Error initializing the h. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&d)) != MP_OKAY) {
				throw("Error initializing the d. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&k)) != MP_OKAY) {
				throw("Error initializing the k. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init_set(&A, 0)) != MP_OKAY) {
				throw("Error initializing the A. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init_set(&B, 7)) != MP_OKAY) {
				throw("Error initializing the B. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&PX)) != MP_OKAY) {
				throw("Error initializing the PX. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&PY)) != MP_OKAY) {
				throw("Error initializing the PY. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&X1)) != MP_OKAY) {
				throw("Error initializing the X1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&Y1)) != MP_OKAY) {
				throw("Error initializing the Y1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u1X)) != MP_OKAY) {
				throw("Error initializing the u1X. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u1Y)) != MP_OKAY) {
				throw("Error initializing the u1Y. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u2X)) != MP_OKAY) {
				throw("Error initializing the u2X. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u2Y)) != MP_OKAY) {
				throw("Error initializing the u2Y. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&X2)) != MP_OKAY) {
				throw("Error initializing the X2. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&Y2)) != MP_OKAY) {
				throw("Error initializing the Y2. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&v)) != MP_OKAY) {
				throw("Error initializing the v. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&r)) != MP_OKAY) {
				throw("Error initializing the r. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&P)) != MP_OKAY) {
				throw("Error initializing the P. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&k1)) != MP_OKAY) {
				throw("Error initializing the k1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&s1)) != MP_OKAY) {
				throw("Error initializing the s1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&n1)) != MP_OKAY) {
				throw("Error initializing the n1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&temp)) != MP_OKAY) {
				throw("Error initializing the temp. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u1)) != MP_OKAY) {
				throw("Error initializing the u1. %s",
					mp_error_to_string(err));

			}
			if ((err = mp_init(&u2)) != MP_OKAY) {
				throw("Error initializing the u2. %s",
					mp_error_to_string(err));

			}
			n.alloc = 512;
			if ((err = mp_read_radix(&P, rP, 0x10)) != MP_OKAY) {
				throw("mp_read_radix failed: \"%s\"\n",
					mp_error_to_string(err));

			}
			if ((err = mp_read_radix(&GX, rGX, 0x10)) != MP_OKAY) {
				throw("mp_read_radix failed: \"%s\"\n",
					mp_error_to_string(err));

			}
			if ((err = mp_read_radix(&GY, rGY, 0x10)) != MP_OKAY) {
				throw("mp_read_radix failed: \"%s\"\n",
					mp_error_to_string(err));

			}
			if ((err = mp_read_radix(&n, rn, 0x10)) != MP_OKAY) {
				throw("mp_read_radix failed: \"%s\"\n",
					mp_error_to_string(err));

			}
		}
		catch (const char* init_err)
		{
			cout << init_err << endl;
		}

	}

	ECDSA::~ECDSA()
	{
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
	}
	void ECDSA::printECDSA(std::string& sh)
	{
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
	}
}