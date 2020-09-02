#include"ecc.h"

int ECC::GetPrime(mp_int* m, int lon) {
	mp_prime_rand(m, 10, lon,
		(rand() & 1) ? 0 : MP_PRIME_2MSB_ON);
	return MP_OKAY;
}

void ECC::Get_B_X_Y(mp_int* x1, mp_int* y1, mp_int* b, mp_int* a, mp_int* p)
{
	mp_int tempx, tempy;
	mp_int temp;
	mp_int compare;
	mp_int temp1;
	mp_int temp2;
	mp_int temp3;
	mp_int temp4;
	mp_int temp5;
	mp_int temp6;
	mp_int temp7;
	mp_int temp8;

	mp_init_ul(&compare, 0);
	mp_init(&tempx);
	mp_init(&tempy);
	mp_init(&temp);
	mp_init(&temp1);
	mp_init(&temp2);
	mp_init(&temp3);
	mp_init(&temp4);
	mp_init(&temp5);
	mp_init(&temp6);
	mp_init(&temp7);
	mp_init(&temp8);


	do
	{
		//4a3+27b2��0 (mod p)
		GetPrime(b, 40);
		mp_expt_u32(a, 3, &temp1);
		mp_sqr(b, &temp2);
		mp_mul_d(&temp1, 4, &temp3);
		mp_mul_d(&temp2, 27, &temp4);
		mp_add(&temp3, &temp4, &temp5);
		mp_mod(&temp5, p, &temp);
	} while (!mp_cmp(&temp, &compare));

	//y2=x3+ax+b,�������X����,����X�������Y����
	GetPrime(x1, 30);
	mp_expt_u32(x1, 3, &temp6);
	mp_mul(a, x1, &temp7);
	mp_add(&temp6, &temp7, &temp8);
	mp_add(&temp8, b, &tempx);
	mp_sqrt(&tempx, y1);



	mp_clear(&tempx);
	mp_clear(&tempy);
	mp_clear(&temp);
	mp_clear(&temp1);
	mp_clear(&temp2);
	mp_clear(&temp3);
	mp_clear(&temp4);
	mp_clear(&temp5);
	mp_clear(&temp6);
	mp_clear(&temp7);
	mp_clear(&temp8);


}

bool ECC::Ecc_points_mul(mp_int* qx, mp_int* qy, mp_int* px, mp_int* py, mp_int* d, mp_int* a, mp_int* p)
{
	size_t written;
	mp_int X1, Y1;
	mp_int X2, Y2;
	mp_int X3, Y3;
	mp_int XX1, YY1;
	mp_int A, P;

	int i;
	bool zero = false;
	char Bt_array[800] = { 0 };
	char cm = '1';

	mp_to_radix(d, Bt_array, SIZE_MAX, &written, 2);

	mp_init_ul(&X3, 0);
	mp_init_ul(&Y3, 0);
	mp_init_copy(&X1, px);
	mp_init_copy(&X2, px);
	mp_init_copy(&XX1, px);
	mp_init_copy(&Y1, py);
	mp_init_copy(&Y2, py);
	mp_init_copy(&YY1, py);

	mp_init_copy(&A, a);
	mp_init_copy(&P, p);

	for (i = 1; i <= KEY_LONG - 1; i++)
	{
		mp_copy(&X2, &X1);
		mp_copy(&Y2, &Y1);
		Two_points_add(&X1, &Y1, &X2, &Y2, &X3, &Y3, &A, zero, &P);
		mp_copy(&X3, &X2);
		mp_copy(&Y3, &Y2);
		if (Bt_array[i] == cm)
		{

			mp_copy(&XX1, &X1);
			mp_copy(&YY1, &Y1);
			Two_points_add(&X1, &Y1, &X2, &Y2, &X3, &Y3, &A, zero, &P);
			mp_copy(&X3, &X2);
			mp_copy(&Y3, &Y2);

		}

	}

	if (zero)
	{
		cout << "It is Zero_Unit!";
		return false;//���QΪ����²���D
	}

	mp_copy(&X3, qx);
	mp_copy(&Y3, qy);

	mp_clear(&X1);
	mp_clear(&Y1);
	mp_clear(&X2);
	mp_clear(&Y2);
	mp_clear(&X3);
	mp_clear(&Y3);
	mp_clear(&XX1);
	mp_clear(&YY1);
	mp_clear(&A);
	mp_clear(&P);

	return true;
}

//�����
int ECC::Two_points_add(mp_int* x1, mp_int* y1, mp_int* x2, mp_int* y2, mp_int* x3, mp_int* y3, mp_int* a, bool zero, mp_int* p)
{
	mp_int x2x1;
	mp_int y2y1;
	mp_int tempk;
	mp_int tempy;
	mp_int tempzero;
	mp_int k;
	mp_int temp1;
	mp_int temp2;
	mp_int temp3;
	mp_int temp4;
	mp_int temp5;
	mp_int temp6;
	mp_int temp7;
	mp_int temp8;
	mp_int temp9;
	mp_int temp10;


	mp_init(&x2x1);
	mp_init(&y2y1);
	mp_init(&tempk);
	mp_init(&tempy);
	mp_init(&tempzero);
	mp_init(&k);
	mp_init(&temp1);
	mp_init(&temp2);
	mp_init_set(&temp3, 2);
	mp_init(&temp4);
	mp_init(&temp5);
	mp_init(&temp6);
	mp_init(&temp7);
	mp_init(&temp8);
	mp_init(&temp9);
	mp_init(&temp10);


	if (zero)
	{
		mp_copy(x1, x3);
		mp_copy(y1, y3);
		zero = false;
		goto L;
	}
	mp_zero(&tempzero);
	mp_sub(x2, x1, &x2x1);
	if (mp_cmp(&x2x1, &tempzero) == -1)
	{

		mp_add(&x2x1, p, &temp1);
		mp_zero(&x2x1);
		mp_copy(&temp1, &x2x1);
	}
	mp_sub(y2, y1, &y2y1);
	if (mp_cmp(&y2y1, &tempzero) == -1)
	{

		mp_add(&y2y1, p, &temp2);
		mp_zero(&y2y1);
		mp_copy(&temp2, &y2y1);
	}
	if (mp_cmp(&x2x1, &tempzero) != 0)
	{

		mp_invmod(&x2x1, p, &tempk);

		mp_mulmod(&y2y1, &tempk, p, &k);
	}
	else
	{
		if (mp_cmp(&y2y1, &tempzero) == 0)
		{

			mp_mulmod(&temp3, y1, p, &tempy);
			mp_invmod(&tempy, p, &tempk);
			mp_sqr(x1, &temp4);
			mp_mul_d(&temp4, 3, &temp5);
			mp_add(&temp5, a, &temp6);
			mp_mulmod(&temp6, &tempk, p, &k);

		}
		else
		{
			zero = true;
			goto L;
		}
	}

	mp_sqr(&k, &temp7);
	mp_sub(&temp7, x1, &temp8);
	mp_submod(&temp8, x2, p, x3);

	mp_sub(x1, x3, &temp9);
	mp_mul(&temp9, &k, &temp10);
	mp_submod(&temp10, y1, p, y3);


L:

	mp_clear(&x2x1);
	mp_clear(&y2y1);
	mp_clear(&tempk);
	mp_clear(&tempy);
	mp_clear(&tempzero);
	mp_clear(&k);
	mp_clear(&temp1);
	mp_clear(&temp2);
	mp_clear(&temp3);
	mp_clear(&temp4);
	mp_clear(&temp5);
	mp_clear(&temp6);
	mp_clear(&temp7);
	mp_clear(&temp8);
	mp_clear(&temp9);
	mp_clear(&temp10);

	return 1;

}

//�����ƴ洢����
int ECC::chmistore(mp_int* a, FILE* fp)
{

	int i, j;
	char ch;
	char chtem[4];

	mp_digit yy = (mp_digit)255;
	for (i = 0; i <= a->used - 1; i++) {

		chtem[3] = (char)(a->dp[i] & yy);
		chtem[2] = (char)((a->dp[i] >> (mp_digit)8)& yy);
		chtem[1] = (char)((a->dp[i] >> (mp_digit)16)& yy);
		chtem[0] = (char)((a->dp[i] >> (mp_digit)24)& yy);

		for (j = 0; j < 4; j++)
		{
			fprintf(fp, "%c", chtem[j]);
		}

	}

	ch = char(255);
	fprintf(fp, "%c", ch);
	return MP_OKAY;
}


//�Ѷ�ȡ���ַ�����mp_int����
int ECC::putin(mp_int* a, char* ch, int chlong)
{
	mp_digit* temp, yy;
	int i, j, res;
	if (a->alloc < chlong * 2 / 7 + 2)
	{
		if ((res = mp_grow(a, chlong * 2 / 7 + 2)) != MP_OKAY)
			return res;
	}

	a->sign = MP_ZPOS;
	mp_zero(a);
	temp = a->dp;
	i = 0;
	yy = (mp_digit)15;

	if (chlong < 4)
	{
		for (j = chlong - 1; j >= 0; j--)
		{
			*temp |= (mp_digit)(ch[j] & 255);
			*temp <<= (mp_digit)CHAR_BIT;
		}
		*temp >>= (mp_digit)8;
		a->used = 1;
		return MP_OKAY;
	}

	if (chlong < 7)
	{
		i += 4;
		*++temp |= (mp_digit)(ch[i - 1] & yy);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 2] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 3] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp-- |= (mp_digit)(ch[i - 4] & 255); //��ű��зֵ��ַ��ĵ���λ


		for (j = chlong - 1; j >= i; j--)
		{
			*temp |= (mp_digit)(ch[j] & 255);
			*temp <<= (mp_digit)CHAR_BIT;
		}
		*temp >>= (mp_digit)4;
		*temp |= (mp_digit)((ch[i - 1] & 255) >> 4);  //��ű��зֵ��ַ��ĸ���λ

		a->used = 2;
		return MP_OKAY;
	}

	//��7���ַ�Ϊ��Ԫѭ�������߸��ַ������mp_int ��������Ԫ��
	for (j = 0; j < chlong / 7; j++)
	{
		i += 7;
		*++temp |= (mp_digit)(ch[i - 1] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 2] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 3] & 255);
		*temp <<= (mp_digit)4;
		*temp-- |= (mp_digit)((ch[i - 4] & 255) >> 4);    //��ű��зֵ��ַ��ĸ���λ

		*temp |= (mp_digit)(ch[i - 4] & yy);      //��ű��зֵ��ַ��ĵ���λ
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 5] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 6] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp++ |= (mp_digit)(ch[i - 7] & 255);

		temp++;

	}

	if ((chlong >= 7) && (chlong % 7 != 0))        //ʣ���ַ��Ĵ��
	{
		if (chlong % 7 < 4)           //ʣ���ַ�����4��ʱ��ֻ��һ��mp_digit��Ԫ���
		{
			for (j = chlong - 1; j >= i; j--)
			{
				*temp |= (mp_digit)(ch[j] & 255);
				*temp <<= (mp_digit)CHAR_BIT;
			}
			*temp >>= (mp_digit)8;
			a->used = chlong * 2 / 7 + 1;
		}
		else
		{                       //ʣ���ַ���С��4��ʱ��������mp_digit��Ԫ���
			i += 4;
			*temp |= (mp_digit)(ch[i - 1] & yy);
			*temp <<= (mp_digit)CHAR_BIT;
			*temp |= (mp_digit)(ch[i - 2] & 255);
			*temp <<= (mp_digit)CHAR_BIT;
			*temp |= (mp_digit)(ch[i - 3] & 255);
			*temp <<= (mp_digit)CHAR_BIT;
			*temp++ |= (mp_digit)(ch[i - 4] & 255); //��ű��зֵ��ַ��ĵ���λ


			for (j = chlong - 1; j >= i; j--)
			{
				*temp |= (mp_digit)(ch[j] & 255);
				*temp <<= (mp_digit)CHAR_BIT;
			}
			*temp >>= (mp_digit)4;
			*temp |= (mp_digit)((ch[i - 1] & 255) >> 4);  //��ű��зֵ��ַ��ĸ���λ

			a->used = chlong * 2 / 7 + 2;
		}

	}
	else
	{
		a->used = chlong * 2 / 7;
	}
	return MP_OKAY;
}

void ECC::Ecc_encipher(mp_int* qx, mp_int* qy, mp_int* px, mp_int* py, mp_int* a, mp_int* p, char* inPath, string outPath)
{
	mp_int mx, my;
	mp_int c1x, c1y;
	mp_int c2x, c2y;
	mp_int r;
	mp_int tempx, tempy;
	bool zero = false;
	FILE* fp, * fq;
	int i;
	char miwenx[280] = { 0 };
	char miweny[280] = { 0 };
	char stemp[650] = { 0 };


	mp_init(&mx);
	mp_init(&my);
	mp_init(&c1x);
	mp_init(&c1y);
	mp_init(&c2x);
	mp_init(&c2y);
	mp_init(&r);
	mp_init(&tempx);
	mp_init(&tempy);

	GetPrime(&r, 100);

	//��Ҫ�����ļ�
	if (fopen_s(&fp, inPath, "rb"))
	{
		printf("can not open the file!");
		exit(1);
	}

	unsigned int FileLong = 0;//�ļ��ַ�����
	char ChTem;//��ʱ�ַ���
	int Frequency = 0;//ȡ�����ֽ����Ĵ���
	int Residue = 0;//ȡ�����ֽں��ʣ�ಿ��

	while (!feof(fp))//���ļ��ַ�����
	{
		ChTem = fgetc(fp);
		FileLong++;
	}
	--FileLong;


	Frequency = FileLong / EN_LONG;
	Residue = FileLong % EN_LONG;

	int enlongtemp = EN_LONG / 2;


	//�򿪱��������ļ�
	if (fopen_s(&fq, outPath.c_str(), "wb"))
	{
		printf("can not open the file!\n");
		exit(1);
	}

	printf("\n��ʼ����...\n");


	rewind(fp);
	for (i = 0; i < Frequency; i++)
	{

		fread(miwenx, 1, enlongtemp, fp);//�����ַ�����EN_LONG��һ��
		miwenx[enlongtemp] = char(255);

		fread(miweny, 1, enlongtemp, fp);//�����ַ�����EN_LONG��һ��
		miweny[enlongtemp] = char(255);

		putin(&mx, miwenx, enlongtemp + 1);//�ļ�����         
		putin(&my, miweny, enlongtemp + 1);//�ļ�����

		Ecc_points_mul(&c2x, &c2y, px, py, &r, a, p);//����
		Ecc_points_mul(&tempx, &tempy, qx, qy, &r, a, p);
		Two_points_add(&mx, &my, &tempx, &tempy, &c1x, &c1y, a, zero, p);

		//��������      
		chmistore(&c1x, fq);
		chmistore(&c1y, fq);
		chmistore(&c2x, fq);
		chmistore(&c2y, fq);

	}
	//ʣ���ַ�����
	if (Residue > 0)
	{
		if (Residue <= enlongtemp)
		{
			fread(miwenx, 1, Residue, fp);//�����ַ���
			miwenx[Residue] = char(255);

			putin(&mx, miwenx, Residue + 1);//�ļ����� 

			mp_zero(&my);

		}
		else
		{

			fread(miwenx, 1, enlongtemp, fp);//�����ַ���
			miwenx[enlongtemp] = char(255);


			fread(miweny, 1, Residue - enlongtemp, fp);//�����ַ���
			miweny[Residue - enlongtemp] = char(255);

			putin(&mx, miwenx, enlongtemp + 1);//�ļ����� 

			putin(&my, miweny, Residue - enlongtemp + 1);//�ļ����� 
		}

		Ecc_points_mul(&c2x, &c2y, px, py, &r, a, p);//����

		Ecc_points_mul(&tempx, &tempy, qx, qy, &r, a, p);


		Two_points_add(&mx, &my, &tempx, &tempy, &c1x, &c1y, a, zero, p);


		//��������      
		chmistore(&c1x, fq);

		chmistore(&c1y, fq);

		chmistore(&c2x, fq);

		chmistore(&c2y, fq);
	}


	cout << "\nok!�������!" << endl;
	cout << "�����Զ����Ʊ���" << endl;
	cout << "���Ĵ��·��Ϊ  " << outPath << endl;


	fclose(fq);
	fclose(fp);
	mp_clear(&mx);
	mp_clear(&my);
	mp_clear(&c1x);
	mp_clear(&c1y);
	mp_clear(&c2x);
	mp_clear(&c2y);
	mp_clear(&r);
	mp_clear(&tempx);
	mp_clear(&tempy);


}

void ECC::Ecc_saveKey(char* tempK, char* tempA, char* temp, string outPath)
{
	outPath+="privateKey.txt";
	ofstream out(outPath, ios::out);
	if (out.is_open())
	{
		out << tempK<<"\n";
		out << tempA << "\n";
		out << temp << "\n";
		out.close();
	}	
}

void ECC::Ecc_loadKey(mp_int* k, mp_int* a, mp_int* p, string inPath)
{
	char tempK[800] = { 0 };
	char tempA[800] = { 0 };
	char temp[800] = { 0 };
	inPath += "privateKey.txt";
	ifstream ifile(inPath, ios::out);
	if (ifile.fail())
		cout << "The file does not exist";
	else{
		ifile.getline(tempK, 800);
		ifile.getline(tempA, 800);
		ifile.getline(temp, 800);
		ifile.close();
	}
	mp_read_radix(k, tempK, 10);
	mp_read_radix(a, tempA, 10);
	mp_read_radix(p, temp, 10);
}


//ȡ����

int ECC::miwendraw(mp_int* a, char* ch, int chlong)
{
	mp_digit* temp;
	int i, j, res;

	if (a->alloc < chlong / 4)
	{
		if ((res = mp_grow(a, chlong / 4)) != MP_OKAY)
			return res;
	}

	a->alloc = chlong / 4;
	a->sign = MP_ZPOS;
	mp_zero(a);
	temp = a->dp;
	i = 0;

	for (j = 0; j < chlong / 4; j++)
	{
		i += 4;
		*temp |= (mp_digit)(ch[i - 4] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 3] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp |= (mp_digit)(ch[i - 2] & 255);
		*temp <<= (mp_digit)CHAR_BIT;
		*temp++ |= (mp_digit)(ch[i - 1] & 255);
	}
	a->used = chlong / 4;
	return MP_OKAY;
}

//ʵ�ֽ�mp_int��a�еı��ش���ԭΪ�ַ����������ַ���ch��
int ECC::chdraw(mp_int* a, char* ch)
{
	int i, j;
	mp_digit* temp, xx, yy;

	temp = a->dp;
	i = 0;
	yy = (mp_digit)255;  //����λ�����㣬ȡ��λ���ش�
	xx = (mp_digit)15;  //����λ�����㣬ȡ��λ���ش�

	for (j = 0; j < a->used / 2; j++)  //��������ԪΪѭ������������Ԫ�ı��ش�����7���ַ�
	{
		i += 7;
		ch[i - 4] = (char)(*++temp & xx);
		ch[i - 3] = (char)((*temp >> (mp_digit)4)& yy);
		ch[i - 2] = (char)((*temp >> (mp_digit)12)& yy);
		ch[i - 1] = (char)((*temp-- >> (mp_digit)20)& yy);

		ch[i - 7] = (char)(*temp & yy);
		ch[i - 6] = (char)((*temp >> (mp_digit)8)& yy);
		ch[i - 5] = (char)((*temp >> (mp_digit)16)& yy);
		ch[i - 4] <<= 4;
		ch[i - 4] += (char)((*temp++ >> (mp_digit)24)& xx);
		temp++;
	}
	if (a->used % 2 != 0)  //ʣ��һ����Ԫ�Ĵ���
	{
		ch[i++] = (char)(*temp & yy);
		ch[i++] = (char)((*temp >> (mp_digit)8)& yy);
		ch[i++] = (char)((*temp >> (mp_digit)16)& yy);
	}
	--i;
	while (int(ch[i] & 0xFF) != 255 && i > 0) i--;
	return i;

}

void ECC::Ecc_decipher(mp_int* k, mp_int* a, mp_int* p,char* inPath, string outPath) {

	mp_int c1x, c1y;
	mp_int c2x, c2y;
	mp_int tempx, tempy;
	mp_int mx, my;
	mp_int temp;

	mp_init(&temp);
	mp_init(&c1x);
	mp_init(&c1y);
	mp_init(&c2x);
	mp_init(&c2y);
	mp_init(&tempx);
	mp_init(&tempy);
	mp_init(&mx);
	mp_init(&my);

	mp_int tempzero;
	mp_init(&tempzero);

	int i;
	char stemp[700] = { 0 };
	FILE* fp, * fq;
	bool zero = false;


	//char filehead[60], filefoot[20], filename[85] = { 0 };
	//cout << "��������Ҫ���ܵ��ļ��Ĵ��·�����ļ���(��:  c:\\000\\����������  ):" << endl;
	//cin >> filehead;
	//cout << "��������Ҫ���ܵ��ļ�����չ��(��:  .doc  ):" << endl;
	//cin >> filefoot;
	//strcpy_s(filename, filehead);
	//strcat_s(filename, filefoot);

	//printf("\n��ʼ����\n");

	if (fopen_s(&fp, inPath, "rb"))
	{
		printf("can not open the file!");
		exit(1);
	}

	////�򿪱�����ܽ���ļ�
	//char filemi[80];
	//strcpy_s(filemi, filehead);
	//strcat_s(filemi, "����");
	//strcat_s(filemi, filefoot);

	if ((fopen_s(&fq,outPath.c_str(), "wb")))
	{
		printf("can not open the file!");
		exit(1);
	}


	rewind(fp);
	while (!feof(fp))
	{
		i = 0;
		while (1)
		{
			stemp[i] = fgetc(fp);
			if (i % 4 == 0)
			{
				if (int(stemp[i] & 0xFF) == 255) goto L1;
			}
			i++;
		}

	L1:     miwendraw(&c1x, stemp, i);
		i = 0;
		while (1)
		{
			stemp[i] = fgetc(fp);
			if (i % 4 == 0)
			{
				if (int(stemp[i] & 0xFF) == 255) goto L2;
			}
			i++;
		}

	L2:     miwendraw(&c1y, stemp, i);
		i = 0;
		while (1)
		{
			stemp[i] = fgetc(fp);
			if (i % 4 == 0)
			{
				if (int(stemp[i] & 0xFF) == 255) goto L3;
			}
			i++;
		}

	L3:     miwendraw(&c2x, stemp, i);
		i = 0;
		while (1)
		{
			stemp[i] = fgetc(fp);
			if (i % 4 == 0)
			{
				if (int(stemp[i] & 0xFF) == 255) goto L4;
			}
			i++;
		}

	L4:     miwendraw(&c2y, stemp, i);

		mp_zero(&tempzero);
		if (mp_cmp(&c1x, &tempzero) == 0) break;

		Ecc_points_mul(&tempx, &tempy, &c2x, &c2y, k, a, p);

		mp_neg(&tempy, &temp);
		Two_points_add(&c1x, &c1y, &tempx, &temp, &mx, &my, a, zero, p);

		int chtem;
		chtem = chdraw(&mx, stemp);//��ming��ȡ���ַ���


		//������ܽ��

		for (int kk = 0; kk < chtem; kk++)
		{
			fprintf(fq, "%c", stemp[kk]);

		}

		chtem = chdraw(&my, stemp);//��ming��ȡ���ַ���


		 //������ܽ��
		for (int kk = 0; kk < chtem; kk++)
		{
			fprintf(fq, "%c", stemp[kk]);

		}


	}

	cout << "\nok!�������!" << endl;
	cout << "���ܺ�����ִ��·��Ϊ  " << outPath << endl;

	fclose(fq);
	fclose(fp);
	mp_clear(&c1x);
	mp_clear(&c1y);
	mp_clear(&c2x);
	mp_clear(&c2y);
	mp_clear(&tempx);
	mp_clear(&tempy);
	mp_clear(&mx);
	mp_clear(&my);
	mp_clear(&temp);


}