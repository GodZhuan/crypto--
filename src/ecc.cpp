#include "../include/ecc.h"
#include <cstddef>
#include <format>
#include <iostream>
#include <tommath.h>

ECC::ECC() {

  mp_err err = MP_OKAY;
  if (err = mp_init(&GX);err != MP_OKAY) {
    cerr << (std::format("Error initializing the GX. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&GY);err != MP_OKAY) {
    cerr << (std::format("Error initializing the GY. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&K);err != MP_OKAY) {
    cerr << (std::format("Error initializing the K. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&A);err != MP_OKAY) {
    cerr << (std::format("Error initializing the A. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&B);err != MP_OKAY) {
    cerr << (std::format("Error initializing the B. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&QX);err != MP_OKAY) {
    cerr << (std::format("Error initializing the QX. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&QY);err != MP_OKAY) {
    cerr << (std::format("Error initializing the QY. {}",
                         mp_error_to_string(err)));
    return;
  }
  
  if (err = mp_init(&P);err != MP_OKAY) {
    cerr << (std::format("Error initializing the P. {}",
                         mp_error_to_string(err)));
    return;
  }
}

ECC::~ECC() {
  mp_clear(&GX);
  mp_clear(&GY);
  mp_clear(&K); // 私有密钥
  mp_clear(&A);
  mp_clear(&B);
  mp_clear(&QX);
  mp_clear(&QY);
  mp_clear(&P); // Fp中的p(有限域P)
}

void ECC::BuildParameters(void) {
  printf("是否生成新的椭圆曲线参数?\n");

  GetPrime(&P, P_LONG);
  GetPrime(&A, 30);
  Get_B_X_Y(&GX, &GY, &B, &A, &P);
  GetPrime(&K, KEY_LONG);
  Ecc_points_mul(&QX, &QY, &GX, &GY, &K, &A, &P);
}

void ECC::PrintParameters(void) {
  char *t = new char[800]();
  size_t written = 0;

  mp_err ret = mp_to_radix(&P, t, SIZE_MAX, &written, 10);
  if (ret == 0) { /* no error */
    temp = t;
    cout<<format("椭圆曲线的参数如下(以十进制显示):\n有限域 P 是:\n{}\n",temp);
  }

  
  ret = mp_to_radix(&A, t, SIZE_MAX, &written, 10);
  tempA = t;
  cout<<format("曲线参数 A 是:\n{}\n",tempA);

  ret = mp_to_radix(&B, t, SIZE_MAX, &written, 10);
  tempB = t;
  cout<<format("曲线参数 B 是:\n{}\n",tempB);

  ret = mp_to_radix(&GX, t, SIZE_MAX, &written, 10);
  tempGX = t;
  cout<<format("曲线G点X坐标是:\n{}\n",tempGX);

  ret = mp_to_radix(&GY, t, SIZE_MAX, &written, 10);
  tempGY = t;
  cout<<format("曲线G点Y坐标是:\n{}\n",tempGY);

  ret = mp_to_radix(&K, t, SIZE_MAX, &written, 10);
  tempK = t;
  cout<<format("私钥 K 是:\n{}\n",tempK);

  ret = mp_to_radix(&QX, t, SIZE_MAX, &written, 10);
  tempQX = t;
  cout<<format("公钥X坐标是:\n{}\n",tempQX);

  ret = mp_to_radix(&QY, t, SIZE_MAX, &written, 10);
  tempQY = t;
  cout<<format("公钥Y坐标是:\n{}\n",tempQY);
}

std::string ECC::Encrypt(const std::string &plain, const std::string &key) {
  return std::string();
}

std::string ECC::Decrypt(const std::string &cipher, const std::string &key) {
  return std::string();
}

int ECC::GetPrime(mp_int *m, int lon) {
  mp_err ret = mp_prime_rand(m, 10, lon, (rand() & 1) ? 0 : MP_PRIME_2MSB_ON);
  return ret;
}

void ECC::Get_B_X_Y(mp_int *x1, mp_int *y1, mp_int *b, mp_int *a, mp_int *p) {
  mp_int tempx;
  mp_int tempy;
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

  mp_err ret = mp_init_ul(&compare, 0);
  ret = mp_init(&tempx);
  ret = mp_init(&tempy);
  ret = mp_init(&temp);
  ret = mp_init(&temp1);
  ret = mp_init(&temp2);
  ret = mp_init(&temp3);
  ret = mp_init(&temp4);
  ret = mp_init(&temp5);
  ret = mp_init(&temp6);
  ret = mp_init(&temp7);
  ret = mp_init(&temp8);

  do {
    // 4a3+27b2≠0 (mod p)
    GetPrime(b, 40);
    ret = mp_expt_u32(a, 3, &temp1);
    ret = mp_sqr(b, &temp2);
    ret = mp_mul_d(&temp1, 4, &temp3);
    ret = mp_mul_d(&temp2, 27, &temp4);
    ret = mp_add(&temp3, &temp4, &temp5);
    ret = mp_mod(&temp5, p, &temp);
  } while (!mp_cmp(&temp, &compare));

  // y2=x3+ax+b,随机产生X坐标,根据X坐标计算Y坐标
  GetPrime(x1, 30);
  ret = mp_expt_u32(x1, 3, &temp6);
  ret = mp_mul(a, x1, &temp7);
  ret = mp_add(&temp6, &temp7, &temp8);
  ret = mp_add(&temp8, b, &tempx);
  ret = mp_sqrt(&tempx, y1);

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

bool ECC::Ecc_points_mul(mp_int *qx, mp_int *qy, mp_int *px, mp_int *py,
                         mp_int *d, mp_int *a, mp_int *p) {
  size_t written;
  mp_int X1, Y1;
  mp_int X2, Y2;
  mp_int X3, Y3;
  mp_int XX1, YY1;
  mp_int A, P;

  int i;
  bool zero = false;
  char Bt_array[800] = {0};
  char cm = '1';

  mp_err ret = mp_to_radix(d, Bt_array, SIZE_MAX, &written, 2);

  ret = mp_init_ul(&X3, 0);
  ret = mp_init_ul(&Y3, 0);
  ret = mp_init_copy(&X1, px);
  ret = mp_init_copy(&X2, px);
  ret = mp_init_copy(&XX1, px);
  ret = mp_init_copy(&Y1, py);
  ret = mp_init_copy(&Y2, py);
  ret = mp_init_copy(&YY1, py);

  ret = mp_init_copy(&A, a);
  ret = mp_init_copy(&P, p);

  for (i = 1; i <= KEY_LONG - 1; i++) {
    ret = mp_copy(&X2, &X1);
    ret = mp_copy(&Y2, &Y1);
    Two_points_add(&X1, &Y1, &X2, &Y2, &X3, &Y3, &A, zero, &P);
    ret = mp_copy(&X3, &X2);
    ret = mp_copy(&Y3, &Y2);
    if (Bt_array[i] == cm) {

      ret = mp_copy(&XX1, &X1);
      ret = mp_copy(&YY1, &Y1);
      Two_points_add(&X1, &Y1, &X2, &Y2, &X3, &Y3, &A, zero, &P);
      ret = mp_copy(&X3, &X2);
      ret = mp_copy(&Y3, &Y2);
    }
  }

  if (zero) {
    cout << "It is Zero_Unit!";
    return false; // 如果Q为零从新产生D
  }

  ret = mp_copy(&X3, qx);
  ret = mp_copy(&Y3, qy);

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

// 两点加
int ECC::Two_points_add(mp_int *x1, mp_int *y1, mp_int *x2, mp_int *y2,
                        mp_int *x3, mp_int *y3, mp_int *a, bool zero,
                        mp_int *p) {
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

  mp_err ret = mp_init(&x2x1);
  ret = mp_init(&y2y1);
  ret = mp_init(&tempk);
  ret = mp_init(&tempy);
  ret = mp_init(&tempzero);
  ret = mp_init(&k);
  ret = mp_init(&temp1);
  ret = mp_init(&temp2);
  ret = mp_init_set(&temp3, 2);
  ret = mp_init(&temp4);
  ret = mp_init(&temp5);
  ret = mp_init(&temp6);
  ret = mp_init(&temp7);
  ret = mp_init(&temp8);
  ret = mp_init(&temp9);
  ret = mp_init(&temp10);

  if (zero) {
    ret = mp_copy(x1, x3);
    ret = mp_copy(y1, y3);
    zero = false;
    goto L;
  }
  mp_zero(&tempzero);
  ret = mp_sub(x2, x1, &x2x1);
  if (mp_cmp(&x2x1, &tempzero) == -1) {

    ret = mp_add(&x2x1, p, &temp1);
    mp_zero(&x2x1);
    ret = mp_copy(&temp1, &x2x1);
  }
  ret = mp_sub(y2, y1, &y2y1);
  if (mp_cmp(&y2y1, &tempzero) == -1) {

    ret = mp_add(&y2y1, p, &temp2);
    mp_zero(&y2y1);
    ret = mp_copy(&temp2, &y2y1);
  }
  if (mp_cmp(&x2x1, &tempzero) != 0) {

    ret = mp_invmod(&x2x1, p, &tempk);

    ret = mp_mulmod(&y2y1, &tempk, p, &k);
  } else {
    if (mp_cmp(&y2y1, &tempzero) == 0) {

      ret = mp_mulmod(&temp3, y1, p, &tempy);
      ret = mp_invmod(&tempy, p, &tempk);
      ret = mp_sqr(x1, &temp4);
      ret = mp_mul_d(&temp4, 3, &temp5);
      ret = mp_add(&temp5, a, &temp6);
      ret = mp_mulmod(&temp6, &tempk, p, &k);

    } else {
      zero = true;
      goto L;
    }
  }

  ret = mp_sqr(&k, &temp7);
  ret = mp_sub(&temp7, x1, &temp8);
  ret = mp_submod(&temp8, x2, p, x3);

  ret = mp_sub(x1, x3, &temp9);
  ret = mp_mul(&temp9, &k, &temp10);
  ret = mp_submod(&temp10, y1, p, y3);

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

// 二进制存储密文
int ECC::chmistore(mp_int *a, FILE *fp) {

  int i, j;
  char ch;
  char chtem[4];

  mp_digit yy = (mp_digit)255;
  for (i = 0; i <= a->used - 1; i++) {

    chtem[3] = (char)(a->dp[i] & yy);
    chtem[2] = (char)((a->dp[i] >> (mp_digit)8) & yy);
    chtem[1] = (char)((a->dp[i] >> (mp_digit)16) & yy);
    chtem[0] = (char)((a->dp[i] >> (mp_digit)24) & yy);

    for (j = 0; j < 4; j++) {
      fprintf(fp, "%c", chtem[j]);
    }
  }

  ch = char(255);
  fprintf(fp, "%c", ch);
  return MP_OKAY;
}

// 把读取的字符存入mp_int型数
int ECC::putin(mp_int *a, char *ch, int chlong) {
  mp_digit *temp, yy;
  int i, j, res;
  if (a->alloc < chlong * 2 / 7 + 2) {
    if ((res = mp_grow(a, chlong * 2 / 7 + 2)) != MP_OKAY)
      return res;
  }

  a->sign = MP_ZPOS;
  mp_zero(a);
  temp = a->dp;
  i = 0;
  yy = (mp_digit)15;

  if (chlong < 4) {
    for (j = chlong - 1; j >= 0; j--) {
      *temp |= (mp_digit)(ch[j] & 255);
      *temp <<= (mp_digit)CHAR_BIT;
    }
    *temp >>= (mp_digit)8;
    a->used = 1;
    return MP_OKAY;
  }

  if (chlong < 7) {
    i += 4;
    *++temp |= (mp_digit)(ch[i - 1] & yy);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 2] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 3] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp-- |= (mp_digit)(ch[i - 4] & 255); // 存放被切分的字符的低四位

    for (j = chlong - 1; j >= i; j--) {
      *temp |= (mp_digit)(ch[j] & 255);
      *temp <<= (mp_digit)CHAR_BIT;
    }
    *temp >>= (mp_digit)4;
    *temp |= (mp_digit)((ch[i - 1] & 255) >> 4); // 存放被切分的字符的高四位

    a->used = 2;
    return MP_OKAY;
  }

  // 以7个字符为单元循环，把七个字符放入的mp_int 的两个单元中
  for (j = 0; j < chlong / 7; j++) {
    i += 7;
    *++temp |= (mp_digit)(ch[i - 1] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 2] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 3] & 255);
    *temp <<= (mp_digit)4;
    *temp-- |= (mp_digit)((ch[i - 4] & 255) >> 4); // 存放被切分的字符的高四位

    *temp |= (mp_digit)(ch[i - 4] & yy); // 存放被切分的字符的低四位
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 5] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp |= (mp_digit)(ch[i - 6] & 255);
    *temp <<= (mp_digit)CHAR_BIT;
    *temp++ |= (mp_digit)(ch[i - 7] & 255);

    temp++;
  }

  if ((chlong >= 7) && (chlong % 7 != 0)) // 剩余字符的存放
  {
    if (chlong % 7 < 4) // 剩余字符少余4个时，只需一个mp_digit单元存放
    {
      for (j = chlong - 1; j >= i; j--) {
        *temp |= (mp_digit)(ch[j] & 255);
        *temp <<= (mp_digit)CHAR_BIT;
      }
      *temp >>= (mp_digit)8;
      a->used = chlong * 2 / 7 + 1;
    } else { // 剩余字符不小于4个时，需两个mp_digit单元存放
      i += 4;
      *temp |= (mp_digit)(ch[i - 1] & yy);
      *temp <<= (mp_digit)CHAR_BIT;
      *temp |= (mp_digit)(ch[i - 2] & 255);
      *temp <<= (mp_digit)CHAR_BIT;
      *temp |= (mp_digit)(ch[i - 3] & 255);
      *temp <<= (mp_digit)CHAR_BIT;
      *temp++ |= (mp_digit)(ch[i - 4] & 255); // 存放被切分的字符的低四位

      for (j = chlong - 1; j >= i; j--) {
        *temp |= (mp_digit)(ch[j] & 255);
        *temp <<= (mp_digit)CHAR_BIT;
      }
      *temp >>= (mp_digit)4;
      *temp |= (mp_digit)((ch[i - 1] & 255) >> 4); // 存放被切分的字符的高四位

      a->used = chlong * 2 / 7 + 2;
    }

  } else {
    a->used = chlong * 2 / 7;
  }
  return MP_OKAY;
}

void ECC::Ecc_encipher(char *inPath, string outPath) {
  mp_int mx, my;
  mp_int c1x, c1y;
  mp_int c2x, c2y;
  mp_int r;
  mp_int tempx, tempy;
  bool zero = false;
  int i;
  char miwenx[280] = {0};
  char miweny[280] = {0};
  char stemp[650] = {0};

  mp_err ret = mp_init(&mx);
  ret = mp_init(&my);
  ret = mp_init(&c1x);
  ret = mp_init(&c1y);
  ret = mp_init(&c2x);
  ret = mp_init(&c2y);
  ret = mp_init(&r);
  ret = mp_init(&tempx);
  ret = mp_init(&tempy);

  GetPrime(&r, 100);
  FILE *fp = fopen(inPath, "rb");
  // 打开要加密文件
  if (fp == NULL) {
    printf("can not open the file!");
    exit(1);
  }

  uint32_t FileLong = 0; // 文件字符长度
  char ChTem;            // 临时字符变
  int Frequency = 0;     // 取明文字节数的次数
  int Residue = 0;       // 取明文字节后的剩余部分

  while (!feof(fp)) // 找文件字符长度
  {
    ChTem = fgetc(fp);
    FileLong++;
  }
  --FileLong;

  Frequency = FileLong / EN_LONG;
  Residue = FileLong % EN_LONG;

  int enlongtemp = EN_LONG / 2;

  // 打开保存密文文件
  FILE *fq = fopen(outPath.c_str(), "wb");
  if (fq == NULL) {
    printf("can not open the file!\n");
    exit(1);
  }

  printf("\n开始加密...\n");

  rewind(fp);
  for (i = 0; i < Frequency; i++) {

    fread(miwenx, 1, enlongtemp, fp); // 读入字符串，EN_LONG的一半
    miwenx[enlongtemp] = char(255);

    fread(miweny, 1, enlongtemp, fp); // 读入字符串，EN_LONG的一半
    miweny[enlongtemp] = char(255);

    putin(&mx, miwenx, enlongtemp + 1); // 文件存入
    putin(&my, miweny, enlongtemp + 1); // 文件存入

    Ecc_points_mul(&c2x, &c2y, &GX, &GY, &r, &A, &P); // 加密
    Ecc_points_mul(&tempx, &tempy, &QX, &QY, &r, &A, &P);
    Two_points_add(&mx, &my, &tempx, &tempy, &c1x, &c1y, &A, zero, &P);

    // 保存密文
    chmistore(&c1x, fq);
    chmistore(&c1y, fq);
    chmistore(&c2x, fq);
    chmistore(&c2y, fq);
  }
  // 剩余字符处理
  if (Residue > 0) {
    if (Residue <= enlongtemp) {
      fread(miwenx, 1, Residue, fp); // 读入字符串
      miwenx[Residue] = char(255);

      putin(&mx, miwenx, Residue + 1); // 文件存入

      mp_zero(&my);

    } else {

      fread(miwenx, 1, enlongtemp, fp); // 读入字符串
      miwenx[enlongtemp] = char(255);

      fread(miweny, 1, Residue - enlongtemp, fp); // 读入字符串
      miweny[Residue - enlongtemp] = char(255);

      putin(&mx, miwenx, enlongtemp + 1); // 文件存入

      putin(&my, miweny, Residue - enlongtemp + 1); // 文件存入
    }

    Ecc_points_mul(&c2x, &c2y, &GX, &GY, &r, &A, &P); // 加密

    Ecc_points_mul(&tempx, &tempy, &QX, &QY, &r, &A, &P);

    Two_points_add(&mx, &my, &tempx, &tempy, &c1x, &c1y, &A, zero, &P);

    // 保存密文
    chmistore(&c1x, fq);

    chmistore(&c1y, fq);

    chmistore(&c2x, fq);

    chmistore(&c2y, fq);
  }

  cout << "\nok!加密完毕!" << endl;
  cout << "密文以二进制保存" << endl;
  cout << "密文存放路径为  " << outPath << endl;

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

void ECC::Ecc_saveKey(string outPath) {
  outPath += "privateKey.txt";
  ofstream out(outPath, ios::out);
  if (out.is_open()) {
    out << tempK << "\n";
    out << tempA << "\n";
    out << temp << "\n";
    out.close();
  }
}

void ECC::Ecc_loadKey(string inPath) {
  char tempK[800] = {0};
  char tempA[800] = {0};
  char temp[800] = {0};
  inPath += "privateKey.txt";
  ifstream ifile(inPath, ios::out);
  if (ifile.fail())
    cout << "The file does not exist";
  else {
    ifile.getline(tempK, 800);
    ifile.getline(tempA, 800);
    ifile.getline(temp, 800);
    ifile.close();
  }
  mp_err ret = mp_read_radix(&K, tempK, 10);
  ret = mp_read_radix(&A, tempA, 10);
  ret = mp_read_radix(&P, temp, 10);
}

// 取密文

int ECC::miwendraw(mp_int *a, char *ch, int chlong) {
  mp_digit *temp;
  int i, j, res;

  if (a->alloc < chlong / 4) {
    if ((res = mp_grow(a, chlong / 4)) != MP_OKAY)
      return res;
  }

  a->alloc = chlong / 4;
  a->sign = MP_ZPOS;
  mp_zero(a);
  temp = a->dp;
  i = 0;

  for (j = 0; j < chlong / 4; j++) {
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

// 实现将mp_int数a中的比特串还原为字符串并赋给字符串ch：
int ECC::chdraw(mp_int *a, char *ch) {
  int i, j;
  mp_digit *temp, xx, yy;

  temp = a->dp;
  i = 0;
  yy = (mp_digit)255; // 用于位与运算，取八位比特串
  xx = (mp_digit)15;  // 用于位与运算，取四位比特串

  for (j = 0; j < a->used / 2;
       j++) // 以两个单元为循环，把两个单元的比特串赋给7个字符
  {
    i += 7;
    ch[i - 4] = (char)(*++temp & xx);
    ch[i - 3] = (char)((*temp >> (mp_digit)4) & yy);
    ch[i - 2] = (char)((*temp >> (mp_digit)12) & yy);
    ch[i - 1] = (char)((*temp-- >> (mp_digit)20) & yy);

    ch[i - 7] = (char)(*temp & yy);
    ch[i - 6] = (char)((*temp >> (mp_digit)8) & yy);
    ch[i - 5] = (char)((*temp >> (mp_digit)16) & yy);
    ch[i - 4] <<= 4;
    ch[i - 4] += (char)((*temp++ >> (mp_digit)24) & xx);
    temp++;
  }
  if (a->used % 2 != 0) // 剩于一个单元的处理
  {
    ch[i++] = (char)(*temp & yy);
    ch[i++] = (char)((*temp >> (mp_digit)8) & yy);
    ch[i++] = (char)((*temp >> (mp_digit)16) & yy);
  }
  --i;
  while (int(ch[i] & 0xFF) != 255 && i > 0)
    i--;
  return i;
}

void ECC::Ecc_decipher(char *inPath, string outPath) {

  mp_int c1x, c1y;
  mp_int c2x, c2y;
  mp_int tempx, tempy;
  mp_int mx, my;
  mp_int temp;

  mp_err ret = mp_init(&temp);
  ret = mp_init(&c1x);
  ret = mp_init(&c1y);
  ret = mp_init(&c2x);
  ret = mp_init(&c2y);
  ret = mp_init(&tempx);
  ret = mp_init(&tempy);
  ret = mp_init(&mx);
  ret = mp_init(&my);

  mp_int tempzero;
  ret = mp_init(&tempzero);

  int i;
  char stemp[700] = {0};
  bool zero = false;

  // char filehead[60], filefoot[20], filename[85] = { 0 };
  // cout << "请输入您要解密的文件的存放路径和文件名(如:  c:\\000\\大整数运算
  // ):" << endl; cin >> filehead; cout << "请输入您要解密的文件的扩展名(如:
  // .doc  ):" << endl; cin >> filefoot; strcpy_s(filename, filehead);
  // strcat_s(filename, filefoot);

  // printf("\n开始解密\n");

  FILE *fp = fopen(inPath, "rb");
  if (fp == NULL) {
    printf("can not open the file!");
    exit(1);
  }

  ////打开保存解密结果文件
  // char filemi[80];
  // strcpy_s(filemi, filehead);
  // strcat_s(filemi, "解密");
  // strcat_s(filemi, filefoot);

  FILE *fq = fopen(outPath.c_str(), "wb");
  if (fq == NULL) {
    printf("can not open the file!");
    exit(1);
  }

  rewind(fp);
  while (!feof(fp)) {
    i = 0;
    while (1) {
      stemp[i] = fgetc(fp);
      if (i % 4 == 0) {
        if (int(stemp[i] & 0xFF) == 255)
          goto L1;
      }
      i++;
    }

  L1:
    miwendraw(&c1x, stemp, i);
    i = 0;
    while (1) {
      stemp[i] = fgetc(fp);
      if (i % 4 == 0) {
        if (int(stemp[i] & 0xFF) == 255)
          goto L2;
      }
      i++;
    }

  L2:
    miwendraw(&c1y, stemp, i);
    i = 0;
    while (1) {
      stemp[i] = fgetc(fp);
      if (i % 4 == 0) {
        if (int(stemp[i] & 0xFF) == 255)
          goto L3;
      }
      i++;
    }

  L3:
    miwendraw(&c2x, stemp, i);
    i = 0;
    while (1) {
      stemp[i] = fgetc(fp);
      if (i % 4 == 0) {
        if (int(stemp[i] & 0xFF) == 255)
          goto L4;
      }
      i++;
    }

  L4:
    miwendraw(&c2y, stemp, i);

    mp_zero(&tempzero);
    if (mp_cmp(&c1x, &tempzero) == 0)
      break;

    Ecc_points_mul(&tempx, &tempy, &c2x, &c2y, &K, &A, &P);

    ret = mp_neg(&tempy, &temp);
    Two_points_add(&c1x, &c1y, &tempx, &temp, &mx, &my, &A, zero, &P);

    int chtem;
    chtem = chdraw(&mx, stemp); // 从ming中取出字符串

    // 保存解密结果

    for (int kk = 0; kk < chtem; kk++) {
      fprintf(fq, "%c", stemp[kk]);
    }

    chtem = chdraw(&my, stemp); // 从ming中取出字符串

    // 保存解密结果
    for (int kk = 0; kk < chtem; kk++) {
      fprintf(fq, "%c", stemp[kk]);
    }
  }

  cout << "\nok!解密完毕!" << endl;
  cout << "解密后的文字存放路径为  " << outPath << endl;

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