#ifndef _STS_H_
#define _STS_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include "tommath.h"
#include <time.h>


#define BIT_LEN 800 
#define KEY_LONG 256  //私钥比特长
#define P_LONG 200    //有限域P比特长
#define EN_LONG 40    //一次取明文字节数(x,20)(y,20)

class STS
{
public:
	STS();
	~STS();
	//得到lon比特长素数p
	int GetPrime(mp_int* p, mp_int* a, int lon);
	void get_primitive_root(mp_int* num, mp_int* root);
private:

};

#endif // !_STS_H_

