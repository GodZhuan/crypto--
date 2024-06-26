#include "../include/sts.h"

STS::STS() = default;

STS::~STS() = default;

int STS::GetPrime(mp_int *p, mp_int *a, int lon) {
  mp_prime_rand(p, 10, lon,
                (rand() & 1) ? 0 : MP_PRIME_2MSB_ON | MP_PRIME_SAFE);
  get_primitive_root(p, a);
  return MP_OKAY;
}

void STS::get_primitive_root(mp_int *num, mp_int *root) {
  mp_set(root, 2);
  mp_int temp;
  mp_int param1;
  mp_int param2;
  // 第一个参数为2
  mp_err err = mp_init_set(&param1, 2);
  err = mp_init_multi(&temp, &param2, NULL);
  // 第二个参数问 (roo-1)/2
  err = mp_sub_d(num, 1, &param2);
  err = mp_div_2(&param2, &param2);
  while (true) {
    err = mp_exptmod(root, &param1, num, &temp);
    if (mp_cmp_d(&temp, 1) != MP_EQ) {
      err = mp_exptmod(root, &param2, num, &temp);
      if (mp_cmp_d(&temp, 1) != MP_EQ) {
        break;
      }
    }
    err = mp_add_d(root, 1, root);
  }
  mp_clear_multi(&temp, &param1, &param2, NULL);
}
