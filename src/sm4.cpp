#include "../include/sm4.h"
namespace crypto__ {
void SM4::SM4_KeySchedule(uint8_t MK[], uint32_t rk[]) {
  uint32_t tmp, buf, K[36];
  int i;
  for (i = 0; i < 4; i++) {
    K[i] = SM4_FK[i] ^ ((MK[4 * i] << 24) | (MK[4 * i + 1] << 16) |
                        (MK[4 * i + 2] << 8) | (MK[4 * i + 3]));
  }
  for (i = 0; i < 32; i++) {
    tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i];
    // nonlinear operation
    buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24 |
          (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16 |
          (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | (SM4_Sbox[tmp & 0xFF]);
    // linear operation
    K[i + 4] = K[i] ^ ((buf) ^ (rotl32((buf), 13)) ^ (rotl32((buf), 23)));
    rk[i] = K[i + 4];
  }
}

void SM4::SM4_Encrypt(uint8_t MK[], uint8_t PlainText[], uint8_t CipherText[]) {
  uint32_t rk[32], X[36], tmp, buf;
  int i, j;
  SM4_KeySchedule(MK, rk);
  for (j = 0; j < 4; j++) {
    X[j] = (PlainText[j * 4] << 24) | (PlainText[j * 4 + 1] << 16) |
           (PlainText[j * 4 + 2] << 8) | (PlainText[j * 4 + 3]);
  }
  for (i = 0; i < 32; i++) {
    tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
    // nonlinear operation
    buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24 |
          (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16 |
          (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | (SM4_Sbox[tmp & 0xFF]);
    // linear operation
    X[i + 4] = X[i] ^ (buf ^ rotl32((buf), 2) ^ rotl32((buf), 10) ^
                       rotl32((buf), 18) ^ rotl32((buf), 24));
  }
  for (j = 0; j < 4; j++) {
    CipherText[4 * j] = (X[35 - j] >> 24) & 0xFF;
    CipherText[4 * j + 1] = (X[35 - j] >> 16) & 0xFF;
    CipherText[4 * j + 2] = (X[35 - j] >> 8) & 0xFF;
    CipherText[4 * j + 3] = (X[35 - j]) & 0xFF;
  }
}

void SM4::SM4_Decrypt(uint8_t MK[], uint8_t CipherText[], uint8_t PlainText[]) {
  uint32_t rk[32], X[36], tmp, buf;
  int i, j;
  SM4_KeySchedule(MK, rk);
  for (j = 0; j < 4; j++) {
    X[j] = (CipherText[j * 4] << 24) | (CipherText[j * 4 + 1] << 16) |
           (CipherText[j * 4 + 2] << 8) | (CipherText[j * 4 + 3]);
  }
  for (i = 0; i < 32; i++) {
    tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[31 - i];
    // nonlinear operation
    buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24 |
          (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16 |
          (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8 | (SM4_Sbox[tmp & 0xFF]);
    // linear operation
    X[i + 4] = X[i] ^ (buf ^ rotl32((buf), 2) ^ rotl32((buf), 10) ^
                       rotl32((buf), 18) ^ rotl32((buf), 24));
  }
  for (j = 0; j < 4; j++) {
    PlainText[4 * j] = (X[35 - j] >> 24) & 0xFF;
    PlainText[4 * j + 1] = (X[35 - j] >> 16) & 0xFF;
    PlainText[4 * j + 2] = (X[35 - j] >> 8) & 0xFF;
    PlainText[4 * j + 3] = (X[35 - j]) & 0xFF;
  }
}

int SM4::SM4_SelfCheck() {
  int i;
  // Standard data
  uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  uint8_t plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  uint8_t cipher[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
  uint8_t En_output[16];
  uint8_t De_output[16];
  SM4_Encrypt(key, plain, En_output);
  SM4_Decrypt(key, cipher, De_output);
  for (i = 0; i < 16; i++) {
    if ((En_output[i] != cipher[i]) | (De_output[i] != plain[i])) {
      printf("Self-check error");
      return 1;
    }
  }
  printf("Self-check success");
  return 0;
}
} // namespace crypto__
