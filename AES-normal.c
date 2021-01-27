#include "AES.h"

/*
    Basic Cryptography 2021
    Editted by Sooyibin
    2021.1.27
*/

static __inline__ unsigned long long GetCycleCount(void)
{
  unsigned long long int x;
     __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
     return x;
}

/* AES加密 */
void AES_cipher(unsigned char *in, unsigned char *out, unsigned char *key){
    int i, j, k;
    unsigned char ExpKey[Nb*(Nr+1)*4];
    unsigned char state[Nb*4];
    KeyExpansion(key, ExpKey);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            state[j*4+i] = in[j*4+i];
        }
    }
    AddRoundKey(state, ExpKey);
    for(i = 1; i < Nr; i++){
        SubBytes(state);
        RowShift(state);
        MixColumn(state);
        AddRoundKey(state, ExpKey+4*Nb*i);
    }
    SubBytes(state);
    RowShift(state);
    AddRoundKey(state, ExpKey+4*Nb*Nr);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            out[i*4+j] = state[i*4+j];
        }
    }
}

/* AES解密 */
void AES_decryption(unsigned char *in, unsigned char *out, unsigned char *key){
    int i, j, k;
    unsigned char ExpKey[Nb*(Nr+1)*4];
    unsigned char state[Nb*4];
    KeyExpansion(key, ExpKey);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            state[j*4+i] = in[j*4+i];
        }
    }
    AddRoundKey(state, ExpKey+4*Nb*Nr);
    for(i = Nr - 1; i >= 1; i--){
        InvSubBytes(state);
        InvShiftRow(state);
        AddRoundKey(state, ExpKey+4*Nb*i);  
        InvMixColumn(state);
    }
    InvSubBytes(state);
    InvShiftRow(state);
    AddRoundKey(state, ExpKey);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            out[i*4+j] = state[i*4+j];
        }
    }
}

int main(){
    unsigned long long x;
    unsigned long long  time1 = 0, time2 = 0;
    unsigned char in[16] = {
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33
    };
    unsigned char *out = (unsigned char *)malloc(16);
    unsigned char *plaintext = (unsigned char *)malloc(16);
    unsigned char k[Nk*4] = {
        0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x32, 0x32, 0x32, 0x32
    };
    printf("Plaintext block: \n");
    display(in);
    for(int i = 0; i < 10; i++){
        x = GetCycleCount();
        AES_cipher(in, out, k);
        time1 += GetCycleCount() - x;
        x = GetCycleCount();
        AES_decryption(out, plaintext, k);
        time2 += GetCycleCount() - x;
    }
    printf("Ciphertext block: \n");
    display(out);
    printf("Decrypted block: \n");
    display(plaintext);
    printf("Average CPU Cycles/Byte: Encryption %lld, Decryption %lld\n", time1/10/16, time2/10/16);
    return 0;
}