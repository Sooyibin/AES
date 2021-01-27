#include "AES.h"

/*
    Basic Cryptography 2021
    Editted by Sooyibin
    2021.1.27
*/

/* GF[8]多项式乘法 */
unsigned char multi(unsigned char a, unsigned char b){
    unsigned char tmp = 0;
    int b_tmp = b;
    while(a){
        if(a%2) tmp ^= b_tmp;
        a = a >> 1;
        b_tmp = b_tmp << 1;
        if(b_tmp > 0xff) b_tmp ^= R;
    }
    return tmp;
}

/* 计算轮常数 */
unsigned char rcon(int i){
    unsigned char r = 0x01;
    if(i > 1){
        while(i>1){
            r = multi(r, 0x02);
            i--;
        }
    }
    return r;
}

/* 密钥扩展 */
void KeyExpansion(unsigned char *key, unsigned char *ExpKey){
    int i, j, k;
    int len = Nb*(Nr+1);
    unsigned char *tmp = (unsigned char *)malloc(16);
    unsigned char c;
    /* 第一部分密钥就是种子密钥 */
    for(i = 0; i < Nk; i++){
        for(j = 0; j < 4; j++){
            ExpKey[i*4+j] = key[i*4+j];
        }
    }
    for(i = Nk; i < len; i++){
        /* tmp数组存储最新字的前一个字 */
        for(j = 0; j < 4; j++){
            tmp[j] = ExpKey[4*(i-1)+j];
        }

        if(i%Nk == 0){ // 如果i/Nk为整数
            /* 一字节的循环移位 */
            c = tmp[0];
            for(k = 0; k < 3; k++) tmp[k] = tmp[k+1];
            tmp[3] = c;
            
            /* 用S盒变换 */
            for(k = 0; k < 4; k++) tmp[k] = s_box[tmp[k]];

            /* 异或轮常数 */
            for(k = 0; k < 4; k++) tmp[k] = tmp[k] ^ ((k == 0) ? rcon(i/Nk) : 0);
        }
        else if(Nk > 6 && i%Nk == 4){
            /* sbox替换 */
            for(k = 0; k < 4; k++) tmp[k] = s_box[tmp[k]];
        }
        /* 和Nk前的字异或 */
        for(j = 0; j < 4; j++) ExpKey[4*i+j] =  ExpKey[4*(i-Nk)+j] ^ tmp[j];
        //printf("expkey: 0x%x 0x%x 0x%x 0x%x\n", ExpKey[4*i+0], ExpKey[4*i+1], ExpKey[4*i+2], ExpKey[4*i+3]);
    }
}

/* 轮密钥加 */
void AddRoundKey(unsigned char *state, unsigned char *ExpKey){
    int i, j;
    for(i = 0; i < Nb; i++){
        for(j = 0; j < 4; j++){
            state[j*Nb+i] ^= ExpKey[i*4+j];
        }
    }
}

/* S盒替换 */
void SubBytes(unsigned char *state){
    int i, j, row, col;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            row = state[i*Nb+j] >> 4; // 获取行
            col = state[i*Nb+j] & 0x0f; // 获取列
            state[i*Nb+j] = s_box[16*row+col]; // sbox替换
        }
    }
}

/* 逆S盒变换 */
void InvSubBytes(unsigned char *state){
    int i, j, row, col;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            row = state[i*Nb+j] >> 4; // 获取行
            col = state[i*Nb+j] & 0x0f; // 获取列
            state[i*Nb+j] = inv_s_box[16*row+col]; // sbox替换
        }
    }
}

/* 行移位 */
void RowShift(unsigned char *state){
    int i, j, k;
    unsigned char tmp;
    for(i = 1; i < 4; i++){
        for(j = i; j < 4; j++){
            tmp = state[j*Nb+0]; //存下第一个元素
            for(k = 0; k < Nb-1; k++) state[Nb*j+k] = state[Nb*j+k+1]; //移位
            state[Nb*j+Nb-1] = tmp; //将第一个元素放到最后
        }
    }
}

/* 逆行移位 */
void InvShiftRow(unsigned char *state){
    int i, j, k;
    unsigned char tmp;
    for(i = 1; i < 4; i++){
        for(j = i; j < 4; j++){
            tmp = state[j*Nb+Nb-1]; //存下最后一个元素
            for(k = Nb-1; k > 0; k--) state[Nb*j+k] = state[Nb*j+k-1]; //移位
            state[Nb*j+0] = tmp; //将最后一个元素放在第一个
        }
    }
}

/* 列混淆 */
void MixColumn(unsigned char *state){
    int i, j, k;
    unsigned char tmp[4];
    unsigned char A[] = {0x02, 0x03, 0x01, 0x01};
    for(i = 0; i < Nb; i++){
        for(j = 0; j < 4; j++){
            tmp[j] = 0;
            for(k = 0; k < 4; k++) tmp[j] ^= multi(state[k*Nb+i], A[(k-j+4)%4]);
        }
        for(j = 0; j < 4; j++) state[j*Nb+i] = tmp[j];
    }
}

/* 逆列混淆 */
void InvMixColumn(unsigned char *state){
    int i, j, k;
    unsigned char tmp[4];
    unsigned char A[] = {0x0e, 0x0b, 0x0d, 0x09};
    for(i = 0; i < Nb; i++){
        for(j = 0; j < 4; j++){
            tmp[j] = 0;
            for(k = 0; k < 4; k++){
                tmp[j] ^= multi(state[k*Nb+i], A[(k-j+4)%4]);
            }
        }
        for(j = 0; j < 4; j++) state[j*Nb+i] = tmp[j];
    }
}

void display(unsigned char *out){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            printf("0x%x ", out[Nb*i+j]);
        }
        printf("\n");
    }
    printf("\n");
}