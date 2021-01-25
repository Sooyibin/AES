#include <stdio.h>
#include <stdlib.h>

#define Nr 10
#define Nk 4
#define Nb 4
#define R 0x11b

static char s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

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

/* 列混淆 */
void MixColumn(unsigned char *state){
    int i, j, k;
    unsigned char tmp[4];
    unsigned char A[] = {0x02, 0x03, 0x01, 0x01};
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

/* AES加密 */
void AES_cipher(unsigned char *in, unsigned char *out, unsigned char *key){
    int i, j, k;
    unsigned char *ExpKey = (unsigned char *)malloc(Nb*(Nr+1)*4);
    unsigned char *state = (unsigned char *)malloc(Nb*4);
    KeyExpansion(key, ExpKey);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            state[j*4+i] = in[j*4+i];
        }
    }
    AddRoundKey(state, ExpKey);
    for(i = 1; i < 2; i++){
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

int main(){
    unsigned char in[16] = {
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x33
    };
    unsigned char *out = (unsigned char *)malloc(16);
    unsigned char k[Nk*4] = {
        0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x32, 0x32, 0x32, 0x32
    };
    AES_cipher(in, out, k);
    display(out);
    return 0;
}