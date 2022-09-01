#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <string>
#include <cstring>

#define int32 uint32_t
#define msglen 64
#define blocklen 8
#define charlen 8

using namespace std;

/**
 * @brief struct type to hold encrypted strings as half-block arrays
 * 
 */
typedef struct encrypted_string_t {
    int32 * array;
    size_t size;
} encrypted_string;

/**
 * @brief basic Wikipedia Blowfish blowfish_encryption implementation
 * @author Joseph Coston
 *
 */

int32 P[18];     // 18-entry P-array
int32 S[4][256]; // 4 S-boxes

int32 f(int32 x)
{
    int32 h = S[0][x >> 24] + S[1][x >> 16 & 0xff];
    return (h ^ S[2][x >> 8 & 0xff]) + S[3][x & 0xff];
}

/**
 * @brief simple swap function to exchange the values of L and R
 *
 * @param L the left value to swap with R
 * @param R the right value to swap with L
 */
void swap(int32 *L, int32 *R)
{
    int32 tmp = *R;
    *R = *L;
    *L = tmp;
}

void blowfish_encrypt(int32 *L, int32 *R)
{
    for (int r = 0; r < 16; r++)
    {
        *L = *L ^ P[r];
        *R = f(*L) ^ *R;
        swap(L, R);
    }
    swap(L, R);
    *R = *R ^ P[16];
    *L = *L ^ P[17];
}

void blowfish_decrypt(int32 *L, int32 *R)
{
    for (int r = 17; r > 1; r--)
    {
        *L = *L ^ P[r];
        *R = f(*L) ^ *R;
        swap(L, R);
    }
    swap(L, R);
    *R = *R ^ P[1];
    *L = *L ^ P[0];
}

/**
 * @brief initialize P-array with key*
 *
 * @param key
 * @param key_len
 */
void gen_P(int32 *key, int32 key_len)
{
    int32 k;
    for (int i = 0, p = 0; i < 18; i++)
    {
        k = 0x00;
        for (int j = 0; j < 4; j++)
        {
            k = (k << 8) | (uint8_t)key[p];
            p = (p + 1) % key_len;
        }
        P[i] ^= k;
    }

    // perform key expansion
    int32 l = 0x00, r = 0x00;
    for (int i = 0; i < 18; i += 2)
    {
        blowfish_encrypt(&l, &r);
        P[i] = l;
        P[i + 1] = r;
    }
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 256; j += 2)
        {
            blowfish_encrypt(&l, &r);
            S[i][j] = l;
            S[i][j + 1] = r;
        }
    }
}

/**
 * @brief function to convert an array of half-block data to a string
 * 
 * @param blocks array of 32-bit half-blocks 
 * @param length length of the array
 * @return string the string representative of the array
 */
string blocks_to_string(int32* blocks, size_t length)
{
    string s = "";
    for (int i = 0; i < length; i++)
    {
        plaintext.append(1, (char)((ciphertext[i] & 0xff000000) >> 24));
        plaintext.append(1, (char)((ciphertext[i] & 0x00ff0000) >> 16));
        plaintext.append(1, (char)((ciphertext[i] & 0x0000ff00) >> 8));
        plaintext.append(1, (char)(ciphertext[i] & 0x000000ff));
    }
}

int32 *encrypt(string message)
{
    encrypted_string CIPHERTEXT;


    // generate a C string from the message
    int message_len = message.length() + 1;
    printf("message length: %d chars (%d blocks)\n", message_len, message_len / blocklen); // for @debug
    char *plaintext = new char[message_len];
    strncpy(plaintext, message.c_str(), message_len);

    // create an array of blocks to contain ciphertext
    uint32_t *ciphertext = new uint32_t[message_len / blocklen * 2];

    // divide the message into blocks and encrypt them
    for (int i = 0; i < message_len / blocklen * 2; i += 2)
    {
        uint64_t block = 0x00;
        for (int j = 0; j < blocklen; j++)
        { // bit-shift the string chars into a block
            block = block << charlen | plaintext[0];
            plaintext++;
        }
        int32 blockL = (int32)(block >> 32);
        int32 blockR = (int32)(block & 0xffffffff);
        blowfish_encrypt(&blockL, &blockR);
        ciphertext[i] = blockL;
        ciphertext[i + 1] = blockR;
    }
    return ciphertext;
}

/**
 * @brief 
 * @todo finish this!!
 * 
 * @param ciphertext 
 * @return string 
 */
string decrypt(int32 *ciphertext, size_t length)
{
    string plaintext = "";
    // take each half-block pair and decrypt them
    for (int i = 0; i < length; i += 2)
    {
        // int32 blockL = ciphertext[i];
        // int32 blockR = ciphertext[i + 1];
        blowfish_decrypt(&ciphertext[i], &ciphertext[i+1]);
    }
    for (int i = 0; i < length; i++)
    {
        plaintext.append(1, (char)((ciphertext[i] & 0xff000000) >> 24));
        plaintext.append(1, (char)((ciphertext[i] & 0x00ff0000) >> 16));
        plaintext.append(1, (char)((ciphertext[i] & 0x0000ff00) >> 8));
        plaintext.append(1, (char)(ciphertext[i] & 0x000000ff));
    }
    return plaintext;
}

int main(int argp, char *argv[])
{
    int32 key = 0x69;
    printf("the key is: %d\n", key);
    gen_P(&key, 1);

    string text = "Skyler! XD";

    // pad the message string to be block-divisible
    if ((text.length() + 1) % blocklen)
    {
        int pad_width = blocklen - ((text.length() + 1) % blocklen);
        text.append(pad_width, (char)pad_width);
    }

    int32 *ciphertext = encrypt(text);
    size_t ciphertext_length = (text.length() + 1) / blocklen * 2;
    printf("ciphertext length: %ld half-blocks\n", ciphertext_length);


    int32 blockL = ciphertext[0], blockR = ciphertext[1];

    char encrypted[9];
    encrypted[0] = (blockL & 0xff000000)>>24;
    encrypted[1] = (blockL & 0x00ff0000)>>16;
    encrypted[2] = (blockL & 0x0000ff00)>>8;
    encrypted[3] = (blockL & 0x000000ff);
    encrypted[4] = (blockR & 0xff000000)>>24;
    encrypted[5] = (blockR & 0x00ff0000)>>16;
    encrypted[6] = (blockR & 0x0000ff00)>>8;
    encrypted[7] = (blockR & 0x000000ff);
    encrypted[8] = '\0';

    string decrypted = decrypt(ciphertext, ciphertext_length);

    // char decrypted[9];
    // decrypted[0] = (blockL & 0xff000000)>>24;
    // decrypted[1] = (blockL & 0x00ff0000)>>16;
    // decrypted[2] = (blockL & 0x0000ff00)>>8;
    // decrypted[3] = (blockL & 0x000000ff);
    // decrypted[4] = (blockR & 0xff000000)>>24;
    // decrypted[5] = (blockR & 0x00ff0000)>>16;
    // decrypted[6] = (blockR & 0x0000ff00)>>8;
    // decrypted[7] = (blockR & 0x000000ff);
    // decrypted[8] = '\0';

    printf("the plaintext is: %s\n", text.c_str());
    // printf("the ciphertext is: %d\n", ciphertext[0]);
    printf("the ciphertext encrypted is:             %s       \n",encrypted);
    printf("the plaintext decrypted is:   %s       \n",decrypted.c_str());
}