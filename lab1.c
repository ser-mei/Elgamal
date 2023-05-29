#include <stdio.h>
#include <time.h>
#include <gmp.h>

int main()
{
    const char elgamalp[] = "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1 D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9 7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561 2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935 984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735 30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19 0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61 9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73 3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA 886B4238 61285C97 FFFFFFFF FFFFFFFF";

//Declare variables and state
    mpz_t p, g, secretKey, publicKey, message, ephemeralKey, cipher1, cipher2, c1inverse, decrypted;
    gmp_randstate_t state;

//Initialize variables and state
    mpz_init(p);
    mpz_init(g);
    mpz_init(secretKey);
    mpz_init(publicKey);
    mpz_init(message);
    mpz_init(ephemeralKey);
    mpz_init(cipher1);
    mpz_init(cipher2);
    mpz_init(c1inverse);
    mpz_init(decrypted);
    gmp_randinit_mt(state);

//Seed the random state
    gmp_randseed_ui(state, time(NULL));

/*
//If the number is even, add 1 to make it odd
    if(mpz_even_p(rand_num) != 0)
        mpz_add_ui(rand_num, rand_num, 1);

//Print the random number
    gmp_printf("Random number: %Zd\n", rand_num);

//Check if the number is prime
    while(mpz_probab_prime_p(rand_num, 25) == 0)
        mpz_add_ui(rand_num, rand_num, 1);

    if(mpz_probab_prime_p(rand_num, 25) == 0)
        printf("Composite\n");
    else
        printf("Probably prime\n");

    mpz_sub_ui(phiden, rand_num, 1);

    gmp_printf("Phi(n): %Zd\n", phiden);

    mpz_primorial_ui(primorial, 180);

    gmp_printf("Primorial: %Zd\n", primorial);

    mpz_gcd(factor, phiden, primorial);

    gmp_printf("GCD: %Zd\n", factor);

    while(mpz_cmp_ui(factor, 1) != 0)
    {
        mpz_cdiv_q(phiden, phiden, factor);
        mpz_gcd(factor, phiden, primorial);
        gmp_printf("GCD: %Zd\n", factor);
    }*/

//Declare time variables
    clock_t time1, time2;

    time1 = clock();

//Set p and g
    mpz_set_str(p, elgamalp, 16);
    mpz_set_ui(g, 2);

    gmp_printf("ElgamalP: %#ZX\n", p);

//Generate random number between 0 and p-1
    mpz_urandomm(secretKey, state, p);
    gmp_printf("SecretKey: %#ZX\n", secretKey);

//Calculate public key A = g^a mod p
    mpz_powm(publicKey, g, secretKey, p);
    gmp_printf("Public Key: %#ZX\n", publicKey);

//Generate random Bob message m

    //mpz_urandomm(message, state, p);
    mpz_set_str(message, "FFFFFF", 16);
    gmp_printf("Message: %#ZX\n", message);

//Generate random ephemeral key k
    mpz_urandomm(ephemeralKey, state, p);
    gmp_printf("Ephemeral Key: %#ZX\n", ephemeralKey);

//Calculate c1 = g^k mod p
    mpz_powm(cipher1, g, ephemeralKey, p);
    gmp_printf("Cipher1: %#ZX\n", cipher1);

//Calculate c2 = m * A^k mod p
    mpz_powm(cipher2, publicKey, ephemeralKey, p);
    mpz_mul(cipher2, message, cipher2);
    mpz_mod(cipher2, cipher2, p);
    gmp_printf("Cipher2: %#ZX \n", cipher2);

//Calculate c1 inverse = (c1^a)^-1 mod p
    mpz_powm(c1inverse, cipher1, secretKey, p);
    mpz_invert(c1inverse, c1inverse, p);
    gmp_printf("C1 Inverse: %#ZX\n", c1inverse);

//Decrypt message m = (c1^a)^-1 * c2 mod p
    mpz_mul(decrypted, c1inverse, cipher2);
    mpz_mod(decrypted, decrypted, p);
    gmp_printf("Decrypted Message: %#ZX\n", decrypted);

    time2 = clock();
    printf("Time: %f\n" , ( (double)time2 - (double)time1 ) / ( (double)CLOCKS_PER_SEC ) );    

//Compare decrypted message to original message
    if(mpz_cmp(message, decrypted) == 0)
        printf("Message decrypted successfully\n");
    else
        printf("Message decryption failed\n");

    

//Clear memory
    mpz_clear(secretKey);
    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(publicKey);
    mpz_clear(message);
    mpz_clear(ephemeralKey);
    mpz_clear(cipher1);
    mpz_clear(cipher2);
    mpz_clear(c1inverse);
    mpz_clear(decrypted);

    gmp_randclear(state);

    return 0;
}