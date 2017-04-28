/**
 * @author Ricardo Román <reroman4@gmail.com>
 */

#include "rsa.h"
#include <stdlib.h>
#include <time.h>
#include <math.h>

uint64_t random_bits( uint8_t n )
{
	static int first = 1;
	int i;
	char *num;
	uint64_t result;

	if( first ){
		srand( time(NULL) );
		first = !first;
	}

	if( n > 64 )
		return -1;

	num = malloc( n + 1 );
	num[0] = '1';
	for( i = 1 ; i < n ; i++ )
		num[i] = rand() % 2 + '0';
	num[n] = '\0';

	result = strtoull( num, NULL, 2 );
	free( num );

	return result;
}

int createKeys( RSAKeys *res, uint8_t n )
{
	int64_t auxD;

	if( n > 32 )
		return -1;
	uint32_t p, q, x;

	do{
		p = nextPrime( random_bits( n/2 ) );
		q = nextPrime( random_bits( n/2 ) );

		res->n = p * q;
		x = (p-1) * (q-1);

		res->e = 65537;
		while( gcd( res->e, x ) != 1 )
			res->e += 2;

		auxD = invert( res->e, x );
		while( auxD < 0 )
			auxD += x;
	}while( auxD > (int64_t)res->n );
	res->d = auxD;
	return 0;
}

uint32_t encrypt( uint32_t c, const RSAKeys *keys )
{
	return bin_pow_mod( c, keys->e, keys->n );
}

uint32_t decrypt( uint32_t c, const RSAKeys *keys )
{
	return bin_pow_mod( c, keys->d, keys->n );
}

uint32_t bin_pow_mod( uint32_t a, uint64_t x, uint32_t n )
{
	uint32_t res = 1;
	uint64_t aux = a % n;

	if( n == 1 )
		return 0;
	if( x == 0 )
		return 1;
	if( x == 1 )
		return aux;

	while( x > 0 ){
		if( x & 1 )
			res = res * aux % n;
		aux = aux * aux % n;
		x >>= 1;
	}
	return res;
}

uint32_t gcd( uint32_t a, uint32_t b )
{
	uint32_t mod;

	if( a < b ){
		uint32_t temp = a;
		a = b;
		b = temp;
	}

	while( b != 0 ){
		mod = a % b;
		a = b;
		b = mod;
	}
	return a;;
}

int64_t invert( int64_t a, int64_t b )
{
	int64_t x, x1, x2, y, y1, y2, q, r;

	if( a < b ){
		a = a ^ b;
		b = a ^ b;
		a = a ^ b;
	}
	q = r = x1 = y2 = 0;
	x2 = y1 = 1;

	while( b > 0 ){
		q = a / b;
		r = a - q * b;
		x = x2 - q * x1;
		y = y2 - q * y1;
		a = b;
		b = r;
		x2 = x1;
		x1 = x;
		y2 = y1;
		y1 = y;
	}
	return y2;
}

int isPrime( uint32_t a )
{
	uint32_t sqrt_a = (uint32_t) sqrt( a );
	uint32_t i;

	if( a == 2 )
		return 1;

	if( a % 2 == 0 )
		return 0;

	for( i = 3 ; i <= sqrt_a ; i += 2 )
		if( a % i == 0 )
			return 0;
	return 1;
}

uint32_t nextPrime( uint32_t a )
{
	uint64_t aux = a;

	do{
		if( ++aux == 0x100000000 )
			return 0;
	}while( !isPrime( aux ) );
	return aux;
}
