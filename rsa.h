/**
 * @author Ricardo Román <reroman4@gmail.com>
 */

#pragma once

#ifndef RSA_H
#define RSA_H

#include <stdint.h>

typedef struct{
	uint32_t e;
	uint32_t d;
	uint32_t n;
} RSAKeys;

/**
 * Genera un número aleatorio de n bits.
 *
 * @param n es el número de bits del número a generar.
 *
 * @return El número generado, -1 si n es mayor a 64.
 */
uint64_t random_bits( uint8_t n );

/**
 * Crea los valores para las llaves de cifrado y
 * descifrado del algoritmo RSA.
 *
 * @param res Apuntador en el cual se almacenarán las llaves generadas.
 * @param n Indica el número de bits del módulo.
 *
 * @return Esta función retorna 0 en caso de éxito, -1 si n es mayor a 32 (en 
 * este caso el valor de res no se modifica).
 *
 * @note Llaves mayores a 32 bits podrían no ser soportadas por
 * tipos nativos de C.
 */
int createKeys( RSAKeys *res, uint8_t n );

/**
 * Cifra un número c, utilizando el algoritmo RSA.
 *
 * @param c Valor a cifrar.
 * @param keys Apuntador que contiene las llaves con las
 * que se hará el cifrado.
 *
 * @return El valor c cifrado.
 *
 * @note Al cifrar valores de 32 bits, podría perderse información
 * si la llave es de menor valor.
 */
uint32_t encrypt( uint32_t c, const RSAKeys *keys );

/**
 * Descifra un número utilizando el algoritmo RSA.
 *
 * @param c Valor a descifrar.
 * @param keys Apuntador que contiene
 * las llaves con las que se hará el descifrado.
 *
 * @return El valor c descifrado.
 */
uint32_t decrypt( uint32_t c, const RSAKeys *keys );

/**
 * Calcula la potencia de un número y obtiene el módulo.
 *
 * @param a Indica la base.
 * @param x Indica el valor del exponente.
 * @param n Es el módulo.
 *
 * @return El resultado de a^x mod n.
 */
uint32_t bin_pow_mod( uint32_t a, uint64_t x, uint32_t n );

/**
 * Obtiene el máximo común divisor de dos números.
 * @param a Primer valor para calcular MCD
 * @param b Segundo valor para calcular MCD.
 *
 * @return El MCD entre a y b.
 */
uint32_t gcd( uint32_t a, uint32_t b );

/**
 * Obtiene el multiplicador modular inverso de 2 números,
 * utilizando el algoritmo de Euclides extendido.
 *
 * @param a Primer valor. 
 * @param b Segundo valor. 
 *
 * @return n, tal que n*a ≡ 1 mod b.
 */
int64_t invert( int64_t a, int64_t b );

/**
 * Determina si un número es primo mediante un sencillo
 * test de primalidad.
 *
 * @param a El número a evaluar.
 *
 * @return 1, si a es primo; 0 en caso contrario.
 */
int isPrime( uint32_t a );

/**
 * Retorna el siguiente número primo de un determinado
 * número
 *
 * @param a Indica a partir de qué número obtener el
 * siquiente primo.
 *
 * @return El siguiente número primo, 0 en caso de desborde.
 */
uint32_t nextPrime( uint32_t a );

#endif
