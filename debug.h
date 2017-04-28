#ifndef MY_DEBUG_H
#define MY_DEBUG_H

#ifndef NDEBUG
#include <stdio.h>
#include <wchar.h>

#define debug(FormatLiteral, ...)  fprintf(stderr, "%s(%u): " FormatLiteral "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define wdebug(FormatLiteral, ...)  fwprintf(stderr, L"%s(%u): " FormatLiteral "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define derror( StringLiteral )		perror( StringLiteral )

#else
#define debug( FormatLiteral, ... )
#define derror( StringLiteral )
#endif

#endif
