#include <string>
#include <iostream>
#include <sstream>
#include <cstring>
#include <string.h>
#include "../lib/include/uFCoder.h"

using namespace std;

void changeAuthMode();
void changeAuthenticationKey();
void changeKeyIndex();
void changeProvidedKey();
void convertStrToByteArray(string str, uint8_t *array);
void ConvertStringToUint8Array(std::string str, uint8_t *array);
string eraseDelimiters(string hexStr);
bool isHexChar(char c);
string ConvertToHexArray(const uint8_t *data, int len, string delimiter);
void printCurrentAuthConfig(void);
void usage(void);
void operation_BlockRead(void);
void operation_BlockInSectorRead(void);
void operation_BlockWrite(void);
void operation_BlockInSectorWrite(void);
void operation_LinearRead(void);
void operation_LinearWrite(void);
void operation_ReaderKeyWrite(void);
void operation_ReaderKeyWriteAes(void);
void operation_SamKeyWrite(void);
void operation_ValueBlockRead(void);
void operation_ValueBlockWrite(void);
void operation_ValueBlockIncrement(void);
void operation_ValueBlockDecrement(void);
void operation_ValueBlockInSectorRead(void);
void operation_ValueBlockInSectorWrite(void);
void operation_ValueBlockInSectorIncrement(void);
void operation_ValueBlockInSectorDecrement(void);
void operation_SectorTrailerWrite(void);

#if linux || __linux__ || __APPLE__
int _kbhit(void);
void _resetTermios(void);
char _getch(void);
#endif
