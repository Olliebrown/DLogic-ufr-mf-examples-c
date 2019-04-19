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
void printCurrentAuthConfig();
void usage(void);
void operation_BlockRead();
void operation_BlockWrite();
void operation_LinearRead();
void operation_LinearWrite();
void operation_ReaderKeyWrite();
void operation_ReaderKeyWriteAes();
bool isCardMifarePlus();
#if linux || __linux__ || __APPLE__

int _kbhit(void);
void _resetTermios(void);
char _getch(void);
#endif
