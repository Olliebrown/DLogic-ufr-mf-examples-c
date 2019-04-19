#ifndef VERSION_MK_H_
#define VERSION_MK_H_

#define TOKENIZE_VER(a,b) a##.##b
#define EXPAND_VER(a,b)   TOKENIZE_VER(a,b)
#define STRINGIZE(x) #x
#define EXPAND(x) STRINGIZE(x)
#define EXPAND_ADD_0_0(x) STRINGIZE(x) ".0.0"

#define MAJOR_VER    1
#define MINOR_VER    8
#define APP_VER      EXPAND_VER(MAJOR_VER, MINOR_VER) /*
        APP_VER=   1.8
#
# You have to manualy change:
#     MAJOR_VER,
#     MINOR_VER,
#     and for C/C++ commented out APP_VER=
#
#*/
#endif /* VERSION_MK_H_ */
