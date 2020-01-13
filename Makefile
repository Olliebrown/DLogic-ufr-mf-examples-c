#+-----------------------------------------------------------------------------+
#| makefile by Aleksandar Krstic                                               |
#| date: 19.04.2019.                                                           |
#+-----------------------------------------------------------------------------+
$(VERBOSE).SILENT:
#-------------------------------------------------------------------------------

all : help

info :
	echo "-------------------------------------------------------------------------"
	echo "Building executables"
	echo "---> version: 1.2"
	echo "-------------------------------------------------------------------------"
	echo

help :
	echo "-------------------------------------------------------------------------"
	echo "For different platforms - type:"
	echo " 'make win'  : on Windows (x86, x86_64 and InnoSetup)"
	echo " 'make lin'  : on Linux (x86, x86_64)"
	echo " 'make macos': on macOS (macOS dylib x86/x86_64)"
	echo " 'make rpi'  : on RPi (arm-hf)"
	echo "-------------------------------------------------------------------------"
	echo

BUILD_ARTEFACT=ufr.exe
LINBUILD_ARTEFACT=ufr

windows win :
	make info
	make preclean
	make win32_release
	make win64_release

linux lin :
	make preclean_linux
	make info
	make lin32_release
	make lin64_release

osx macos :
	make osx_release

#-------------------------------------------------------------------------------
COMMON_SRC_FILES=main.cpp ufr.cpp
#-------------------------------------------------------------------------------
preclean :
	cd win32_release_out && rm -f *.exe && rm -rf src
	cd win64_release_out && rm -f *.exe && rm -rf src

preclean_linux :
	cd linux32_release_out && rm -f *.exe && rm -rf src
	cd linux64_release_out && rm -f *.exe && rm -rf src

clean :
	cd src && rm -f *.o

post_mk : clean
	echo "done."
	echo

#-------------------------------------------------------------------------------
CPPFLAGS=-std=c++11 -I../lib/include -Iinclude -O2 -c -fmessage-length=0
# -Wall

#-------------------------------------------------------------------------------
# Windows
#-------------------------------------------------------------------------------

CFLGWIN=$(CPPFLAGS)

CPPCW32_PATH="/c/dt/mingw32/bin"
CPPCW32=i686-w64-mingw32-g++
CPPCW64_PATH="/c/dt/mingw64/bin"
CPPCW64=x86_64-w64-mingw32-g++
LNKW32=-s -static-libstdc++ -static-libgcc -L../lib/windows/x86
LNKW64=-s -static-libstdc++ -static-libgcc -L../lib/windows/x86_64

win32_release :
	echo "Building 32-bit executable, version:" $(APP_VER)
	make clean
	export PATH=$(CPPCW32_PATH) && cd src && $(CPPCW32) $(CFLGWIN) $(COMMON_SRC_FILES)
	export PATH=$(CPPCW32_PATH) && cd src && $(CPPCW32_PATH)/windres --use-temp-file -iver_inf.rc -oversioninfo.o
	export PATH=$(CPPCW32_PATH) && cd src && $(CPPCW32) $(LNKW32) *.o -o $(BUILD_ARTEFACT) -Wl, -Bdynamic -luFCoder-x86 -Wl,-Bstatic -lpthread -Wl,--enable-stdcall-fixup
	mv src/$(BUILD_ARTEFACT) win32_release_out
	echo "Compiled exe is in the folder 'win32_release_out'"
	make post_mk

win64_release :
	echo "Building 64-bit executable, version:" $(APP_VER)
	make clean
	export PATH=$(CPPCW64_PATH) && cd src && $(CPPCW64) $(CFLGWIN) $(COMMON_SRC_FILES)
	export PATH=$(CPPCW64_PATH) && cd src && $(CPPCW64_PATH)/windres --use-temp-file -iver_inf.rc -oversioninfo.o
	export PATH=$(CPPCW64_PATH) && cd src && $(CPPCW64) $(LNKW64) *.o -o $(BUILD_ARTEFACT) -Wl, -Bdynamic -luFCoder-x86_64 -Wl,-Bstatic -lpthread -Wl,--enable-stdcall-fixup
	mv src/$(BUILD_ARTEFACT) win64_release_out
	echo "Compiled exe is in the folder 'win64_release_out'"
	make post_mk

#-------------------------------------------------------------------------------
# Linux
#-------------------------------------------------------------------------------
CFLGLIN=$(CPPFLAGS)

CPPCL32=g++
CPPCL64=g++
LNKL32=-s -L../lib/linux/x86 -m32
LNKL64=-s -L../lib/linux/x86_64 -m64
LNKRPI=-s -L../lib/linux/armhf

lin32_release :
	echo "Building 32-bit executable, version:" $(APP_VER)
	make clean
	cd src && $(CPPCL32) $(CFLGLIN) -m32 $(COMMON_SRC_FILES) -pthread
	cd src && $(CPPCL32) $(LNKL32) *.o -o $(LINBUILD_ARTEFACT) -Wl,-Bdynamic ../lib/linux/x86/libuFCoder-x86.so -ldl
	mv src/$(LINBUILD_ARTEFACT) linux32_release_out
	echo "Compiled binary is in the folder 'linux32_release_out'"
	make post_mk

lin64_release :
	echo "Building 64-bit executable, version:" $(APP_VER)
	make clean
	cd src && $(CPPCL64) $(CFLGLIN) -m64 $(COMMON_SRC_FILES) -pthread
	cd src && $(CPPCL64) $(LNKL64) *.o -o $(LINBUILD_ARTEFACT) -Wl,-Bdynamic ../lib/linux/x86_64/libuFCoder-x86_64.so -ldl
	mv src/$(LINBUILD_ARTEFACT) linux64_release_out
	echo "Compiled binary is in the folder 'linux64_release_out'"
	make post_mk

rpi:
	echo "Building executable, version:" $(APP_VER)
	make clean
	cd src && $(CPPCL32) $(CFLGLIN) $(COMMON_SRC_FILES) -pthread
	cd src && $(CPPCL32) $(LNKRPI) *.o -o $(LINBUILD_ARTEFACT) -Wl,-Bdynamic ../lib/linux/arm-hf/libuFCoder-armhf.so -ldl
	mv src/$(LINBUILD_ARTEFACT) rpi_release_out
	echo "Compiled binary is in the folder 'rpi_release_out'"
	make post_mk

LNKOSX=-v -static-libstdc++ -L../lib/macos/x86_64

osx_release :
	echo "Building executable, version:" $(APP_VER)
	make clean
	cd src && $(CPPCL64) $(CFLGLIN) -w $(COMMON_SRC_FILES)
	cd src && $(CPPCL64) $(LNKOSX) -w *.o -o $(LINBUILD_ARTEFACT) -Wl ../lib/macos/x86_64/libuFCoder-x86_64.dylib -framework CoreFoundation -framework IOKit
	mv src/$(LINBUILD_ARTEFACT) macos_release
	echo "Compiled binary is in the folder 'macos_release'"
	make post_mk

#osx default compile: -m64 -pthread
#osx default link: -pthread -ldl [-lobjc] [-lc++] -lSystem
