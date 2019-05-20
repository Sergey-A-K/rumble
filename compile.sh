#!/bin/bash
add="-I/usr/include/lua5.1/ -I/usr/include/"
echo "----------------------------------------"
echo "Initializing build process"
printf "%-32s"  "Checking architecture..."
if [ `arch` == "x86_64" ]; then
  add="$add -fPIC"
  echo "ARCH 64 bit"
else
  echo "ARCH 32 bit"
fi

llibs="-lsqlite3 -lgnutls -lgcrypt -lpthread -lcrypto -llua5.1 -lresolv -ldl"

add="$add -DRUMBLE_LUA"
# add="$add -DGNUTLS_LOGLEVEL=9"
# add="$add -DRUMBLE_DBG"
# add="$add -DRADB_DEBUG"



echo "Making build directory..."
mkdir -p build
mkdir -p build/modules
mkdir -p build/db

echo
echo "----------------------------------------"
echo "Compiling rumblectrl"
echo "----------------------------------------"
l=""
for f in src/rumblectrl/*.c
do
    f=${f/.c/}
    f=${f/src\/rumblectrl\//}
    l="$l build/$f.o"
    echo   "Compiling $f.c"
    gcc $add -c -O2 -Wall -MMD -MP -MF build/$f.o.d -o build/$f.o src/rumblectrl/$f.c -lsqlite3
done

gcc -o build/rumblectrl $l -lsqlite3
if [[ $? -ne 0 ]]; then
    echo "An error occured, trying to compile with static linkage instead";
    gcc -static -o build/rumblectrl $l -lsqlite3
    if [[ $? -ne 0 ]]; then
        echo "Meh, that didn't work either - giving up!"
    fi
fi

echo
echo "----------------------------------------"
echo "Compiling individual files"
echo "----------------------------------------"
l=""
for f in src/*.c
do
	f=${f/.c/}
	f=${f/src\//}
	l="$l build/$f.o"
	echo   "Compiling $f.c"
	gcc    $add -c -O2 -Wall -MMD -MP -MF build/$f.o.d -o build/$f.o src/$f.c $llibs
done

echo
echo "----------------------------------------"
echo "Building library and server"
echo "----------------------------------------"
gcc -o build/rumble $l $llibs
if [[ $? -ne 0 ]]; then
	echo "An error occured, trying to compile with static linkage instead";
	gcc -static -o build/rumble $l $llibs
	if [[ $? -ne 0 ]]; then
		echo "Meh, that didn't work either - giving up!"
		exit
	fi
fi

ar -rvc build/librumble.a $l
ranlib build/librumble.a
if [[ $? -ne 0 ]]; then
    echo "Meh, librumble.a not build - giving up!"
fi





echo
echo "----------------------------------------"
echo "Compiling standard modules"
echo "----------------------------------------"

for d in src/modules/*
do
	l=""
	d=${d/src\/modules\//}
	if [ "$d" != "rumblelua" ]; then
		echo "Module $d";
		mkdir -p "build/modules/$d"
		for f in src/modules/$d/*.c
		do
			f=${f/src\/modules\/$d\//}
			f=${f/.c/}
			l="$l build/modules/$d/$f.o"
			gcc  $add -c -O3 -s  -MMD -MP -MF build/modules/$d/$f.o.d -o build/modules/$d/$f.o src/modules/$d/$f.c
		done
		gcc  $add -shared -o build/modules/$d.so -s $l build/librumble.a  $llibs
		rm -rf build/modules/$d
	fi
done

echo
echo "----------------------------------------"
echo "Finalizing the build process"
echo "----------------------------------------"

echo "Creating the final folders and scripts"
cp -r src/modules/rumblelua build/modules/
############# cp -r config build/


echo "Cleaning up..."
rm -r build/*.o*
echo "============ DONE ============"
