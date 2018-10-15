#1
./build_ok_centos_in.sh

#2
sodiumPath="libsodium-stable"
if [ ! -d "$sodiumPath" ]
then
    wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
    tar -xzvf LATEST.tar.gz
    cd libsodium-stable
    ./configure --disable-pie
    make
    cp -f ./src/libsodium/.libs/libsodium.a ../../depends/x86_64-unknown-linux-gnu/lib/libsodium.a
    cd ..
else
    cd libsodium-stable
    cp -f ./src/libsodium/.libs/libsodium.a ../../depends/x86_64-unknown-linux-gnu/lib/libsodium.a
    cd ..
fi

#3
gmpPath="gmp-6.1.1"
if [ ! -d "$gmpPath" ]
then
    wget https://gmplib.org/download/gmp/gmp-6.1.1.tar.bz2
    tar -jxvf gmp-6.1.1.tar.bz2
    cd gmp-6.1.1
    ./configure --with-pic
    make
    cp -f ./.libs/libgmp.a ../../depends/x86_64-unknown-linux-gnu/lib/libgmp.a
    cd ..
else
    cd gmp-6.1.1
    cp -f ./.libs/libgmp.a ../../depends/x86_64-unknown-linux-gnu/lib/libgmp.a
    cd ..
fi

#4
cd ../src
make -f Makefile_src_centos