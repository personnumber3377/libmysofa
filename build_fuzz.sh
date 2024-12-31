#export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
#export ASAN_OPTIONS=symbolize=1
cmake -DFUZZ_BUILD=1 -DCMAKE_BUILD_TYPE=Debug -DADDRESS_SANITIZE=ON -DVDEBUG=1 ..
make all

