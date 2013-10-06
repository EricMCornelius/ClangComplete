flags=`pkg-config --cflags --libs clang`

all:
	g++ -std=c++11 -g -O2 -c -fPIC ${flags} complete.cpp -o complete.o
	g++ -shared -Wl,-soname,libcomplete.so -o libcomplete.so complete.o ${flags} -lclang -lpython3.3m
	clang-format -i -style=file complete.cpp
