all: pdfextract

pdfextract: main.cpp unicode.cpp unicode.hpp
	g++ -O2 unicode.cpp main.cpp -o pdfextract -std=c++17 `pkg-config --cflags --libs openssl` `pkg-config --cflags --libs zlib`

.PHONY : clean
clean: 
	@rm -rf pdfextract
