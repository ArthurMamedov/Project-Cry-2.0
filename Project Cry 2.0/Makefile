finish: cleanup
	echo "Build finished. Enjoy your program!"

cleanup: main
	echo "Build finished. Cleaning up..."
	mv a.out cry

main:
	echo "Build started..."
	g++ -Wno-unknown-pragmas AesCore.cpp Counter.cpp Factory.cpp BlowfishCore.cpp GostCore.cpp ICryptor.cpp main.cpp AnubisCore.cpp FileCryptor.cpp cryptors.cpp
