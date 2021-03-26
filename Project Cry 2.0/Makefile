finish: cleanup
	echo "Build finished. Enjoy your program!"

cleanup: main
	echo "Build finished. Cleaning up..."
	#rm AesCore.hpp.gch AnubisCore.hpp.gch BlowfishCore.hpp.gch Counter.hpp.gch cryptors.hpp.gch Factory.hpp.gch FileCryptor.hpp.gch GostCore.hpp.gch ICore.hpp.gch ICryptor.hpp.gch
	mv a.out cry

main:
	echo "Build started..."
	g++ -Wno-unknown-pragmas AesCore.cpp Counter.cpp Factory.cpp BlowfishCore.cpp GostCore.cpp ICryptor.cpp main.cpp AnubisCore.cpp FileCryptor.cpp cryptors.cpp
