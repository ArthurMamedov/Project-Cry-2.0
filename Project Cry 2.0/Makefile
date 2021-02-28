finish: cleanup
	echo "Build finished. Enjoy your program!"

cleanup: main
	echo "Build finished. Cleaning up..."
	rm AesCore.hpp.gch AnubisCore.hpp.gch BlowfishCore.hpp.gch Counter.hpp.gch cryptors.hpp.gch Factory.hpp.gch FileCryptor.hpp.gch GostCore.hpp.gch ICore.hpp.gch ICryptor.hpp.gch
	mv a.out cry

main:
	echo "Build started..."
	g++ AesCore.cpp AnubisCore.hpp Counter.cpp Factory.cpp FileCryptor.hpp ICore.hpp cryptors.hpp AesCore.hpp BlowfishCore.cpp Counter.hpp Factory.hpp GostCore.cpp ICryptor.cpp main.cpp AnubisCore.cpp BlowfishCore.hpp FileCryptor.cpp GostCore.hpp ICryptor.hpp cryptors.cpp
