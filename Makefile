all: airodump


airodump: userinterface statistics main 
	g++ main.o statistics.o userinterface.o -o airodump -lpcap -pthread -std=c++11


main: main.cpp
	g++ main.cpp -c -o main.o -lpcap -std=c++11


statistics: statistics.cpp 
	g++ statistics.cpp  -c -o statistics.o -std=c++11


userinterface: userinterface.cpp
	g++ userinterface.cpp -c -o userinterface.o -std=c++11 -pthread


test: test.cpp
	g++ test.cpp -o test -lpcap


clean:
	rm -rf *.o
	rm -rf airodump
	rm -rf test
