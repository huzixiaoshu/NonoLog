all:
	g++ -g -O3 -std=c++11 -pthread NanoLog.cpp test.cpp -o test
