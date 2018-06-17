OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128
LDFLAGS += -flto

DEPSRC=depsrc
DEPINST=depinst

LDLIBS += -L $(DEPINST)/lib -Wl,-rpath $(DEPINST)/lib -L . -lsnark -lgmpxx -lgmp
LDLIBS += -lboost_system

all:
	#$(CXX) -o test.o src/test.cpp -c $(CXXFLAGS)
	#$(CXX) -o test test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o cmp_test.o src/cmp_test.cpp -c $(CXXFLAGS)
	$(CXX) -o cmp_test cmp_test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	#$(CXX) -o basic_test.o src/basic_test.cpp -c $(CXXFLAGS)
	#$(CXX) -o basic_test basic_test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) test.o test
	$(RM) cmp_test.o cmp_test
