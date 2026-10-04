# libmemwatch - build
#
# Strict by default: the library and the test driver must compile warning-free
# with -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror.  No warning is
# suppressed anywhere in the makefile.
#
#   make            optimised build + test driver
#   make debug      -O0 -g3 build (separate object tree)
#   make test       build and run the whole test suite
#   make stress     build and run the repeated multithreaded stress tests

CXX      ?= g++
STD      := -std=c++17
WARN     := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
            -Wcast-qual -Wdouble-promotion -Wnull-dereference -Wformat=2 \
            -Wundef -Wpointer-arith -Wwrite-strings -Wmissing-declarations \
            -Wredundant-decls -Wstrict-overflow=2 -Wvla -Wswitch -Winit-self \
            -Werror
INC      := -Iinclude
OPT      ?= -O2 -g
CXXFLAGS := $(STD) $(WARN) $(INC) $(OPT) $(EXTRA_CXXFLAGS)
LDFLAGS  := $(EXTRA_LDFLAGS)
LDLIBS   :=

BUILD    ?= build
SRC      := src/util.cpp src/thr.cpp src/remote.cpp src/watch.cpp \
            src/event.cpp src/ctx.cpp
OBJ      := $(SRC:%.cpp=$(BUILD)/%.o)
DEP      := $(OBJ:.o=.d)
LIB      := $(BUILD)/libmemwatch.a
TESTBIN  := $(BUILD)/memwatch_tests

# Manual two-terminal demo (see README.md).
EXAMPLES := $(BUILD)/examples/test_target $(BUILD)/examples/test_memwatch

.PHONY: all debug examples test stress clean

all: $(LIB) $(TESTBIN) $(EXAMPLES)

debug:
	$(MAKE) BUILD=build-debug OPT="-O0 -g3 -fno-omit-frame-pointer" all

$(BUILD):
	mkdir -p $(BUILD)/src $(BUILD)/examples

$(BUILD)/src/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(TESTBIN): tests/harness.cpp tests/t_main.cpp $(LIB) | $(BUILD)
	$(CXX) $(CXXFLAGS) tests/harness.cpp tests/t_main.cpp $(LIB) -o $@ \
	    -lpthread $(LDFLAGS) $(LDLIBS)

$(BUILD)/examples/test_target: examples/test_target.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/examples/test_memwatch: examples/test_memwatch.cpp $(LIB) | $(BUILD)
	$(CXX) $(CXXFLAGS) $< $(LIB) -o $@ $(LDFLAGS) $(LDLIBS)

examples: $(EXAMPLES)

test: all
	$(TESTBIN)

stress: all
	$(TESTBIN) --stress 40

clean:
	rm -rf build build-debug

-include $(DEP)
