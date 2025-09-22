# Copilot Instructions for crypto C++ Project

## Project Overview
- This is a C++ project for big integer (bignum) arithmetic, organized as a multi-component CMake project.
- Main components:
  - `bignum/`: Core big integer implementation (`bignum.hpp`, `bignum.cpp`).
  - `solver/`: Example usage and entry point (`main.cpp`).
  - `tests/`: Unit tests for bignum functionality.

## Build & Test Workflow
- **Build:**
  - Use CMake: `cmake -S . -B build && cmake --build build`
  - Artifacts: static library in `build/bignum/libbignum.a`, test and solver binaries in `build/tests/` and `build/solver/`.
- **Run tests:**
  - After building, run: `build/tests/bignum_tests`
- **Run example:**
  - After building, run: `build/solver/solver`

## Coding Conventions & Patterns
- All bignum logic is in the `bignum` namespace.
- Public API is defined in `bignum/include/bignum/bignum.hpp`.
- Use C++ standard library types (e.g., `std::string`) for input/output.
- Negative numbers are supported; check sign with `is_negative()`.
- Construction from decimal and hexadecimal strings is supported (e.g., `BigInt("0xFF")`).
- String conversion methods: `to_dec_string()`, `to_hex_string()`.
- Arithmetic operators (`+`, etc.) are overloaded for `BigInt`.

## Project Structure
- `bignum/include/bignum/bignum.hpp`: Main API header.
- `bignum/src/bignum.cpp`: Implementation.
- `solver/main.cpp`: Example usage and manual tests.
- `tests/bignum_tests.cpp`: Unit tests.
- `CMakeLists.txt` files: Project and subproject build configuration.

## Integration & Extension
- To add new arithmetic operations, extend `BigInt` in `bignum.hpp`/`bignum.cpp`.
- To add tests, update `tests/bignum_tests.cpp` and rebuild.
- For new executables, add a subdirectory and update the root `CMakeLists.txt`.

## Example Usage
```cpp
#include "bignum/bignum.hpp"
bignum::BigInt a("1000");
bignum::BigInt b("0xFF");
a + b;
a.is_negative();
a.to_dec_string();
```

## Notes
- No external dependencies beyond standard C++ and CMake.
- All code should be portable and not rely on platform-specific features.

## Python reference math for tests
- For any non-trivial arithmetic or bitwise test in `tests/`, you MUST check the expected result using Python.
- Use the provided file `tests/test.py` for calculations: run `python3 ./tests/test.py`.
- You may add or modify code in `tests/test.py` to automate or verify calculations for C++ test cases.
- Always prefer python3 for reference math over manual calculation or hardcoded values.
