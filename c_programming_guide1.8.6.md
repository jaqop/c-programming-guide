    tetris_run(&game);
    tetris_cleanup(&game);
    
    return 0;
}
```

---

### 28. Advanced Software Security {#advanced-security}

**Figure Reference: [Security Mitigations Stack Diagram]**

Modern C applications require multiple layers of security protection against various attack vectors.

#### Runtime Protection Mechanisms

**Stack Canaries¹:**

```c
/* stack_protection.c - Demonstrating stack protection mechanisms */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Vulnerable function without protection
void vulnerable_function(const char* input) {
    char buffer[64];  // Small buffer
    
    // VULNERABILITY: No bounds checking
    strcpy(buffer, input);  // Stack buffer overflow possible
    
    printf("Buffer content: %s\n", buffer);
}

// Protected function with manual canary
void protected_function_manual(const char* input) {
    const unsigned long canary = 0xDEADBEEF;  // Stack canary
    char buffer[64];
    unsigned long canary_check = canary;
    
    // Safe string copy
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    // Check canary integrity
    if (canary_check != canary) {
        printf("Stack smashing detected! Terminating.\n");
        abort();
    }
    
    printf("Protected buffer content: %s\n", buffer);
}

// Function to demonstrate stack protection
void stack_protection_demo(void) {
    printf("=== Stack Protection Demo ===\n");
    
    // Normal input - should work fine
    const char* normal_input = "Hello, World!";
    printf("Testing with normal input: %s\n", normal_input);
    
    vulnerable_function(normal_input);
    protected_function_manual(normal_input);
    
    // Large input that would cause overflow
    char large_input[200];
    memset(large_input, 'A', sizeof(large_input) - 1);
    large_input[sizeof(large_input) - 1] = '\0';
    
    printf("\nTesting with oversized input (%zu bytes):\n", strlen(large_input));
    
    // This would cause stack overflow in vulnerable function
    // vulnerable_function(large_input);  // DANGEROUS - commented out
    
    // This is protected
    protected_function_manual(large_input);
}

// Compiler stack protection demonstration
__attribute__((noinline))
void function_with_stack_protector(void) {
    char buffer[64];
    
    printf("Function with compiler stack protection\n");
    
    // Compiler automatically inserts stack canary checks here
    // when compiled with -fstack-protector-strong
    
    fgets(buffer, sizeof(buffer), stdin);
    printf("Input received: %s", buffer);
}
```

**Address Space Layout Randomization (ASLR):**

```c
/* aslr_demo.c - Demonstrating ASLR effects */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Global variables (in data/bss segment)
int global_var = 42;
static int static_var;

void aslr_demonstration(void) {
    // Stack variables
    int stack_var = 100;
    char stack_buffer[64];
    
    // Heap allocation
    void* heap_ptr = malloc(64);
    
    // Function addresses
    void* function_addr = (void*)aslr_demonstration;
    void* main_addr = (void*)main;
    
    printf("=== ASLR Memory Layout Demo ===\n");
    printf("Process ID: %d\n", getpid());
    printf("\nMemory addresses:\n");
    
    // Code segment
    printf("Code segment:\n");
    printf("  main() function:           %p\n", main_addr);
    printf("  aslr_demonstration():      %p\n", function_addr);
    
    // Data segment
    printf("Data segment:\n");
    printf("  Global variable:           %p\n", (void*)&global_var);
    printf("  Static variable:           %p\n", (void*)&static_var);
    
    // Stack
    printf("Stack:\n");
    printf("  Stack variable:            %p\n", (void*)&stack_var);
    printf("  Stack buffer:              %p\n", (void*)stack_buffer);
    
    // Heap
    printf("Heap:\n");
    printf("  Malloc'd memory:           %p\n", heap_ptr);
    
    // Libraries
    printf("Libraries:\n");
    printf("  printf() function:         %p\n", (void*)printf);
    printf("  malloc() function:         %p\n", (void*)malloc);
    
    printf("\nRun this program multiple times to see ASLR in action!\n");
    
    free(heap_ptr);
}
```

**Data Execution Prevention (DEP/NX)²:**

```c
/* dep_nx_demo.c - Demonstrating DEP/NX protection */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Shellcode example (x86_64 - just returns)
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,  // xor rax, rax
    0xc3               // ret
};

void dep_nx_demo(void) {
    printf("=== DEP/NX Protection Demo ===\n");
    
    // Attempt 1: Try to execute code on stack (should fail with DEP/NX)
    char stack_buffer[64];
    memcpy(stack_buffer, shellcode, sizeof(shellcode));
    
    printf("Attempting to execute code on stack...\n");
    // This would crash with SIGSEGV on systems with DEP/NX
    // ((void(*)())stack_buffer)();  // DANGEROUS - commented out
    printf("Stack execution blocked by DEP/NX\n");
    
    // Attempt 2: Try to execute code in heap (should fail)
    void* heap_mem = malloc(64);
    memcpy(heap_mem, shellcode, sizeof(shellcode));
    
    printf("Attempting to execute code in heap...\n");
    // This would also crash with SIGSEGV
    // ((void(*)())heap_mem)();  // DANGEROUS - commented out
    printf("Heap execution blocked by DEP/NX\n");
    
    // Correct approach: Use mmap with executable permissions
    void* exec_mem = mmap(NULL, 4096, 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem != MAP_FAILED) {
        memcpy(exec_mem, shellcode, sizeof(shellcode));
        
        printf("Executing code in properly allocated executable memory...\n");
        ((void(*)())exec_mem)();  // This works because we requested PROT_EXEC
        printf("Code executed successfully\n");
        
        munmap(exec_mem, 4096);
    }
    
    free(heap_mem);
}
```

**RELRO (Read-Only Relocations)³:**

```bash
# Compiler flags for RELRO protection
gcc -Wl,-z,relro,-z,now program.c -o program

# Check RELRO status
readelf -l program | grep GNU_RELRO
checksec --file=program
```

```c
/* relro_demo.c - Demonstrating RELRO protection */
#include <stdio.h>
#include <dlfcn.h>

// Function pointer that could be targeted in GOT overwrite attacks
extern void (*vulnerable_function_ptr)(void);

void normal_function(void) {
    printf("Normal function called\n");
}

void malicious_function(void) {
    printf("Malicious function called!\n");
}

void relro_demo(void) {
    printf("=== RELRO Protection Demo ===\n");
    
    // Display function addresses
    printf("Function addresses:\n");
    printf("  normal_function:    %p\n", (void*)normal_function);
    printf("  malicious_function: %p\n", (void*)malicious_function);
    printf("  printf:             %p\n", (void*)printf);
    
    // With RELRO enabled, the GOT (Global Offset Table) is read-only
    // after initialization, preventing runtime modification attacks
    
    printf("RELRO makes GOT read-only, preventing function pointer overwrites\n");
    
    // This would demonstrate a GOT overwrite attack (educational only)
    // In a real attack, an attacker would overwrite function pointers
    // in the GOT to redirect execution to malicious code
}
```

#### Secure Coding Standards (CERT-C)

**CERT-C Rule Examples⁴:**

```c
/* cert_c_examples.c - CERT-C secure coding standard examples */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// ARR38-C: Guarantee that library functions do not form invalid pointers
void cert_arr38_example(void) {
    printf("=== CERT-C ARR38: Valid pointer usage ===\n");
    
    char buffer[10];
    
    // ❌ VIOLATION: Potential buffer overflow
    // strcpy(buffer, "This string is too long");
    
    // ✅ COMPLIANT: Safe string copy
    const char* source = "This string is too long";
    size_t source_len = strlen(source);
    
    if (source_len < sizeof(buffer)) {
        strcpy(buffer, source);
    } else {
        strncpy(buffer, source, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }
    
    printf("Safe string copy: %s\n", buffer);
}

// INT30-C: Ensure that unsigned integer operations do not wrap
void cert_int30_example(void) {
    printf("\n=== CERT-C INT30: Integer overflow prevention ===\n");
    
    unsigned int a = UINT_MAX;
    unsigned int b = 1;
    
    // ❌ VIOLATION: Potential overflow
    // unsigned int result = a + b;  // Wraps to 0
    
    // ✅ COMPLIANT: Check for overflow before operation
    unsigned int result;
    if (a > UINT_MAX - b) {
        printf("Addition would overflow!\n");
        result = UINT_MAX;  // Saturate or handle error
    } else {
        result = a + b;
    }
    
    printf("Safe addition result: %u\n", result);
}

// MEM31-C: Free dynamically allocated memory when no longer needed
void cert_mem31_example(void) {
    printf("\n=== CERT-C MEM31: Memory management ===\n");
    
    // ❌ VIOLATION: Memory leak
    /*
    char* buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Hello");
        printf("Buffer: %s\n", buffer);
        // Missing free(buffer) - MEMORY LEAK
    }
    */
    
    // ✅ COMPLIANT: Proper cleanup
    char* buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Hello");
        printf("Buffer: %s\n", buffer);
        
        free(buffer);
        buffer = NULL;  // Prevent use-after-free
    } else {
        printf("Memory allocation failed\n");
    }
}

// STR31-C: Guarantee that storage for strings has sufficient space
void cert_str31_example(void) {
    printf("\n=== CERT-C STR31: String buffer safety ===\n");
    
    char dest[10];
    const char* src = "This is a very long string";
    
    // ❌ VIOLATION: Buffer overflow risk
    // strcpy(dest, src);
    
    // ✅ COMPLIANT: Safe string operations
    if (strlen(src) >= sizeof(dest)) {
        printf("Source string too long for destination\n");
        // Use dynamic allocation or truncate safely
        strncpy(dest, src, sizeof(dest) - 1);
        dest[sizeof(dest) - 1] = '\0';
    } else {
        strcpy(dest, src);
    }
    
    printf("Safe string result: %s\n", dest);
}

// FIO47-C: Use valid format strings
void cert_fio47_example(void) {
    printf("\n=== CERT-C FIO47: Format string safety ===\n");
    
    char user_input[] = "User data %d %s %x";  // Simulated user input
    
    // ❌ VIOLATION: Format string vulnerability
    // printf(user_input);  // DANGEROUS
    
    // ✅ COMPLIANT: Safe format string usage
    printf("User input: %s\n", user_input);  // Treat as data, not format
    
    // When using user data in format strings, validate first
    const char* safe_format = "Processing: %s";
    printf(safe_format, "user data here");
}
```

#### Hardened Build Pipeline

**Security-Focused Build Configuration:**

```bash
#!/bin/bash
# secure_build.sh - Security-hardened build script

set -euo pipefail

PROJECT_NAME="secure-app"
BUILD_TYPE="${BUILD_TYPE:-Release}"

# Security compilation flags
SECURITY_CFLAGS=(
    "-D_FORTIFY_SOURCE=2"      # Buffer overflow detection
    "-fstack-protector-strong" # Stack canary protection
    "-fPIE"                    # Position Independent Executable
    "-Wformat"                 # Format string warnings
    "-Wformat-security"        # Format security warnings
    "-Werror=format-security"  # Make format warnings errors
    "-Wall"                    # Enable common warnings
    "-Wextra"                  # Extra warnings
    "-Wpedantic"               # Pedantic warnings
    "-Werror"                  # Treat warnings as errors
)

# Security linking flags
SECURITY_LDFLAGS=(
    "-pie"              # Position Independent Executable
    "-Wl,-z,relro"     # Read-only relocations
    "-Wl,-z,now"       # Immediate binding
    "-Wl,-z,noexecstack" # Non-executable stack
)

# Sanitizer flags (for debug builds)
SANITIZER_FLAGS=(
    "-fsanitize=address"           # AddressSanitizer
    "-fsanitize=undefined"         # UndefinedBehaviorSanitizer
    "-fsanitize=leak"              # LeakSanitizer
    "-fno-omit-frame-pointer"      # Keep frame pointers for better backtraces
)

echo "🔒 Building ${PROJECT_NAME} with security hardening"
echo "Build type: ${BUILD_TYPE}"

# Combine flags based on build type
if [ "${BUILD_TYPE}" = "Debug" ]; then
    CFLAGS=("${SECURITY_CFLAGS[@]}" "${SANITIZER_FLAGS[@]}")
    LDFLAGS=("${SECURITY_LDFLAGS[@]}")
else
    CFLAGS=("${SECURITY_CFLAGS[@]}" "-O2" "-DNDEBUG")
    LDFLAGS=("${SECURITY_LDFLAGS[@]}")
fi

# Clean previous build
rm -rf build/
mkdir -p build/

# Configure with CMake
cmake -B build \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_C_FLAGS="${CFLAGS[*]}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS[*]}" \
    -DENABLE_SECURITY_HARDENING=ON

# Build
cmake --build build --parallel "$(nproc)"

# Run security analysis
echo "🔍 Running security analysis..."

# Check binary security features
if command -v checksec >/dev/null 2>&1; then
    echo "Security features analysis:"
    checksec --file=build/${PROJECT_NAME}
fi

# Static analysis with clang-static-analyzer
if command -v scan-build >/dev/null 2>&1; then
    echo "Running static analysis..."
    scan-build -o build/static-analysis cmake --build build --clean-first
fi

echo "✅ Secure build completed"
```

**Fuzzing Integration:**

```c
/* fuzz_target.c - LibFuzzer integration */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function to be fuzzed
int parse_input(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    
    // Simulate parsing with potential vulnerabilities
    char buffer[256];
    
    if (size > sizeof(buffer)) {
        // Safe handling of large inputs
        size = sizeof(buffer);
    }
    
    memcpy(buffer, data, size);
    
    // Simulate processing
    for (size_t i = 0; i < size; i++) {
        if (buffer[i] == 0xFF) {
            // Potential crash condition
            return -1;
        }
    }
    
    return 0;
}

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_input(data, size);
    return 0;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// Additional fuzzing setup if needed
__attribute__((constructor))
void setup_fuzzing(void) {
    // Initialize any global state for fuzzing
}
#endif
```

**CI/CD Security Pipeline (.github/workflows/security.yml):**

```yaml
name: Security Analysis Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-build:
    name: Security Hardened Build
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Install security tools
      run: |
        sudo apt-get update
        sudo apt-get install -y \
          clang \
          clang-tools \
          valgrind \
          cppcheck \
          checksec
    
    - name: Security hardened build
      run: |
        export BUILD_TYPE=Release
        ./scripts/secure_build.sh
    
    - name: Run security tests
      run: |
        # Test with AddressSanitizer
        export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"
        ./build/secure-app --self-test
        
        # Run with Valgrind
        valgrind --tool=memcheck --leak-check=full ./build/secure-app --self-test

  static-analysis:
    name: Static Security Analysis
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Run Clang Static Analyzer
      run: |
        scan-build -o static-analysis-results \
          --status-bugs \
          -enable-checker security.insecureAPI.strcpy \
          -enable-checker security.insecureAPI.UncheckedReturn \
          cmake --build build
    
    - name: Run cppcheck security checks
      run: |
        cppcheck --enable=all \
          --addon=cert \
          --addon=misra \
          --error-exitcode=1 \
          --xml \
          src/ 2> cppcheck-security.xml
    
    - name: Upload static analysis results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: static-analysis-results
        path: static-analysis-results/

  fuzzing:
    name: Fuzzing Tests
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Build fuzzing targets
      run: |
        clang -fsanitize=fuzzer,address \
          -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
          src/fuzz_target.c -o fuzz_target
    
    - name: Run short fuzzing session
      run: |
        # Run fuzzing for 60 seconds
        timeout 60 ./fuzz_target -max_total_time=60 || true
        
        # Check if any crashes were found
        if [ -d "crash-*" ]; then
          echo "Fuzzing found crashes!"
          ls -la crash-*
          exit 1
        fi

  dependency-scan:
    name: Dependency Security Scan
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Run vulnerability scan
      uses: securecodewarrior/github-action-vulnerable-dependencies@v1
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
```

**Footnote 1**: *Stack canaries are random values placed between local variables and return addresses. If a buffer overflow occurs, the canary is overwritten, and the program can detect this and abort before malicious code executes.*

**Footnote 2**: *DEP (Data Execution Prevention) and NX (No-Execute) mark memory pages as either writable or executable, but not both. This prevents code injection attacks where malicious code is written to the stack or heap and executed.*

**Footnote 3**: *RELRO (Read-Only Relocations) makes the Global Offset Table (GOT) read-only after program initialization, preventing attackers from overwriting function pointers to redirect execution.*

**Footnote 4**: *The CERT-C Secure Coding Standard provides rules and recommendations for secure C programming. Following these guidelines significantly reduces the risk of security vulnerabilities. Full standard available at wiki.sei.cmu.edu/confluence/display/c/*

#### Concepts ⚙
- Multiple layers of runtime security protection
- Compiler and linker flags for hardened builds
- Static analysis integration in development workflow
- Fuzzing for discovering security vulnerabilities

#### Errors ⚠
- Relying on a single security mechanism
- Disabling security features for performance without proper analysis
- Not testing security mitigations in CI/CD pipelines
- Ignoring static analysis warnings in security-critical code

#### Tips 🧠
- Enable all available security features by default
- Use multiple sanitizers during development and testing
- Implement defense-in-depth strategies
- Regular security audits and penetration testing

#### Tools 🔧
- **Compiler Security**: GCC/Clang with security flags
- **Static Analysis**: Clang Static Analyzer, PVS-Studio, Coverity
- **Dynamic Analysis**: AddressSanitizer, Valgrind, Dr. Memory
- **Fuzzing**: libFuzzer, AFL++, Honggfuzz, Google OSS-Fuzz

---

## Conclusion

This comprehensive guide has taken you through the complete journey of C programming, from basic syntax to professional-grade software development. The language's power lies in its simplicity, performance, and direct hardware access, making it indispensable for systems programming, embedded development, and performance-critical applications.

**Key Takeaways:**

1. **Master the Fundamentals**: Solid understanding of pointers, memory management, and data structures forms the foundation of expert C programming.

2. **Embrace Modern Practices**: Use contemporary tools, secure coding standards, and automated testing to build reliable software.

3. **Security First**: Implement multiple layers of security protection and follow established secure coding guidelines like CERT-C.

4. **Performance Matters**: Profile your code, understand cache behavior, and optimize where it counts most.

5. **Team Collaboration**: Use version control, CI/CD, and code quality tools to work effectively in professional environments.

**The Future of C Programming:**

Despite being over 50 years old, C remains highly relevant in 2024 and beyond. Modern C standards (C11, C17, C23) continue to evolve while maintaining backward compatibility. The language's role in:

- **Systems Programming**: Operating systems, device drivers, embedded systems
- **Performance Computing**: High-frequency trading, scientific computing, game engines
- **Infrastructure**: Databases, network protocols, compilers, interpreters
- **Security**: Cryptographic libraries, secure communication protocols

This ensures C will continue to be a cornerstone of software development for decades to come.

**Next Steps:**

1. **Practice**: Build the capstone projects and extend them with additional features
2. **Contribute**: Join open-source C projects to gain real-world experience
3. **Specialize**: Focus on domains that interest you (embedded, systems, games, security)
4. **Stay Updated**: Follow C standardization efforts and modern tooling developments
5. **Teach Others**: Share your knowledge through code reviews, mentoring, or technical writing

Remember that mastery comes through practice, experimentation, and continuous learning. The concepts and techniques in this guide provide a solid foundation, but true expertise develops through applying this knowledge to solve real-world problems.

Whether you're building the next great game engine, developing embedded software for IoT devices, or creating high-performance system software, C gives you the tools and control to build exactly what you envision. Use this power responsibly, write secure and maintainable code, and contribute to the rich ecosystem of C software that powers our digital world.

---

**Happy coding, and welcome to the community of C programmers! 🚀**

---

*This guide represents the collective wisdom of the C programming community, drawing from decades of experience in professional software development. Continue learning, keep experimenting, and most importantly, enjoy the journey of mastering one of computing's most fundamental and powerful programming languages.*    // Load plugins
    plugin_manager_load_plugins(g_plugin_manager, config->plugin_directory);
    
    session->config = *config;
    session->start_time = time(NULL);
    session->status = ANALYSIS_STATUS_RUNNING;
    
    return session;
}

int analyzer_scan_files(AnalysisSession* session, const char* root_path) {
    FileList file_list = {0};
    file_list.capacity = 1000;
    file_list.files = malloc(file_list.capacity * sizeof(FileEntry));
    
    LOG_INFO("Starting file scan from: %s", root_path);
    scan_directory_recursive(root_path, &file_list);
    LOG_INFO("Found %zu files to analyze", file_list.count);
    
    // Submit analysis tasks to thread pool
    session->results = calloc(file_list.count, sizeof(AnalysisResult));
    session->result_count = file_list.count;
    
    for (size_t i = 0; i < file_list.count; i++) {
        AnalysisTask* task = malloc(sizeof(AnalysisTask));
        strncpy(task->filepath, file_list.files[i].path, sizeof(task->filepath) - 1);
        task->result = &session->results[i];
        
        thread_pool_submit(g_thread_pool, analysis_task_worker, task);
    }
    
    // Wait for all tasks to complete
    thread_pool_wait(g_thread_pool);
    
    session->status = ANALYSIS_STATUS_COMPLETED;
    session->end_time = time(NULL);
    
    free(file_list.files);
    return 0;
}
```

**Build Configuration (CMakePresets.json):**

```json
{
    "version": 3,
    "cmakeMinimumRequired": {
        "major": 3,
        "minor": 20,
        "patch": 0
    },
    "configurePresets": [
        {
            "name": "default-debug",
            "displayName": "Debug Build",
            "description": "Debug build with sanitizers",
            "binaryDir": "build/debug",
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "Debug",
                "CMAKE_C_COMPILER": "clang",
                "CMAKE_C_FLAGS": "-fsanitize=address,undefined -fno-omit-frame-pointer",
                "ENABLE_TESTING": "ON",
                "ENABLE_COVERAGE": "ON"
            }
        },
        {
            "name": "default-release",
            "displayName": "Release Build", 
            "description": "Optimized release build",
            "binaryDir": "build/release",
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "Release",
                "CMAKE_C_COMPILER": "clang",
                "CMAKE_C_FLAGS": "-O3 -DNDEBUG",
                "ENABLE_TESTING": "OFF"
            }
        },
        {
            "name": "security-hardened",
            "displayName": "Security Hardened Build",
            "description": "Maximum security hardening",
            "binaryDir": "build/hardened", 
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "Release",
                "CMAKE_C_FLAGS": "-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE",
                "CMAKE_EXE_LINKER_FLAGS": "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
            }
        }
    ],
    "buildPresets": [
        {
            "name": "debug-build",
            "configurePreset": "default-debug"
        },
        {
            "name": "release-build", 
            "configurePreset": "default-release"
        }
    ],
    "testPresets": [
        {
            "name": "default-tests",
            "configurePreset": "default-debug",
            "output": {"outputOnFailure": true}
        }
    ]
}
```

### Game Capstone: Tetris Implementation

**Complete Tetris Game with ECS:**

```c
/* tetris.c - Complete Tetris implementation with ECS */
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <SDL2/SDL_mixer.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600
#define BOARD_WIDTH 10
#define BOARD_HEIGHT 20
#define BLOCK_SIZE 30

// Tetris pieces (tetrominoes)
typedef enum {
    PIECE_I, PIECE_O, PIECE_T, PIECE_S, PIECE_Z, PIECE_J, PIECE_L, PIECE_COUNT
} PieceType;

typedef struct {
    int blocks[4][4];  // 4x4 grid for piece shape
    int width, height;
    SDL_Color color;
} PieceShape;

// ECS Components
typedef struct {
    float x, y;
} Position;

typedef struct {
    float vx, vy;
} Velocity;

typedef struct {
    PieceType type;
    int rotation;
    PieceShape* shape;
} TetrisPiece;

typedef struct {
    int grid[BOARD_HEIGHT][BOARD_WIDTH];
    int completed_lines[4];
    int completed_count;
} GameBoard;

typedef struct {
    int score;
    int level;
    int lines_cleared;
    double fall_timer;
    double fall_speed;
    bool game_over;
    bool paused;
} GameState;

// Global game data
static PieceShape piece_shapes[PIECE_COUNT] = {
    // I-piece
    {{
        {0,1,0,0},
        {0,1,0,0}, 
        {0,1,0,0},
        {0,1,0,0}
    }, 4, 4, {0, 255, 255, 255}},
    
    // O-piece  
    {{
        {1,1,0,0},
        {1,1,0,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 2, 2, {255, 255, 0, 255}},
    
    // T-piece
    {{
        {0,1,0,0},
        {1,1,1,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 3, 2, {128, 0, 128, 255}},
    
    // S-piece
    {{
        {0,1,1,0},
        {1,1,0,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 3, 2, {0, 255, 0, 255}},
    
    // Z-piece
    {{
        {1,1,0,0},
        {0,1,1,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 3, 2, {255, 0, 0, 255}},
    
    // J-piece
    {{
        {1,0,0,0},
        {1,1,1,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 3, 2, {0, 0, 255, 255}},
    
    // L-piece
    {{
        {0,0,1,0},
        {1,1,1,0},
        {0,0,0,0},
        {0,0,0,0}
    }, 3, 2, {255, 165, 0, 255}}
};

typedef struct {
    SDL_Window* window;
    SDL_Renderer* renderer;
    TTF_Font* font;
    
    // Game components
    GameBoard board;
    GameState game_state;
    TetrisPiece current_piece;
    TetrisPiece next_piece;
    Position current_pos;
    
    // Audio
    Mix_Chunk* line_clear_sound;
    Mix_Chunk* piece_lock_sound;
    Mix_Music* background_music;
    
    bool running;
    double last_time;
} TetrisGame;

// Initialize Tetris piece
void tetris_piece_init(TetrisPiece* piece, PieceType type) {
    piece->type = type;
    piece->rotation = 0;
    piece->shape = &piece_shapes[type];
}

// Rotate piece (clockwise)
void rotate_piece(int src[4][4], int dst[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            dst[j][3-i] = src[i][j];
        }
    }
}

// Check collision
bool check_collision(const GameBoard* board, const TetrisPiece* piece, 
                    int x, int y, int rotation) {
    int rotated_blocks[4][4];
    
    // Apply rotation
    memcpy(rotated_blocks, piece->shape->blocks, sizeof(rotated_blocks));
    for (int r = 0; r < rotation; r++) {
        int temp[4][4];
        rotate_piece(rotated_blocks, temp);
        memcpy(rotated_blocks, temp, sizeof(temp));
    }
    
    // Check bounds and collisions
    for (int py = 0; py < 4; py++) {
        for (int px = 0; px < 4; px++) {
            if (rotated_blocks[py][px]) {
                int board_x = x + px;
                int board_y = y + py;
                
                // Check bounds
                if (board_x < 0 || board_x >= BOARD_WIDTH ||
                    board_y < 0 || board_y >= BOARD_HEIGHT) {
                    return true;
                }
                
                // Check board collision
                if (board->grid[board_y][board_x]) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

// Lock piece to board
void lock_piece_to_board(GameBoard* board, const TetrisPiece* piece,
                        int x, int y, int rotation) {
    int rotated_blocks[4][4];
    
    // Apply rotation
    memcpy(rotated_blocks, piece->shape->blocks, sizeof(rotated_blocks));
    for (int r = 0; r < rotation; r++) {
        int temp[4][4];
        rotate_piece(rotated_blocks, temp);
        memcpy(rotated_blocks, temp, sizeof(temp));
    }
    
    // Place piece on board
    for (int py = 0; py < 4; py++) {
        for (int px = 0; px < 4; px++) {
            if (rotated_blocks[py][px]) {
                int board_x = x + px;
                int board_y = y + py;
                
                if (board_x >= 0 && board_x < BOARD_WIDTH &&
                    board_y >= 0 && board_y < BOARD_HEIGHT) {
                    board->grid[board_y][board_x] = piece->type + 1;
                }
            }
        }
    }
}

// Check and clear completed lines
int check_completed_lines(GameBoard* board) {
    board->completed_count = 0;
    
    for (int y = 0; y < BOARD_HEIGHT; y++) {
        bool line_complete = true;
        for (int x = 0; x < BOARD_WIDTH; x++) {
            if (board->grid[y][x] == 0) {
                line_complete = false;
                break;
            }
        }
        
        if (line_complete) {
            board->completed_lines[board->completed_count++] = y;
        }
    }
    
    // Remove completed lines
    for (int i = 0; i < board->completed_count; i++) {
        int line_y = board->completed_lines[i];
        
        // Move lines down
        for (int y = line_y; y > 0; y--) {
            for (int x = 0; x < BOARD_WIDTH; x++) {
                board->grid[y][x] = board->grid[y-1][x];
            }
        }
        
        // Clear top line
        for (int x = 0; x < BOARD_WIDTH; x++) {
            board->grid[0][x] = 0;
        }
        
        // Adjust remaining line indices
        for (int j = i + 1; j < board->completed_count; j++) {
            if (board->completed_lines[j] < line_y) {
                board->completed_lines[j]++;
            }
        }
    }
    
    return board->completed_count;
}

// Spawn new piece
void spawn_new_piece(TetrisGame* game) {
    game->current_piece = game->next_piece;
    tetris_piece_init(&game->next_piece, rand() % PIECE_COUNT);
    
    game->current_pos.x = BOARD_WIDTH / 2 - 2;
    game->current_pos.y = 0;
    
    // Check game over
    if (check_collision(&game->board, &game->current_piece,
                       (int)game->current_pos.x, (int)game->current_pos.y, 0)) {
        game->game_state.game_over = true;
    }
}

// Initialize game
bool tetris_init(TetrisGame* game) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
        printf("SDL init failed: %s\n", SDL_GetError());
        return false;
    }
    
    game->window = SDL_CreateWindow("Tetris",
                                   SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                   WINDOW_WIDTH, WINDOW_HEIGHT, 0);
    if (!game->window) {
        printf("Window creation failed: %s\n", SDL_GetError());
        return false;
    }
    
    game->renderer = SDL_CreateRenderer(game->window, -1,
                                       SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!game->renderer) {
        printf("Renderer creation failed: %s\n", SDL_GetError());
        return false;
    }
    
    // Initialize TTF
    if (TTF_Init() == -1) {
        printf("TTF init failed: %s\n", TTF_GetError());
        return false;
    }
    
    game->font = TTF_OpenFont("assets/fonts/arial.ttf", 24);
    if (!game->font) {
        printf("Font load failed: %s\n", TTF_GetError());
        return false;
    }
    
    // Initialize audio
    if (Mix_OpenAudio(22050, MIX_DEFAULT_FORMAT, 2, 4096) < 0) {
        printf("Audio init failed: %s\n", Mix_GetError());
        return false;
    }
    
    // Load sounds
    game->line_clear_sound = Mix_LoadWAV("assets/audio/line_clear.wav");
    game->piece_lock_sound = Mix_LoadWAV("assets/audio/piece_lock.wav");
    game->background_music = Mix_LoadMUS("assets/audio/tetris_theme.ogg");
    
    // Initialize game state
    memset(&game->board, 0, sizeof(GameBoard));
    game->game_state.score = 0;
    game->game_state.level = 1;
    game->game_state.lines_cleared = 0;
    game->game_state.fall_speed = 1.0;  // 1 second per fall
    game->game_state.fall_timer = 0.0;
    game->game_state.game_over = false;
    game->game_state.paused = false;
    
    // Spawn initial pieces
    srand((unsigned int)time(NULL));
    tetris_piece_init(&game->next_piece, rand() % PIECE_COUNT);
    spawn_new_piece(game);
    
    game->running = true;
    game->last_time = SDL_GetTicks() / 1000.0;
    
    // Start background music
    if (game->background_music) {
        Mix_PlayMusic(game->background_music, -1);  // Loop indefinitely
    }
    
    return true;
}

// Handle input
void tetris_handle_input(TetrisGame* game) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_QUIT:
                game->running = false;
                break;
                
            case SDL_KEYDOWN:
                if (game->game_state.game_over) {
                    if (event.key.keysym.sym == SDLK_r) {
                        // Restart game
                        tetris_init(game);
                    }
                    break;
                }
                
                if (game->game_state.paused && event.key.keysym.sym != SDLK_p) {
                    break;
                }
                
                switch (event.key.keysym.sym) {
                    case SDLK_LEFT:
                        if (!check_collision(&game->board, &game->current_piece,
                                           (int)game->current_pos.x - 1, 
                                           (int)game->current_pos.y,
                                           game->current_piece.rotation)) {
                            game->current_pos.x--;
                        }
                        break;
                        
                    case SDLK_RIGHT:
                        if (!check_collision(&game->board, &game->current_piece,
                                           (int)game->current_pos.x + 1,
                                           (int)game->current_pos.y,
                                           game->current_piece.rotation)) {
                            game->current_pos.x++;
                        }
                        break;
                        
                    case SDLK_DOWN:
                        if (!check_collision(&game->board, &game->current_piece,
                                           (int)game->current_pos.x,
                                           (int)game->current_pos.y + 1,
                                           game->current_piece.rotation)) {
                            game->current_pos.y++;
                        }
                        break;
                        
                    case SDLK_UP:
                        // Rotate piece
                        {
                            int new_rotation = (game->current_piece.rotation + 1) % 4;
                            if (!check_collision(&game->board, &game->current_piece,
                                               (int)game->current_pos.x,
                                               (int)game->current_pos.y,
                                               new_rotation)) {
                                game->current_piece.rotation = new_rotation;
                            }
                        }
                        break;
                        
                    case SDLK_SPACE:
                        // Hard drop
                        while (!check_collision(&game->board, &game->current_piece,
                                              (int)game->current_pos.x,
                                              (int)game->current_pos.y + 1,
                                              game->current_piece.rotation)) {
                            game->current_pos.y++;
                        }
                        break;
                        
                    case SDLK_p:
                        game->game_state.paused = !game->game_state.paused;
                        break;
                        
                    case SDLK_ESCAPE:
                        game->running = false;
                        break;
                }
                break;
        }
    }
}

// Update game logic
void tetris_update(TetrisGame* game, double delta_time) {
    if (game->game_state.game_over || game->game_state.paused) {
        return;
    }
    
    // Update fall timer
    game->game_state.fall_timer += delta_time;
    
    if (game->game_state.fall_timer >= game->game_state.fall_speed) {
        game->game_state.fall_timer = 0.0;
        
        // Try to move piece down
        if (!check_collision(&game->board, &game->current_piece,
                           (int)game->current_pos.x,
                           (int)game->current_pos.y + 1,
                           game->current_piece.rotation)) {
            game->current_pos.y++;
        } else {
            // Lock piece and spawn new one
            lock_piece_to_board(&game->board, &game->current_piece,
                              (int)game->current_pos.x, (int)game->current_pos.y,
                              game->current_piece.rotation);
            
            if (game->piece_lock_sound) {
                Mix_PlayChannel(-1, game->piece_lock_sound, 0);
            }
            
            // Check for completed lines
            int cleared_lines = check_completed_lines(&game->board);
            if (cleared_lines > 0) {
                game->game_state.lines_cleared += cleared_lines;
                
                // Calculate score
                int line_scores[] = {0, 100, 300, 500, 800};  // Single, double, triple, tetris
                game->game_state.score += line_scores[cleared_lines] * game->game_state.level;
                
                // Increase level every 10 lines
                game->game_state.level = game->game_state.lines_cleared / 10 + 1;
                game->game_state.fall_speed = fmax(0.1, 1.0 - (game->game_state.level - 1) * 0.1);
                
                if (game->line_clear_sound) {
                    Mix_PlayChannel(-1, game->line_clear_sound, 0);
                }
            }
            
            spawn_new_piece(game);
        }
    }
}

// Render game
void tetris_render(TetrisGame* game) {
    // Clear screen
    SDL_SetRenderDrawColor(game->renderer, 0, 0, 0, 255);
    SDL_RenderClear(game->renderer);
    
    int board_offset_x = 50;
    int board_offset_y = 50;
    
    // Draw board background
    SDL_SetRenderDrawColor(game->renderer, 64, 64, 64, 255);
    SDL_Rect board_bg = {
        board_offset_x - 2, board_offset_y - 2,
        BOARD_WIDTH * BLOCK_SIZE + 4, BOARD_HEIGHT * BLOCK_SIZE + 4
    };
    SDL_RenderFillRect(game->renderer, &board_bg);
    
    // Draw board
    for (int y = 0; y < BOARD_HEIGHT; y++) {
        for (int x = 0; x < BOARD_WIDTH; x++) {
            if (game->board.grid[y][x] > 0) {
                PieceShape* shape = &piece_shapes[game->board.grid[y][x] - 1];
                SDL_SetRenderDrawColor(game->renderer, 
                                     shape->color.r, shape->color.g, shape->color.b, 255);
                
                SDL_Rect block = {
                    board_offset_x + x * BLOCK_SIZE,
                    board_offset_y + y * BLOCK_SIZE,
                    BLOCK_SIZE, BLOCK_SIZE
                };
                SDL_RenderFillRect(game->renderer, &block);
                
                // Draw border
                SDL_SetRenderDrawColor(game->renderer, 255, 255, 255, 255);
                SDL_RenderDrawRect(game->renderer, &block);
            }
        }
    }
    
    // Draw current piece
    if (!game->game_state.game_over) {
        int rotated_blocks[4][4];
        memcpy(rotated_blocks, game->current_piece.shape->blocks, sizeof(rotated_blocks));
        
        for (int r = 0; r < game->current_piece.rotation; r++) {
            int temp[4][4];
            rotate_piece(rotated_blocks, temp);
            memcpy(rotated_blocks, temp, sizeof(temp));
        }
        
        SDL_SetRenderDrawColor(game->renderer,
                             game->current_piece.shape->color.r,
                             game->current_piece.shape->color.g,
                             game->current_piece.shape->color.b, 255);
        
        for (int py = 0; py < 4; py++) {
            for (int px = 0; px < 4; px++) {
                if (rotated_blocks[py][px]) {
                    SDL_Rect block = {
                        board_offset_x + ((int)game->current_pos.x + px) * BLOCK_SIZE,
                        board_offset_y + ((int)game->current_pos.y + py) * BLOCK_SIZE,
                        BLOCK_SIZE, BLOCK_SIZE
                    };
                    SDL_RenderFillRect(game->renderer, &block);
                    
                    SDL_SetRenderDrawColor(game->renderer, 255, 255, 255, 255);
                    SDL_RenderDrawRect(game->renderer, &block);
                    SDL_SetRenderDrawColor(game->renderer,
                                         game->current_piece.shape->color.r,
                                         game->current_piece.shape->color.g,
                                         game->current_piece.shape->color.b, 255);
                }
            }
        }
    }
    
    // Draw UI
    char score_text[64];
    snprintf(score_text, sizeof(score_text), "Score: %d", game->game_state.score);
    
    SDL_Surface* text_surface = TTF_RenderText_Solid(game->font, score_text, 
                                                    (SDL_Color){255, 255, 255, 255});
    if (text_surface) {
        SDL_Texture* text_texture = SDL_CreateTextureFromSurface(game->renderer, text_surface);
        SDL_Rect text_rect = {400, 100, text_surface->w, text_surface->h};
        SDL_RenderCopy(game->renderer, text_texture, NULL, &text_rect);
        SDL_DestroyTexture(text_texture);
        SDL_FreeSurface(text_surface);
    }
    
    // Draw level
    char level_text[64];
    snprintf(level_text, sizeof(level_text), "Level: %d", game->game_state.level);
    
    text_surface = TTF_RenderText_Solid(game->font, level_text, 
                                       (SDL_Color){255, 255, 255, 255});
    if (text_surface) {
        SDL_Texture* text_texture = SDL_CreateTextureFromSurface(game->renderer, text_surface);
        SDL_Rect text_rect = {400, 140, text_surface->w, text_surface->h};
        SDL_RenderCopy(game->renderer, text_texture, NULL, &text_rect);
        SDL_DestroyTexture(text_texture);
        SDL_FreeSurface(text_surface);
    }
    
    // Game over screen
    if (game->game_state.game_over) {
        SDL_SetRenderDrawColor(game->renderer, 0, 0, 0, 128);
        SDL_Rect overlay = {0, 0, WINDOW_WIDTH, WINDOW_HEIGHT};
        SDL_RenderFillRect(game->renderer, &overlay);
        
        text_surface = TTF_RenderText_Solid(game->font, "GAME OVER", 
                                           (SDL_Color){255, 0, 0, 255});
        if (text_surface) {
            SDL_Texture* text_texture = SDL_CreateTextureFromSurface(game->renderer, text_surface);
            SDL_Rect text_rect = {WINDOW_WIDTH/2 - text_surface->w/2, 
                                 WINDOW_HEIGHT/2 - 50, text_surface->w, text_surface->h};
            SDL_RenderCopy(game->renderer, text_texture, NULL, &text_rect);
            SDL_DestroyTexture(text_texture);
            SDL_FreeSurface(text_surface);
        }
        
        text_surface = TTF_RenderText_Solid(game->font, "Press R to restart", 
                                           (SDL_Color){255, 255, 255, 255});
        if (text_surface) {
            SDL_Texture* text_texture = SDL_CreateTextureFromSurface(game->renderer, text_surface);
            SDL_Rect text_rect = {WINDOW_WIDTH/2 - text_surface->w/2, 
                                 WINDOW_HEIGHT/2, text_surface->w, text_surface->h};
            SDL_RenderCopy(game->renderer, text_texture, NULL, &text_rect);
            SDL_DestroyTexture(text_texture);
            SDL_FreeSurface(text_surface);
        }
    }
    
    SDL_RenderPresent(game->renderer);
}

// Main game loop
void tetris_run(TetrisGame* game) {
    while (game->running) {
        double current_time = SDL_GetTicks() / 1000.0;
        double delta_time = current_time - game->last_time;
        game->last_time = current_time;
        
        // Cap delta time
        if (delta_time > 0.05) delta_time = 0.05;
        
        tetris_handle_input(game);
        tetris_update(game, delta_time);
        tetris_render(game);
    }
}

// Cleanup
void tetris_cleanup(TetrisGame* game) {
    if (game->background_music) Mix_FreeMusic(game->background_music);
    if (game->line_clear_sound) Mix_FreeChunk(game->line_clear_sound);
    if (game->piece_lock_sound) Mix_FreeChunk(game->piece_lock_sound);
    
    Mix_CloseAudio();
    
    if (game->font) TTF_CloseFont(game->font);
    TTF_Quit();
    
    if (game->renderer) SDL_DestroyRenderer(game->renderer);
    if (game->window) SDL_DestroyWindow(game->window);
    
    SDL_Quit();
}

int main(int argc, char* argv[]) {
    TetrisGame game = {0};
    
    if (!tetris_init(&game)) {
        return 1;
    }
    
    printf("Tetris Game Controls:\n");
    printf("Arrow Keys: Move/Rotate piece\n");
    printf("Space: Hard drop\n");
    printf("P: Pause/Resume\n");
    printf("R: Restart (when game over)\n");
    printf("Escape: Exit\n");
    
    tetris_run(&game);
    tetris_cleanup(&game);
        assert(entity != NULL_ENTITY && entity < MAX_ENTITIES);
    assert(type < ecs_world.component_count);
    
    ComponentPool* pool = &ecs_world.component_pools[type];
    
    // Add entity to component pool
    sparse_set_add(&pool->entities, entity);
    
    // Update entity mask
    ecs_world.entity_masks[entity] |= (1u << type);
    
    // Return pointer to component data
    uint32_t dense_index = pool->entities.sparse[entity];
    return (char*)pool->data + (dense_index * pool->element_size);
}

// Get component from entity
void* ecs_get_component(Entity entity, ComponentType type) {
    assert(entity != NULL_ENTITY && entity < MAX_ENTITIES);
    assert(type < ecs_world.component_count);
    
    ComponentPool* pool = &ecs_world.component_pools[type];
    
    if (!sparse_set_contains(&pool->entities, entity)) {
        return NULL;
    }
    
    uint32_t dense_index = pool->entities.sparse[entity];
    return (char*)pool->data + (dense_index * pool->element_size);
}

// Example components
typedef struct {
    float x, y;
} PositionComponent;

typedef struct {
    float vx, vy;
} VelocityComponent;

typedef struct {
    SDL_Texture* texture;
    SDL_Rect src_rect;
    float width, height;
} SpriteComponent;

// Component type IDs (registered at startup)
static ComponentType POSITION_COMPONENT;
static ComponentType VELOCITY_COMPONENT;
static ComponentType SPRITE_COMPONENT;

// Initialize ECS system
void ecs_init(void) {
    POSITION_COMPONENT = ecs_register_component(sizeof(PositionComponent));
    VELOCITY_COMPONENT = ecs_register_component(sizeof(VelocityComponent));
    SPRITE_COMPONENT = ecs_register_component(sizeof(SpriteComponent));
}

// System functions
void movement_system(float delta_time) {
    ComponentPool* pos_pool = &ecs_world.component_pools[POSITION_COMPONENT];
    ComponentPool* vel_pool = &ecs_world.component_pools[VELOCITY_COMPONENT];
    
    // Iterate over entities with both position and velocity components
    for (uint32_t i = 0; i < pos_pool->entities.count; i++) {
        Entity entity = pos_pool->entities.dense[i];
        
        if (!(ecs_world.entity_masks[entity] & (1u << VELOCITY_COMPONENT))) {
            continue;  // Entity doesn't have velocity component
        }
        
        PositionComponent* pos = ecs_get_component(entity, POSITION_COMPONENT);
        VelocityComponent* vel = ecs_get_component(entity, VELOCITY_COMPONENT);
        
        pos->x += vel->vx * delta_time;
        pos->y += vel->vy * delta_time;
    }
}

void render_system(Renderer* renderer) {
    ComponentPool* pos_pool = &ecs_world.component_pools[POSITION_COMPONENT];
    
    for (uint32_t i = 0; i < pos_pool->entities.count; i++) {
        Entity entity = pos_pool->entities.dense[i];
        
        if (!(ecs_world.entity_masks[entity] & (1u << SPRITE_COMPONENT))) {
            continue;  // Entity doesn't have sprite component
        }
        
        PositionComponent* pos = ecs_get_component(entity, POSITION_COMPONENT);
        SpriteComponent* sprite = ecs_get_component(entity, SPRITE_COMPONENT);
        
        SDL_FRect dst_rect = {pos->x, pos->y, sprite->width, sprite->height};
        renderer_draw_sprite(sprite->texture, sprite->src_rect, dst_rect, 0.0f,
                           (SDL_Color){255, 255, 255, 255});
    }
}
```

#### Complete Pong Game Example

```c
/* pong.c - Complete Pong game implementation */
#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600
#define PADDLE_WIDTH 20
#define PADDLE_HEIGHT 100
#define BALL_SIZE 20
#define PADDLE_SPEED 300.0f
#define BALL_SPEED 400.0f

typedef struct {
    float x, y;
    float width, height;
} Rect;

typedef struct {
    float x, y;
    float vx, vy;
} Ball;

typedef struct {
    SDL_Window* window;
    SDL_Renderer* renderer;
    bool running;
    
    // Game objects
    Rect player_paddle;
    Rect ai_paddle;
    Ball ball;
    
    // Game state
    int player_score;
    int ai_score;
    bool game_paused;
    
    // Audio
    Mix_Chunk* paddle_sound;
    Mix_Chunk* score_sound;
    
    // Timing
    double last_time;
} PongGame;

// Initialize game
bool pong_init(PongGame* game) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
        printf("SDL initialization failed: %s\n", SDL_GetError());
        return false;
    }
    
    game->window = SDL_CreateWindow("Pong",
                                   SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                   WINDOW_WIDTH, WINDOW_HEIGHT, 0);
    if (!game->window) {
        printf("Window creation failed: %s\n", SDL_GetError());
        return false;
    }
    
    game->renderer = SDL_CreateRenderer(game->window, -1, 
                                       SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!game->renderer) {
        printf("Renderer creation failed: %s\n", SDL_GetError());
        return false;
    }
    
    // Initialize audio
    if (Mix_OpenAudio(22050, MIX_DEFAULT_FORMAT, 2, 4096) < 0) {
        printf("Audio initialization failed: %s\n", Mix_GetError());
        return false;
    }
    
    // Load sounds
    game->paddle_sound = Mix_LoadWAV("assets/paddle.wav");
    game->score_sound = Mix_LoadWAV("assets/score.wav");
    
    // Initialize game objects
    game->player_paddle = (Rect){50, WINDOW_HEIGHT/2 - PADDLE_HEIGHT/2, PADDLE_WIDTH, PADDLE_HEIGHT};
    game->ai_paddle = (Rect){WINDOW_WIDTH - 50 - PADDLE_WIDTH, WINDOW_HEIGHT/2 - PADDLE_HEIGHT/2, PADDLE_WIDTH, PADDLE_HEIGHT};
    
    // Initialize ball
    game->ball.x = WINDOW_WIDTH / 2;
    game->ball.y = WINDOW_HEIGHT / 2;
    game->ball.vx = BALL_SPEED * (rand() % 2 == 0 ? 1 : -1);
    game->ball.vy = BALL_SPEED * 0.5f * (rand() % 2 == 0 ? 1 : -1);
    
    game->player_score = 0;
    game->ai_score = 0;
    game->running = true;
    game->game_paused = false;
    game->last_time = SDL_GetTicks() / 1000.0;
    
    return true;
}

// Handle input
void pong_handle_input(PongGame* game) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_QUIT:
                game->running = false;
                break;
            case SDL_KEYDOWN:
                if (event.key.keysym.sym == SDLK_ESCAPE) {
                    game->running = false;
                } else if (event.key.keysym.sym == SDLK_SPACE) {
                    game->game_paused = !game->game_paused;
                }
                break;
        }
    }
    
    // Continuous input
    const Uint8* keyboard_state = SDL_GetKeyboardState(NULL);
    float delta_time = 0.016f; // Approximate frame time
    
    if (keyboard_state[SDL_SCANCODE_W] && game->player_paddle.y > 0) {
        game->player_paddle.y -= PADDLE_SPEED * delta_time;
    }
    if (keyboard_state[SDL_SCANCODE_S] && 
        game->player_paddle.y + game->player_paddle.height < WINDOW_HEIGHT) {
        game->player_paddle.y += PADDLE_SPEED * delta_time;
    }
}

// Rectangle collision detection
bool rect_intersects(Rect a, Rect b) {
    return (a.x < b.x + b.width && a.x + a.width > b.x &&
            a.y < b.y + b.height && a.y + a.height > b.y);
}

// Update game logic
void pong_update(PongGame* game, float delta_time) {
    if (game->game_paused) return;
    
    // AI paddle movement (simple following)
    float ai_center = game->ai_paddle.y + game->ai_paddle.height / 2;
    float ball_center = game->ball.y;
    
    if (ai_center < ball_center - 10) {
        game->ai_paddle.y += PADDLE_SPEED * 0.7f * delta_time;
    } else if (ai_center > ball_center + 10) {
        game->ai_paddle.y -= PADDLE_SPEED * 0.7f * delta_time;
    }
    
    // Keep AI paddle in bounds
    if (game->ai_paddle.y < 0) game->ai_paddle.y = 0;
    if (game->ai_paddle.y + game->ai_paddle.height > WINDOW_HEIGHT) {
        game->ai_paddle.y = WINDOW_HEIGHT - game->ai_paddle.height;
    }
    
    // Update ball position
    game->ball.x += game->ball.vx * delta_time;
    game->ball.y += game->ball.vy * delta_time;
    
    // Ball collision with top/bottom walls
    if (game->ball.y <= 0 || game->ball.y + BALL_SIZE >= WINDOW_HEIGHT) {
        game->ball.vy = -game->ball.vy;
        if (game->paddle_sound) Mix_PlayChannel(-1, game->paddle_sound, 0);
    }
    
    // Ball collision with paddles
    Rect ball_rect = {game->ball.x, game->ball.y, BALL_SIZE, BALL_SIZE};
    
    if (rect_intersects(ball_rect, game->player_paddle) && game->ball.vx < 0) {
        game->ball.vx = -game->ball.vx;
        // Add some spin based on where ball hit paddle
        float hit_pos = (game->ball.y + BALL_SIZE/2) - (game->player_paddle.y + game->player_paddle.height/2);
        game->ball.vy += hit_pos * 3.0f;
        if (game->paddle_sound) Mix_PlayChannel(-1, game->paddle_sound, 0);
    }
    
    if (rect_intersects(ball_rect, game->ai_paddle) && game->ball.vx > 0) {
        game->ball.vx = -game->ball.vx;
        float hit_pos = (game->ball.y + BALL_SIZE/2) - (game->ai_paddle.y + game->ai_paddle.height/2);
        game->ball.vy += hit_pos * 3.0f;
        if (game->paddle_sound) Mix_PlayChannel(-1, game->paddle_sound, 0);
    }
    
    // Ball out of bounds (scoring)
    if (game->ball.x < 0) {
        game->ai_score++;
        if (game->score_sound) Mix_PlayChannel(-1, game->score_sound, 0);
        // Reset ball
        game->ball.x = WINDOW_WIDTH / 2;
        game->ball.y = WINDOW_HEIGHT / 2;
        game->ball.vx = BALL_SPEED;
        game->ball.vy = BALL_SPEED * 0.5f * (rand() % 2 == 0 ? 1 : -1);
    } else if (game->ball.x + BALL_SIZE > WINDOW_WIDTH) {
        game->player_score++;
        if (game->score_sound) Mix_PlayChannel(-1, game->score_sound, 0);
        // Reset ball
        game->ball.x = WINDOW_WIDTH / 2;
        game->ball.y = WINDOW_HEIGHT / 2;
        game->ball.vx = -BALL_SPEED;
        game->ball.vy = BALL_SPEED * 0.5f * (rand() % 2 == 0 ? 1 : -1);
    }
}

// Render game
void pong_render(PongGame* game) {
    // Clear screen
    SDL_SetRenderDrawColor(game->renderer, 0, 0, 0, 255);
    SDL_RenderClear(game->renderer);
    
    // Draw center line
    SDL_SetRenderDrawColor(game->renderer, 255, 255, 255, 255);
    for (int y = 0; y < WINDOW_HEIGHT; y += 20) {
        SDL_Rect line_rect = {WINDOW_WIDTH/2 - 2, y, 4, 10};
        SDL_RenderFillRect(game->renderer, &line_rect);
    }
    
    // Draw paddles
    SDL_Rect player_rect = {(int)game->player_paddle.x, (int)game->player_paddle.y,
                           (int)game->player_paddle.width, (int)game->player_paddle.height};
    SDL_RenderFillRect(game->renderer, &player_rect);
    
    SDL_Rect ai_rect = {(int)game->ai_paddle.x, (int)game->ai_paddle.y,
                       (int)game->ai_paddle.width, (int)game->ai_paddle.height};
    SDL_RenderFillRect(game->renderer, &ai_rect);
    
    // Draw ball
    SDL_Rect ball_rect = {(int)game->ball.x, (int)game->ball.y, BALL_SIZE, BALL_SIZE};
    SDL_RenderFillRect(game->renderer, &ball_rect);
    
    // Simple score display using rectangles (no TTF for simplicity)
    // Draw score as simple digits made of rectangles
    // (Implementation simplified for brevity)
    
    SDL_RenderPresent(game->renderer);
}

// Main game loop
void pong_run(PongGame* game) {
    while (game->running) {
        double current_time = SDL_GetTicks() / 1000.0;
        float delta_time = (float)(current_time - game->last_time);
        game->last_time = current_time;
        
        // Cap delta time to prevent large jumps
        if (delta_time > 0.05f) delta_time = 0.05f;
        
        pong_handle_input(game);
        pong_update(game, delta_time);
        pong_render(game);
    }
}

// Cleanup
void pong_cleanup(PongGame* game) {
    if (game->paddle_sound) Mix_FreeChunk(game->paddle_sound);
    if (game->score_sound) Mix_FreeChunk(game->score_sound);
    
    Mix_CloseAudio();
    
    if (game->renderer) SDL_DestroyRenderer(game->renderer);
    if (game->window) SDL_DestroyWindow(game->window);
    
    SDL_Quit();
}

int main(int argc, char* argv[]) {
    PongGame game = {0};
    
    if (!pong_init(&game)) {
        return 1;
    }
    
    printf("Pong Game Controls:\n");
    printf("W/S: Move paddle up/down\n");
    printf("Space: Pause/Resume\n");
    printf("Escape: Exit\n");
    
    pong_run(&game);
    pong_cleanup(&game);
    
    return 0;
}
```

**Footnote 1**: *SDL2 (Simple DirectMedia Layer) provides cross-platform access to audio, keyboard, mouse, joystick, and graphics hardware. It's widely used in commercial games and has excellent documentation at libsdl.org.*

**Footnote 2**: *Raylib is a simpler, more beginner-friendly alternative to SDL2. It provides a cleaner API but less low-level control. Trade-off: easier to learn vs. less flexibility.*

**Footnote 3**: *Fixed timestep ensures consistent physics simulation regardless of frame rate, crucial for deterministic gameplay and networked games. Variable timestep is simpler but can cause physics instability.*

**Footnote 4**: *The "spiral of death" occurs when frame processing takes longer than the timestep, causing the accumulator to grow indefinitely. Capping maximum frame time prevents this.*

**Footnote 5**: *Sprite batching reduces draw calls by grouping sprites with the same texture. This is crucial for performance when rendering many sprites.*

**Footnote 6**: *Sparse sets provide O(1) insertion, deletion, and lookup while maintaining dense iteration over entities with specific components. This is optimal for ECS systems.*

#### Concepts ⚙
- Game loop architecture with fixed and variable timesteps
- Input handling with polling vs event-driven approaches  
- 2D rendering optimizations with batching and culling
- Entity-Component-System pattern for flexible game objects

#### Errors ⚠
- Frame rate dependent physics causing inconsistent gameplay
- Memory leaks from unfreed SDL resources
- Audio glitches from incorrect buffer sizes
- Input lag from polling at wrong frequency

#### Tips 🧠
- Profile your game loop to identify bottlenecks
- Use object pools to avoid frequent allocations
- Implement proper game state management for menus/gameplay
- Test on different hardware to ensure consistent performance

#### Tools 🔧
- **Game Libraries**: SDL2, Raylib, SFML
- **Audio**: SDL_mixer, OpenAL, FMOD
- **Profiling**: AMD CodeXL, Intel VTune, custom profilers
- **Asset Pipeline**: Aseprite, GIMP, Audacity

---

## Appendices

### Glossary

**API (Application Programming Interface)**: A set of functions, protocols, and tools that allow different software components to communicate with each other.

**ASLR (Address Space Layout Randomization)**: A security technique that randomizes the memory layout of a process to prevent exploit attacks.

**Atomicity**: The property of an operation being indivisible - it either completes entirely or not at all, with no intermediate states visible.

**Big Endian**: A byte order where the most significant byte is stored first. Contrast with Little Endian.

**Cache Miss**: When requested data is not found in the CPU cache, requiring a slower fetch from main memory.

**Deadlock**: A situation where two or more threads are blocked forever, each waiting for the other to release a resource.

**ECS (Entity-Component-System)**: An architectural pattern used in game development where entities are composed of components and processed by systems.

**Endianness**: The order in which bytes are arranged within larger data types. Important for data serialization and network protocols.

**Frame Rate**: The frequency at which images are displayed, typically measured in frames per second (FPS).

**Heap**: A region of memory used for dynamic allocation, managed by malloc/free in C.

**IPC (Inter-Process Communication)**: Mechanisms that allow processes to communicate and synchronize with each other.

**Memory Leak**: A condition where a program fails to release memory that is no longer needed, causing gradual memory exhaustion.

**Mutex (Mutual Exclusion)**: A synchronization primitive that prevents multiple threads from simultaneously accessing shared resources.

**Race Condition**: A situation where the outcome of a program depends on the unpredictable timing of multiple threads.

**RAII (Resource Acquisition Is Initialization)**: A programming idiom where resource lifetime is tied to object lifetime.

**Stack**: A region of memory that stores local variables and function call information, managed automatically by the compiler.

**Thread Pool**: A pattern where a fixed number of threads are created to handle tasks from a queue, avoiding the overhead of thread creation/destruction.

**UB (Undefined Behavior)**: Behavior that is not specified by the C standard, potentially causing unpredictable program behavior.

**VSync (Vertical Synchronization)**: A display technology that synchronizes frame rate with monitor refresh rate to prevent screen tearing.

### FAQ & Troubleshooting

**Q: My program compiles but crashes with segmentation fault. What should I check?**

A: Common causes include:
- Dereferencing NULL or uninitialized pointers
- Buffer overflows (writing past array boundaries)  
- Use after free (accessing freed memory)
- Stack overflow from infinite recursion

Use debugging tools like GDB, Valgrind, or AddressSanitizer to identify the exact location.

**Q: I'm getting "undefined reference" linker errors. How do I fix this?**

A: This usually means:
- Missing function implementation
- Not linking required libraries (add `-lm` for math, `-lpthread` for threads)
- Incorrect function declarations (check headers)
- Missing object files in the link command

Example fix: `gcc -o program main.c utils.c -lm -lpthread`

**Q: SDL2 fails to initialize. What's wrong?**

A: Check these common issues:
- SDL2 development libraries not installed
- Missing DLLs on Windows (copy SDL2.dll to executable directory)
- Insufficient permissions or missing display server (on Linux)
- Outdated graphics drivers

Enable SDL error reporting: `printf("SDL Error: %s\n", SDL_GetError());`

**Q: My multithreaded program sometimes works, sometimes doesn't. Why?**

A: This suggests race conditions or missing synchronization:
- Shared data accessed without mutexes
- Incorrect use of condition variables
- Missing memory barriers
- Thread-unsafe library functions

Use ThreadSanitizer: `gcc -fsanitize=thread -g program.c`

**Q: Program runs slowly in Debug mode but fast in Release. Is this normal?**

A: Yes, this is expected because:
- Debug builds disable optimizations (-O0)
- Extra bounds checking and assertions
- Debug symbols and metadata
- Sanitizers add significant overhead

For production, use Release builds with optimizations (-O2 or -O3).

**Q: Getting "permission denied" when running my program on Linux/macOS?**

A: Make the file executable: `chmod +x program`

For system resources, you might need elevated privileges: `sudo ./program`

**Q: CMake can't find my library. How do I fix this?**

A: Try these approaches:
- Install development packages: `sudo apt install libsdl2-dev`
- Set PKG_CONFIG_PATH: `export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig`
- Use find_package with explicit paths
- Check CMAKE_PREFIX_PATH environment variable

### Curated Resources

**Books:**
- *The C Programming Language* by Kernighan & Ritchie - The definitive C reference, essential for understanding language fundamentals
- *Expert C Programming* by Peter van der Linden - Deep insights into C's quirks and advanced features  
- *Modern C* by Jens Gustedt - Contemporary approach to C programming with C11/C17 features
- *Game Engine Architecture* by Jason Gregory - Comprehensive guide to game engine systems and patterns

**Documentation:**
- *C11 Standard (ISO/IEC 9899:2011)* - Official language specification for compliance and edge cases
- *POSIX.1-2017* - Standard for Unix-like operating system interfaces and threading
- *SDL2 Documentation* (wiki.libsdl.org) - Complete API reference with examples
- *Intel Software Developer Manuals* - Low-level CPU architecture and optimization guidance

**Tools & Static Analysis:**
- *Clang Static Analyzer* - Free static analysis with excellent C support
- *PVS-Studio* - Commercial static analyzer with deep C/C++ understanding
- *PC-lint Plus* - Industry-standard static analysis for safety-critical code
- *Compiler Explorer* (godbolt.org) - Online tool to examine compiler output and optimizations

**Online Resources:**
- *C FAQ* (c-faq.com) - Authoritative answers to common C programming questions
- *SEI CERT C Coding Standard* - Security-focused coding guidelines with rationale
- *Awesome C* (GitHub) - Curated list of C libraries, tools, and resources
- *Stack Overflow C Tag* - Active community for troubleshooting and best practices

**Courses & Tutorials:**
- *CS50* (Harvard) - Excellent introduction to programming fundamentals with C
- *Beej's Guide to Network Programming* - Practical socket programming tutorial
- *Learn C The Hard Way* - Hands-on approach with emphasis on debugging skills
- *C Programming Course* (Coursera) - University-level structured learning

---

## Capstone Projects

### Systems Capstone: Mini File Analyzer

**Project Overview:**
A professional-grade file analysis tool demonstrating systems programming concepts including concurrent processing, plugin architecture, and robust error handling.

**Project Structure:**
```
file-analyzer/
├── .github/
│   └── workflows/
│       └── ci.yml                 # CI/CD pipeline
├── cmake/
│   ├── CompilerWarnings.cmake     # Compiler configuration
│   └── CodeCoverage.cmake         # Coverage setup
├── src/
│   ├── main.c                     # Application entry point
│   ├── analyzer/
│   │   ├── core.c                 # Core analysis engine
│   │   ├── thread_pool.c          # Thread pool implementation
│   │   └── plugin_manager.c       # Plugin system
│   ├── plugins/
│   │   ├── text_analyzer.c        # Text file analysis
│   │   ├── image_analyzer.c       # Image metadata extraction
│   │   └── binary_analyzer.c      # Binary file analysis
│   └── utils/
│       ├── config.c               # Configuration management
│       ├── logger.c               # Logging system
│       └── file_utils.c           # File system utilities
├── include/
│   ├── analyzer/
│   │   ├── core.h
│   │   ├── thread_pool.h
│   │   └── plugin_api.h
│   └── utils/
│       ├── config.h
│       ├── logger.h
│       └── common.h
├── tests/
│   ├── unit/
│   │   ├── test_core.c
│   │   ├── test_thread_pool.c
│   │   └── test_config.c
│   ├── integration/
│   │   └── test_full_analysis.c
│   └── fixtures/
│       ├── sample.txt
│       ├── sample.jpg
│       └── sample.bin
├── config/
│   └── analyzer.toml              # Configuration file
├── docs/
│   ├── API.md                     # API documentation
│   └── DESIGN.md                  # Architecture overview
├── scripts/
│   ├── build.sh                   # Build script
│   └── run_tests.sh               # Test runner
├── CMakeLists.txt                 # Main build configuration
├── CMakePresets.json              # Build presets
└── README.md                      # Project documentation
```

**Core Implementation:**

```c
/* src/analyzer/core.c - Core analysis engine */
#include "analyzer/core.h"
#include "analyzer/thread_pool.h"
#include "analyzer/plugin_manager.h"
#include "utils/logger.h"
#include "utils/config.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char path[PATH_MAX];
    struct stat file_stat;
} FileEntry;

typedef struct {
    FileEntry* files;
    size_t count;
    size_t capacity;
} FileList;

static ThreadPool* g_thread_pool = NULL;
static PluginManager* g_plugin_manager = NULL;

// Analysis task for thread pool
typedef struct {
    char filepath[PATH_MAX];
    AnalysisResult* result;
} AnalysisTask;

void analysis_task_worker(void* arg) {
    AnalysisTask* task = (AnalysisTask*)arg;
    
    LOG_DEBUG("Analyzing file: %s", task->filepath);
    
    // Determine file type and select appropriate plugin
    Plugin* plugin = plugin_manager_select_plugin(g_plugin_manager, task->filepath);
    if (plugin) {
        plugin->analyze(task->filepath, task->result);
        LOG_INFO("Analysis completed: %s (type: %s)", 
                task->filepath, task->result->file_type);
    } else {
        LOG_WARN("No suitable plugin for file: %s", task->filepath);
        task->result->status = ANALYSIS_STATUS_UNSUPPORTED;
    }
    
    free(task);
}

// Recursive directory scanning
static void scan_directory_recursive(const char* path, FileList* file_list) {
    DIR* dir = opendir(path);
    if (!dir) {
        LOG_ERROR("Failed to open directory: %s", path);
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        struct stat file_stat;
        if (stat(full_path, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                scan_directory_recursive(full_path, file_list);
            } else if (S_ISREG(file_stat.st_mode)) {
                // Add file to list
                if (file_list->count >= file_list->capacity) {
                    file_list->capacity *= 2;
                    file_list->files = realloc(file_list->files, 
                                             file_list->capacity * sizeof(FileEntry));
                }
                
                FileEntry* entry = &file_list->files[file_list->count++];
                strncpy(entry->path, full_path, sizeof(entry->path) - 1);
                entry->file_stat = file_stat;
            }
        }
    }
    
    closedir(dir);
}

// Main analysis function
AnalysisSession* analyzer_create_session(const AnalyzerConfig* config) {
    AnalysisSession* session = calloc(1, sizeof(AnalysisSession));
    if (!session) return NULL;
    
    // Initialize thread pool
    g_thread_pool = thread_pool_create(config->thread_count);
    if (!g_thread_pool) {
        free(session);
        return NULL;
    }
    
    // Initialize plugin manager
    g_plugin_manager = plugin_manager_create();
    if (!g_plugin_manager) {
        thread_pool_destroy(g_thread_pool);
        free(session);
        return NULL;
    }
    
    // Load plugins
    plugin_manager_load_plugins(g_plugin_manager, config->plugin**Footnote 3**: *Interactive rebase allows you to squash commits, reword messages, and reorder commits before merging. This creates cleaner history but should not be used on public branches that others depend on.*

**Footnote 4**: *CI/CD pipelines automate building, testing, and deployment processes. This reduces human error, ensures consistent builds across environments, and enables rapid iteration.*

**Footnote 5**: *Static analysis tools examine code without executing it, finding potential bugs, security vulnerabilities, and style violations. They complement dynamic testing by catching issues that might not surface during normal execution.*

#### Concepts ⚙
- Version control workflows for collaborative development
- Automated testing and continuous integration practices
- Code quality enforcement through tooling
- Professional project organization and documentation standards

#### Errors ⚠
- Inconsistent coding styles across team members
- Missing or inadequate code documentation
- Skipping code reviews and quality checks
- Not following established Git workflows

#### Tips 🧠
- Establish team coding standards early in the project
- Use pre-commit hooks to enforce quality standards
- Write meaningful commit messages for better history tracking
- Regularly review and update CI/CD pipelines

#### Tools 🔧
- **Version Control**: Git, GitLab, GitHub, Bitbucket
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, Travis CI
- **Code Quality**: SonarQube, Codacy, CodeClimate
- **Documentation**: Doxygen, Sphinx, GitBook

---

### 27. Game Development with C {#game-development}

**Figure Reference: [Game Engine Architecture Diagram]**

Game development in C offers direct control over performance and memory management, making it ideal for high-performance games and game engines.

#### Library Setup and Configuration

**SDL2 Installation and Setup¹:**

```bash
# Ubuntu/Debian
sudo apt-get install libsdl2-dev libsdl2-image-dev libsdl2-mixer-dev libsdl2-ttf-dev

# macOS with Homebrew
brew install sdl2 sdl2_image sdl2_mixer sdl2_ttf

# Windows with vcpkg
vcpkg install sdl2:x64-windows sdl2-image:x64-windows sdl2-mixer:x64-windows

# Arch Linux
sudo pacman -S sdl2 sdl2_image sdl2_mixer sdl2_ttf
```

**Raylib Installation²:**

```bash
# Ubuntu/Debian
sudo apt-get install libasound2-dev libx11-dev libxrandr-dev libxi-dev libgl1-mesa-dev libglu1-mesa-dev libxcursor-dev libxinerama-dev
git clone https://github.com/raysan5/raylib.git
cd raylib && make PLATFORM=PLATFORM_DESKTOP

# macOS  
brew install raylib

# Windows - precompiled binaries available
# Download from: https://github.com/raysan5/raylib/releases
```

**CMake Configuration for Game Projects:**

```cmake
# CMakeLists.txt - Game project configuration
cmake_minimum_required(VERSION 3.15)
project(GameProject LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find SDL2 packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_IMAGE REQUIRED SDL2_image)
pkg_check_modules(SDL2_MIXER REQUIRED SDL2_mixer)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)

# Alternative: Find Raylib
# find_package(raylib QUIET)
# if (NOT raylib_FOUND)
#     include(FetchContent)
#     FetchContent_Declare(raylib
#         GIT_REPOSITORY https://github.com/raysan5/raylib.git
#         GIT_TAG 4.5.0)
#     FetchContent_MakeAvailable(raylib)
# endif()

# Game executable
add_executable(game
    src/main.c
    src/game.c
    src/renderer.c
    src/input.c
    src/audio.c
)

# Link libraries
target_link_libraries(game
    ${SDL2_LIBRARIES}
    ${SDL2_IMAGE_LIBRARIES}
    ${SDL2_MIXER_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
    m  # Math library
)

target_include_directories(game PRIVATE
    include
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_IMAGE_INCLUDE_DIRS}
    ${SDL2_MIXER_INCLUDE_DIRS}
    ${SDL2_TTF_INCLUDE_DIRS}
)

# Copy assets to build directory
file(COPY assets DESTINATION ${CMAKE_BINARY_DIR})

# Platform-specific settings
if(WIN32)
    # Copy SDL2 DLLs on Windows
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(SDL2_DLL_DIR "${SDL2_PREFIX}/debug/bin")
    else()
        set(SDL2_DLL_DIR "${SDL2_PREFIX}/bin")
    endif()
    
    add_custom_command(TARGET game POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${SDL2_DLL_DIR}" $<TARGET_FILE_DIR:game>)
endif()
```

#### Game Loop Architecture

**Core Game Loop Theory³:**

```c
/* game_loop.c - Professional game loop implementation */
#include <SDL2/SDL.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
    SDL_Window* window;
    SDL_Renderer* renderer;
    bool running;
    double current_time;
    double accumulator;
    double frame_time;
    int target_fps;
} GameEngine;

// Fixed timestep constants⁴
static const double FIXED_TIMESTEP = 1.0 / 60.0;  // 60 FPS physics
static const double MAX_FRAME_TIME = 0.25;        // Prevent spiral of death

// High-resolution timer
double get_time(void) {
    return (double)SDL_GetPerformanceCounter() / 
           (double)SDL_GetPerformanceFrequency();
}

// Variable timestep game loop (simple but problematic)
void variable_timestep_loop(GameEngine* engine) {
    double last_time = get_time();
    
    while (engine->running) {
        double current_time = get_time();
        double delta_time = current_time - last_time;
        last_time = current_time;
        
        // Process input
        handle_input(engine);
        
        // Update game state (frame rate dependent!)
        update_game(delta_time);
        
        // Render
        render_game(engine);
        
        SDL_Delay(1);  // Yield CPU
    }
}

// Fixed timestep with accumulator (professional approach)
void fixed_timestep_loop(GameEngine* engine) {
    engine->current_time = get_time();
    engine->accumulator = 0.0;
    
    while (engine->running) {
        double new_time = get_time();
        double frame_time = new_time - engine->current_time;
        
        // Prevent spiral of death
        if (frame_time > MAX_FRAME_TIME) {
            frame_time = MAX_FRAME_TIME;
        }
        
        engine->current_time = new_time;
        engine->accumulator += frame_time;
        
        // Process input (once per frame)
        handle_input(engine);
        
        // Fixed timestep physics updates
        while (engine->accumulator >= FIXED_TIMESTEP) {
            update_physics(FIXED_TIMESTEP);
            engine->accumulator -= FIXED_TIMESTEP;
        }
        
        // Interpolation factor for smooth rendering
        double interpolation = engine->accumulator / FIXED_TIMESTEP;
        
        // Variable timestep game logic
        update_game_logic(frame_time);
        
        // Render with interpolation
        render_game_interpolated(engine, interpolation);
        
        // Frame rate limiting
        limit_frame_rate(engine, frame_time);
    }
}

// Frame rate limiting
void limit_frame_rate(GameEngine* engine, double frame_time) {
    if (engine->target_fps > 0) {
        double target_frame_time = 1.0 / engine->target_fps;
        double sleep_time = target_frame_time - frame_time;
        
        if (sleep_time > 0) {
            // Convert to milliseconds
            Uint32 delay_ms = (Uint32)(sleep_time * 1000.0);
            if (delay_ms > 0) {
                SDL_Delay(delay_ms);
            }
        }
    }
}

// Game loop with performance monitoring
void monitored_game_loop(GameEngine* engine) {
    double last_time = get_time();
    double fps_timer = 0.0;
    int frame_count = 0;
    
    printf("Starting game loop with performance monitoring\n");
    
    while (engine->running) {
        double current_time = get_time();
        double delta_time = current_time - last_time;
        last_time = current_time;
        
        // FPS calculation
        fps_timer += delta_time;
        frame_count++;
        
        if (fps_timer >= 1.0) {  // Every second
            printf("FPS: %d, Frame Time: %.2f ms\n", 
                   frame_count, (fps_timer / frame_count) * 1000.0);
            fps_timer = 0.0;
            frame_count = 0;
        }
        
        // Main game loop steps
        handle_input(engine);
        update_game(delta_time);
        render_game(engine);
        
        // VSync alternative for frame limiting
        SDL_GL_SetSwapInterval(1);  // Enable VSync if using OpenGL
    }
}
```

#### Input Handling Systems

```c
/* input_system.c - Comprehensive input management */
#include <SDL2/SDL.h>
#include <SDL2/SDL_gamecontroller.h>
#include <stdbool.h>
#include <string.h>

#define MAX_KEYS 512
#define MAX_CONTROLLERS 4

typedef struct {
    // Keyboard state
    bool keys_current[MAX_KEYS];
    bool keys_previous[MAX_KEYS];
    
    // Mouse state
    int mouse_x, mouse_y;
    int mouse_delta_x, mouse_delta_y;
    bool mouse_buttons_current[8];
    bool mouse_buttons_previous[8];
    int scroll_x, scroll_y;
    
    // Controller state
    SDL_GameController* controllers[MAX_CONTROLLERS];
    int controller_count;
    
    // Text input
    char text_input[64];
    bool text_input_active;
} InputState;

static InputState input_state = {0};

// Initialize input system
void input_init(void) {
    memset(&input_state, 0, sizeof(InputState));
    
    // Initialize game controller subsystem
    if (SDL_Init(SDL_INIT_GAMECONTROLLER) < 0) {
        printf("Failed to initialize game controller: %s\n", SDL_GetError());
    }
    
    // Detect and open game controllers
    for (int i = 0; i < SDL_NumJoysticks(); i++) {
        if (SDL_IsGameController(i)) {
            SDL_GameController* controller = SDL_GameControllerOpen(i);
            if (controller && input_state.controller_count < MAX_CONTROLLERS) {
                input_state.controllers[input_state.controller_count++] = controller;
                printf("Opened controller: %s\n", SDL_GameControllerName(controller));
            }
        }
    }
}

// Update input state (call once per frame)
void input_update(void) {
    // Save previous keyboard state
    memcpy(input_state.keys_previous, input_state.keys_current, 
           sizeof(input_state.keys_current));
    
    // Save previous mouse button state
    memcpy(input_state.mouse_buttons_previous, input_state.mouse_buttons_current,
           sizeof(input_state.mouse_buttons_current));
    
    // Get current keyboard state
    const Uint8* keyboard_state = SDL_GetKeyboardState(NULL);
    for (int i = 0; i < MAX_KEYS; i++) {
        input_state.keys_current[i] = keyboard_state[i];
    }
    
    // Get mouse state
    Uint32 mouse_state = SDL_GetMouseState(&input_state.mouse_x, &input_state.mouse_y);
    for (int i = 0; i < 8; i++) {
        input_state.mouse_buttons_current[i] = (mouse_state & SDL_BUTTON(i + 1)) != 0;
    }
    
    // Calculate mouse delta
    static int last_mouse_x = 0, last_mouse_y = 0;
    input_state.mouse_delta_x = input_state.mouse_x - last_mouse_x;
    input_state.mouse_delta_y = input_state.mouse_y - last_mouse_y;
    last_mouse_x = input_state.mouse_x;
    last_mouse_y = input_state.mouse_y;
    
    // Reset scroll
    input_state.scroll_x = input_state.scroll_y = 0;
    
    // Clear text input
    input_state.text_input[0] = '\0';
}

// Process SDL events
void input_handle_event(SDL_Event* event) {
    switch (event->type) {
        case SDL_MOUSEWHEEL:
            input_state.scroll_x = event->wheel.x;
            input_state.scroll_y = event->wheel.y;
            break;
            
        case SDL_TEXTINPUT:
            if (input_state.text_input_active) {
                strncpy(input_state.text_input, event->text.text, 
                       sizeof(input_state.text_input) - 1);
                input_state.text_input[sizeof(input_state.text_input) - 1] = '\0';
            }
            break;
            
        case SDL_CONTROLLERDEVICEADDED:
            if (input_state.controller_count < MAX_CONTROLLERS) {
                SDL_GameController* controller = SDL_GameControllerOpen(event->cdevice.which);
                if (controller) {
                    input_state.controllers[input_state.controller_count++] = controller;
                    printf("Controller connected: %s\n", SDL_GameControllerName(controller));
                }
            }
            break;
            
        case SDL_CONTROLLERDEVICEREMOVED:
            for (int i = 0; i < input_state.controller_count; i++) {
                if (SDL_GameControllerFromInstanceID(event->cdevice.which) == 
                    input_state.controllers[i]) {
                    SDL_GameControllerClose(input_state.controllers[i]);
                    // Shift remaining controllers
                    for (int j = i; j < input_state.controller_count - 1; j++) {
                        input_state.controllers[j] = input_state.controllers[j + 1];
                    }
                    input_state.controller_count--;
                    printf("Controller disconnected\n");
                    break;
                }
            }
            break;
    }
}

// Input query functions
bool input_key_pressed(SDL_Scancode key) {
    return input_state.keys_current[key] && !input_state.keys_previous[key];
}

bool input_key_held(SDL_Scancode key) {
    return input_state.keys_current[key];
}

bool input_key_released(SDL_Scancode key) {
    return !input_state.keys_current[key] && input_state.keys_previous[key];
}

bool input_mouse_pressed(int button) {
    return input_state.mouse_buttons_current[button] && 
           !input_state.mouse_buttons_previous[button];
}

void input_get_mouse_position(int* x, int* y) {
    *x = input_state.mouse_x;
    *y = input_state.mouse_y;
}

void input_get_mouse_delta(int* dx, int* dy) {
    *dx = input_state.mouse_delta_x;
    *dy = input_state.mouse_delta_y;
}

// Controller input
bool input_controller_button_pressed(int controller, SDL_GameControllerButton button) {
    if (controller >= input_state.controller_count) return false;
    
    static bool previous_state[MAX_CONTROLLERS][SDL_CONTROLLER_BUTTON_MAX] = {0};
    bool current = SDL_GameControllerGetButton(input_state.controllers[controller], button);
    bool pressed = current && !previous_state[controller][button];
    previous_state[controller][button] = current;
    
    return pressed;
}

float input_controller_axis(int controller, SDL_GameControllerAxis axis) {
    if (controller >= input_state.controller_count) return 0.0f;
    
    Sint16 value = SDL_GameControllerGetAxis(input_state.controllers[controller], axis);
    return (float)value / 32768.0f;  // Normalize to [-1, 1]
}

// Cleanup
void input_cleanup(void) {
    for (int i = 0; i < input_state.controller_count; i++) {
        SDL_GameControllerClose(input_state.controllers[i]);
    }
    SDL_QuitSubSystem(SDL_INIT_GAMECONTROLLER);
}
```

#### 2D Rendering System

```c
/* renderer.c - 2D rendering system with batching */
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <SDL2/SDL_ttf.h>
#include <stdbool.h>
#include <math.h>

#define MAX_BATCH_SPRITES 1024
#define MAX_TEXTURES 256

// Sprite batch vertex
typedef struct {
    float x, y;          // Position
    float u, v;          // Texture coordinates
    Uint8 r, g, b, a;    // Color
} Vertex;

// Sprite batch entry
typedef struct {
    SDL_Texture* texture;
    SDL_Rect src_rect;
    SDL_FRect dst_rect;
    float rotation;
    SDL_Color color;
} SpriteEntry;

// Camera/viewport
typedef struct {
    float x, y;          // Position
    float zoom;          // Zoom level
    int viewport_width;
    int viewport_height;
    SDL_FRect bounds;    // World bounds
} Camera;

// Renderer state
typedef struct {
    SDL_Renderer* sdl_renderer;
    Camera camera;
    
    // Sprite batching
    SpriteEntry sprite_batch[MAX_BATCH_SPRITES];
    int batch_count;
    SDL_Texture* current_texture;
    
    // Texture management
    SDL_Texture* textures[MAX_TEXTURES];
    int texture_count;
    
    // Font rendering
    TTF_Font* default_font;
    
    // Render stats
    int draw_calls;
    int sprites_rendered;
} Renderer;

static Renderer renderer = {0};

// Initialize renderer
bool renderer_init(SDL_Renderer* sdl_renderer, int viewport_width, int viewport_height) {
    renderer.sdl_renderer = sdl_renderer;
    renderer.camera.x = 0;
    renderer.camera.y = 0;
    renderer.camera.zoom = 1.0f;
    renderer.camera.viewport_width = viewport_width;
    renderer.camera.viewport_height = viewport_height;
    
    // Initialize SDL_image
    if (!(IMG_Init(IMG_INIT_PNG | IMG_INIT_JPG) & (IMG_INIT_PNG | IMG_INIT_JPG))) {
        printf("Failed to initialize SDL_image: %s\n", IMG_GetError());
        return false;
    }
    
    // Initialize SDL_ttf
    if (TTF_Init() == -1) {
        printf("Failed to initialize SDL_ttf: %s\n", TTF_GetError());
        return false;
    }
    
    // Load default font
    renderer.default_font = TTF_OpenFont("assets/fonts/default.ttf", 16);
    if (!renderer.default_font) {
        printf("Warning: Could not load default font\n");
    }
    
    return true;
}

// Load texture
SDL_Texture* renderer_load_texture(const char* filename) {
    if (renderer.texture_count >= MAX_TEXTURES) {
        printf("Maximum texture limit reached\n");
        return NULL;
    }
    
    SDL_Texture* texture = IMG_LoadTexture(renderer.sdl_renderer, filename);
    if (texture) {
        renderer.textures[renderer.texture_count++] = texture;
        printf("Loaded texture: %s\n", filename);
    } else {
        printf("Failed to load texture %s: %s\n", filename, IMG_GetError());
    }
    
    return texture;
}

// Begin frame
void renderer_begin_frame(void) {
    renderer.batch_count = 0;
    renderer.current_texture = NULL;
    renderer.draw_calls = 0;
    renderer.sprites_rendered = 0;
    
    // Clear screen
    SDL_SetRenderDrawColor(renderer.sdl_renderer, 32, 32, 64, 255);
    SDL_RenderClear(renderer.sdl_renderer);
}

// Flush current batch⁵
void renderer_flush_batch(void) {
    if (renderer.batch_count == 0) return;
    
    // Sort by texture to minimize texture switches
    // (Implementation simplified for brevity)
    
    SDL_Texture* last_texture = NULL;
    
    for (int i = 0; i < renderer.batch_count; i++) {
        SpriteEntry* entry = &renderer.sprite_batch[i];
        
        // Switch texture if needed
        if (entry->texture != last_texture) {
            SDL_SetTextureColorMod(entry->texture, 
                                  entry->color.r, entry->color.g, entry->color.b);
            SDL_SetTextureAlphaMod(entry->texture, entry->color.a);
            last_texture = entry->texture;
            renderer.draw_calls++;
        }
        
        // Transform destination rectangle by camera
        SDL_FRect transformed_dst = entry->dst_rect;
        transformed_dst.x = (entry->dst_rect.x - renderer.camera.x) * renderer.camera.zoom;
        transformed_dst.y = (entry->dst_rect.y - renderer.camera.y) * renderer.camera.zoom;
        transformed_dst.w = entry->dst_rect.w * renderer.camera.zoom;
        transformed_dst.h = entry->dst_rect.h * renderer.camera.zoom;
        
        // Render sprite
        if (entry->rotation == 0.0f) {
            SDL_RenderCopyF(renderer.sdl_renderer, entry->texture,
                           &entry->src_rect, &transformed_dst);
        } else {
            SDL_FPoint center = {transformed_dst.w / 2, transformed_dst.h / 2};
            SDL_RenderCopyExF(renderer.sdl_renderer, entry->texture,
                              &entry->src_rect, &transformed_dst,
                              entry->rotation, &center, SDL_FLIP_NONE);
        }
        
        renderer.sprites_rendered++;
    }
    
    renderer.batch_count = 0;
}

// Add sprite to batch
void renderer_draw_sprite(SDL_Texture* texture, SDL_Rect src_rect, 
                         SDL_FRect dst_rect, float rotation, SDL_Color color) {
    // Flush if batch is full or texture changed
    if (renderer.batch_count >= MAX_BATCH_SPRITES ||
        (renderer.current_texture && renderer.current_texture != texture)) {
        renderer_flush_batch();
    }
    
    renderer.current_texture = texture;
    
    SpriteEntry* entry = &renderer.sprite_batch[renderer.batch_count++];
    entry->texture = texture;
    entry->src_rect = src_rect;
    entry->dst_rect = dst_rect;
    entry->rotation = rotation;
    entry->color = color;
}

// Draw text
void renderer_draw_text(const char* text, float x, float y, SDL_Color color) {
    if (!renderer.default_font) return;
    
    SDL_Surface* surface = TTF_RenderText_Blended(renderer.default_font, text, color);
    if (surface) {
        SDL_Texture* texture = SDL_CreateTextureFromSurface(renderer.sdl_renderer, surface);
        if (texture) {
            SDL_FRect dst_rect = {x, y, surface->w, surface->h};
            SDL_Rect src_rect = {0, 0, surface->w, surface->h};
            
            renderer_draw_sprite(texture, src_rect, dst_rect, 0.0f, 
                               (SDL_Color){255, 255, 255, 255});
            
            SDL_DestroyTexture(texture);
        }
        SDL_FreeSurface(surface);
    }
}

// Camera functions
void renderer_camera_set_position(float x, float y) {
    renderer.camera.x = x;
    renderer.camera.y = y;
}

void renderer_camera_set_zoom(float zoom) {
    renderer.camera.zoom = fmaxf(0.1f, zoom);  // Minimum zoom
}

void renderer_camera_follow(float target_x, float target_y, float lerp_factor) {
    // Smooth camera following
    float center_x = target_x - renderer.camera.viewport_width / 2;
    float center_y = target_y - renderer.camera.viewport_height / 2;
    
    renderer.camera.x += (center_x - renderer.camera.x) * lerp_factor;
    renderer.camera.y += (center_y - renderer.camera.y) * lerp_factor;
}

// End frame and present
void renderer_end_frame(void) {
    renderer_flush_batch();
    SDL_RenderPresent(renderer.sdl_renderer);
    
    // Print debug stats (every 60 frames)
    static int frame_count = 0;
    if (++frame_count % 60 == 0) {
        printf("Render stats: %d draw calls, %d sprites\n", 
               renderer.draw_calls, renderer.sprites_rendered);
    }
}

// Cleanup
void renderer_cleanup(void) {
    for (int i = 0; i < renderer.texture_count; i++) {
        SDL_DestroyTexture(renderer.textures[i]);
    }
    
    if (renderer.default_font) {
        TTF_CloseFont(renderer.default_font);
    }
    
    TTF_Quit();
    IMG_Quit();
}
```

#### Entity-Component-System Pattern

```c
/* ecs.c - Entity Component System implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Entity is just an ID
typedef uint32_t Entity;
typedef uint32_t ComponentType;

#define MAX_ENTITIES 10000
#define MAX_COMPONENT_TYPES 32
#define NULL_ENTITY 0

// Component mask for tracking which components an entity has
typedef uint32_t ComponentMask;

// Sparse set for efficient entity-component mapping⁶
typedef struct {
    uint32_t dense[MAX_ENTITIES];   // Dense array of entity IDs
    uint32_t sparse[MAX_ENTITIES];  // Sparse array mapping entity ID to dense index
    uint32_t count;                 // Number of entities in set
} SparseSet;

// Component pool (Structure of Arrays layout)
typedef struct {
    void* data;           // Component data array
    size_t element_size;  // Size of each component
    size_t capacity;      // Maximum components
    SparseSet entities;   // Entities that have this component
} ComponentPool;

// ECS World
typedef struct {
    Entity next_entity_id;
    ComponentMask entity_masks[MAX_ENTITIES];
    ComponentPool component_pools[MAX_COMPONENT_TYPES];
    uint32_t component_count;
} ECSWorld;

static ECSWorld ecs_world = {1}; // Entity 0 is reserved as NULL_ENTITY

// Initialize sparse set
void sparse_set_init(SparseSet* set) {
    set->count = 0;
    memset(set->dense, 0, sizeof(set->dense));
    memset(set->sparse, 0, sizeof(set->sparse));
}

// Add entity to sparse set
void sparse_set_add(SparseSet* set, Entity entity) {
    assert(entity < MAX_ENTITIES);
    assert(!sparse_set_contains(set, entity));
    
    uint32_t dense_index = set->count;
    set->dense[dense_index] = entity;
    set->sparse[entity] = dense_index;
    set->count++;
}

// Remove entity from sparse set
void sparse_set_remove(SparseSet* set, Entity entity) {
    assert(sparse_set_contains(set, entity));
    
    uint32_t dense_index = set->sparse[entity];
    uint32_t last_index = set->count - 1;
    Entity last_entity = set->dense[last_index];
    
    // Swap with last element
    set->dense[dense_index] = last_entity;
    set->sparse[last_entity] = dense_index;
    
    set->count--;
}

// Check if entity is in sparse set
bool sparse_set_contains(SparseSet* set, Entity entity) {
    if (entity >= MAX_ENTITIES) return false;
    uint32_t dense_index = set->sparse[entity];
    return dense_index < set->count && set->dense[dense_index] == entity;
}

// Register component type
ComponentType ecs_register_component(size_t component_size) {
    assert(ecs_world.component_count < MAX_COMPONENT_TYPES);
    
    ComponentType type = ecs_world.component_count++;
    ComponentPool* pool = &ecs_world.component_pools[type];
    
    pool->element_size = component_size;
    pool->capacity = MAX_ENTITIES;
    pool->data = calloc(MAX_ENTITIES, component_size);
    sparse_set_init(&pool->entities);
    
    return type;
}

// Create entity
Entity ecs_create_entity(void) {
    Entity entity = ecs_world.next_entity_id++;
    assert(entity < MAX_ENTITIES);
    
    ecs_world.entity_masks[entity] = 0;
    return entity;
}

// Destroy entity
void ecs_destroy_entity(Entity entity) {
    assert(entity != NULL_ENTITY && entity < MAX_ENTITIES);
    
    // Remove from all component pools
    for (uint32_t type = 0; type < ecs_world.component_count; type++) {
        if (ecs_world.entity_masks[entity] & (1u << type)) {
            sparse_set_remove(&ecs_world.component_pools[type].entities, entity);
        }
    }
    
    ecs_world.entity_masks[entity] = 0;
}

// Add component to entity
void* ecs_add_component(Entity entity, ComponentType type) {
    assert(entity != NULL_ENTITY && entity < MAX_ENTITIES);
    assert(type < ecs_world.component_count);
        free(input_data);
    free(output_data);
}
```

**Footnote 5**: *Parallel map operations are embarrassingly parallel - each element can be processed independently. This makes them ideal for multi-threading with minimal synchronization overhead.*

#### Common Concurrency Pitfalls

```c
/* concurrency_pitfalls.c - Common threading mistakes and solutions */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

// PITFALL 1: Race Condition Example
int unsafe_counter = 0;  // Shared without protection

void* unsafe_increment(void* arg) {
    for (int i = 0; i < 100000; i++) {
        unsafe_counter++;  // RACE CONDITION: Non-atomic operation⁶
    }
    return NULL;
}

void race_condition_demo(void) {
    printf("=== Race Condition Demo ===\n");
    
    pthread_t t1, t2;
    unsafe_counter = 0;
    
    pthread_create(&t1, NULL, unsafe_increment, NULL);
    pthread_create(&t2, NULL, unsafe_increment, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    printf("Expected: 200000, Actual: %d\n", unsafe_counter);
    printf("Race condition %s\n", unsafe_counter == 200000 ? "avoided" : "occurred");
}

// PITFALL 2: Deadlock Example⁷
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

void* thread1_deadlock_prone(void* arg) {
    printf("Thread 1: Acquiring mutex1\n");
    pthread_mutex_lock(&mutex1);
    sleep(1);  // Simulate work
    
    printf("Thread 1: Trying to acquire mutex2\n");
    pthread_mutex_lock(&mutex2);  // DEADLOCK RISK
    
    printf("Thread 1: Got both mutexes\n");
    
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    return NULL;
}

void* thread2_deadlock_prone(void* arg) {
    printf("Thread 2: Acquiring mutex2\n");
    pthread_mutex_lock(&mutex2);
    sleep(1);  // Simulate work
    
    printf("Thread 2: Trying to acquire mutex1\n");
    pthread_mutex_lock(&mutex1);  // DEADLOCK RISK
    
    printf("Thread 2: Got both mutexes\n");
    
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex2);
    return NULL;
}

// SOLUTION: Ordered locking
void* thread1_deadlock_safe(void* arg) {
    printf("Thread 1: Acquiring mutexes in order\n");
    pthread_mutex_lock(&mutex1);  // Always acquire in same order
    pthread_mutex_lock(&mutex2);
    
    printf("Thread 1: Got both mutexes safely\n");
    sleep(1);
    
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    return NULL;
}

void* thread2_deadlock_safe(void* arg) {
    printf("Thread 2: Acquiring mutexes in order\n");
    pthread_mutex_lock(&mutex1);  // Same order as thread1
    pthread_mutex_lock(&mutex2);
    
    printf("Thread 2: Got both mutexes safely\n");
    sleep(1);
    
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    return NULL;
}

void deadlock_demo(void) {
    printf("\n=== Deadlock Prevention Demo ===\n");
    
    pthread_t t1, t2;
    
    printf("Running deadlock-safe version:\n");
    pthread_create(&t1, NULL, thread1_deadlock_safe, NULL);
    pthread_create(&t2, NULL, thread2_deadlock_safe, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    printf("Completed without deadlock\n");
}

int main(void) {
    basic_pthread_demo();
    thread_attributes_demo();
    mutex_demo();
    condition_variable_demo();
    barrier_demo();
    spinlock_demo();
    thread_pool_demo();
    parallel_algorithms_demo();
    race_condition_demo();
    deadlock_demo();
    
    return 0;
}
```

**Footnote 6**: *Race conditions occur when multiple threads access shared data concurrently without proper synchronization. The final result depends on the unpredictable timing of thread execution.*

**Footnote 7**: *Deadlock occurs when two or more threads wait indefinitely for each other to release resources. The classic solution is to establish a global ordering for acquiring locks.*

#### Concepts ⚙
- Thread creation, joining, and lifecycle management
- Synchronization primitives for coordinating thread execution
- Thread pool pattern for efficient resource management
- Parallel algorithm design with map-reduce patterns

#### Errors ⚠
- Race conditions in shared data access
- Deadlocks from improper lock ordering
- Memory leaks in threaded applications
- Priority inversion and starvation issues

#### Tips 🧠
- Always protect shared data with appropriate synchronization
- Use thread-safe functions or provide your own synchronization
- Consider lock-free data structures for high-performance scenarios
- Profile threaded applications to identify bottlenecks

#### Tools 🔧
- **ThreadSanitizer**: Detects race conditions and deadlocks
- **Helgrind**: Valgrind tool for thread error detection
- **Intel VTune**: Performance profiling for threaded applications
- **Perf**: System-wide performance monitoring

---

### 26. Professional Practices {#professional-practices}

**Figure Reference: [Professional Development Workflow Diagram]**

Professional C development requires disciplined practices for version control, quality assurance, and team collaboration.

#### Git and Version Control

**Basic Git Operations:**

```bash
# Initialize repository
git init my-c-project
cd my-c-project

# Configure user (first time setup)
git config --global user.name "John Developer"
git config --global user.email "john@company.com"

# Create initial project structure
mkdir -p src include tests docs
touch src/main.c include/mylib.h tests/test_main.c README.md

# Stage and commit initial files¹
git add .
git commit -m "Initial project structure

- Added src/, include/, tests/, docs/ directories
- Created placeholder files for main components
- Added README.md for project documentation"
```

**Branching and Merging Workflow:**

```bash
# Create and switch to feature branch
git checkout -b feature/user-authentication
# Or using newer syntax:
git switch -c feature/user-authentication

# Make changes to files...
echo '#include "auth.h"' >> src/main.c

# Stage specific changes
git add src/main.c
git commit -m "Add authentication header include

- Include auth.h in main.c for user authentication
- Prepares for implementing login functionality"

# View commit history with graph
git log --oneline --graph --decorate

# Switch back to main branch
git checkout main
# Or: git switch main

# Merge feature branch²
git merge feature/user-authentication

# Clean up merged branch
git branch -d feature/user-authentication

# Push changes to remote repository
git push origin main
```

**Advanced Git Operations:**

```bash
# Interactive rebase to clean up commits³
git rebase -i HEAD~3  # Rebase last 3 commits

# Cherry-pick specific commit
git cherry-pick a1b2c3d4

# Create annotated tag for release
git tag -a v1.0.0 -m "Release version 1.0.0

Features:
- User authentication system
- Basic file operations
- Comprehensive test suite
- Documentation updates"

# Push tags to remote
git push --tags

# View difference between branches
git diff main..feature/new-feature

# Stash uncommitted changes
git stash push -m "Work in progress on optimization"

# Apply stashed changes later
git stash pop

# Show file history
git log --follow -- src/main.c

# Blame/annotate file to see who changed what
git blame src/main.c
```

**Git Flow Workflow Example:**

```bash
# Initialize git-flow in repository
git flow init

# Start new feature
git flow feature start user-management

# Work on feature...
echo "User management code" >> src/user.c
git add src/user.c
git commit -m "Implement basic user management"

# Finish feature (merges to develop)
git flow feature finish user-management

# Start release branch
git flow release start 1.1.0

# Make release preparations...
echo "Version 1.1.0" > VERSION
git add VERSION
git commit -m "Bump version to 1.1.0"

# Finish release (merges to main and develop)
git flow release finish 1.1.0

# Handle hotfix
git flow hotfix start security-patch
echo "Security fix" >> src/security.c
git add src/security.c
git commit -m "Fix security vulnerability in authentication"
git flow hotfix finish security-patch
```

**.gitignore for C Projects:**

```gitignore
# Object files
*.o
*.obj
*.elf

# Executables
*.exe
*.out
*.app
a.out

# Debug files
*.dSYM/
*.pdb

# Static and dynamic libraries
*.a
*.lib
*.so
*.dylib
*.dll

# Build directories
build/
bin/
obj/
dist/

# IDE files
.vscode/
.idea/
*.xcworkspace/

# OS generated files
.DS_Store
Thumbs.db

# Compiler output
*.i      # Preprocessor output
*.s      # Assembly output

# Coverage files
*.gcda
*.gcno
*.gcov
coverage.info
coverage/

# Memory debugging
valgrind-*.log
*.log

# Package manager
node_modules/
conan.lock
```

#### Continuous Integration and Deployment

**GitHub Actions CI Pipeline (.github/workflows/ci.yml):**

```yaml
name: CI Pipeline

# Trigger on push to main/develop and pull requests⁴
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  # Build and test job
  build-test:
    name: Build and Test
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        compiler: [gcc, clang]
        build-type: [Debug, Release]
    
    steps:
    # Checkout repository code
    - name: Checkout code
      uses: actions/checkout@v3
    
    # Install dependencies
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake valgrind
        sudo apt-get install -y clang-tidy cppcheck lcov
    
    # Configure build with CMake
    - name: Configure CMake
      run: |
        cmake -B build \
          -DCMAKE_BUILD_TYPE=${{ matrix.build-type }} \
          -DCMAKE_C_COMPILER=${{ matrix.compiler }} \
          -DENABLE_TESTING=ON \
          -DENABLE_COVERAGE=ON
    
    # Build project
    - name: Build
      run: cmake --build build --parallel $(nproc)
    
    # Run unit tests
    - name: Run Tests
      working-directory: build
      run: |
        ctest --output-on-failure --parallel $(nproc)
        
    # Generate coverage report (only for gcc debug builds)
    - name: Generate Coverage
      if: matrix.compiler == 'gcc' && matrix.build-type == 'Debug'
      working-directory: build
      run: |
        lcov --directory . --capture --output-file coverage.info
        lcov --remove coverage.info '/usr/*' --output-file coverage.info
        lcov --list coverage.info
        
    # Upload coverage to Codecov
    - name: Upload Coverage
      if: matrix.compiler == 'gcc' && matrix.build-type == 'Debug'
      uses: codecov/codecov-action@v3
      with:
        file: build/coverage.info
        
  # Static analysis job
  static-analysis:
    name: Static Analysis
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Install tools
      run: |
        sudo apt-get update
        sudo apt-get install -y clang-tidy cppcheck
        
    # Run clang-tidy
    - name: Run clang-tidy
      run: |
        find src -name "*.c" -exec clang-tidy {} \; \
          -checks='-*,readability-*,bugprone-*,clang-analyzer-*' \
          -- -Iinclude
          
    # Run cppcheck
    - name: Run cppcheck
      run: |
        cppcheck --enable=all --error-exitcode=1 \
          --suppress=missingIncludeSystem \
          --inline-suppr src/
          
  # Security scan job
  security-scan:
    name: Security Analysis
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: cpp
        
    - name: Build for analysis
      run: |
        cmake -B build -DCMAKE_BUILD_TYPE=Debug
        cmake --build build
        
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
```

**Docker-based Build Environment:**

```dockerfile
# Dockerfile for consistent build environment
FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    clang \
    clang-tidy \
    clang-format \
    cppcheck \
    valgrind \
    lcov \
    doxygen \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for building
RUN useradd -m -s /bin/bash developer
USER developer
WORKDIR /home/developer

# Set up environment
ENV CC=clang
ENV CXX=clang++

# Copy build script
COPY --chown=developer:developer build.sh /home/developer/
RUN chmod +x build.sh

ENTRYPOINT ["./build.sh"]
```

**Build Script (build.sh):**

```bash
#!/bin/bash
set -euo pipefail

# Professional build script with error handling
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
BUILD_TYPE="${BUILD_TYPE:-Release}"
ENABLE_TESTS="${ENABLE_TESTS:-ON}"
ENABLE_COVERAGE="${ENABLE_COVERAGE:-OFF}"

echo "🔨 Building C Project"
echo "  Project: ${PROJECT_DIR}"
echo "  Build Type: ${BUILD_TYPE}"
echo "  Tests: ${ENABLE_TESTS}"
echo "  Coverage: ${ENABLE_COVERAGE}"

# Clean build directory
if [ -d "${BUILD_DIR}" ]; then
    echo "🧹 Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
fi

# Configure with CMake
echo "⚙️  Configuring with CMake..."
cmake -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DENABLE_TESTING="${ENABLE_TESTS}" \
    -DENABLE_COVERAGE="${ENABLE_COVERAGE}" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build project
echo "🔨 Building project..."
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

# Run tests if enabled
if [ "${ENABLE_TESTS}" = "ON" ]; then
    echo "🧪 Running tests..."
    (cd "${BUILD_DIR}" && ctest --output-on-failure)
fi

# Generate coverage if enabled
if [ "${ENABLE_COVERAGE}" = "ON" ]; then
    echo "📊 Generating coverage report..."
    (cd "${BUILD_DIR}" && lcov --directory . --capture --output-file coverage.info)
    (cd "${BUILD_DIR}" && genhtml coverage.info --output-directory coverage)
    echo "📊 Coverage report generated in ${BUILD_DIR}/coverage/"
fi

echo "✅ Build completed successfully!"
```

#### Code Quality Tools

**clang-tidy Configuration (.clang-tidy):**

```yaml
---
Checks: >
  *,
  -llvmlibc-*,
  -altera-*,
  -fuchsia-*,
  -google-readability-todo,
  -readability-else-after-return,
  -readability-static-accessed-through-instance,
  -readability-avoid-const-params-in-decls,
  -cppcoreguidelines-init-variables,
  -cert-err33-c,
  -bugprone-easily-swappable-parameters,
  -clang-diagnostic-missing-prototypes

CheckOptions:
  - key: readability-identifier-naming.VariableCase
    value: snake_case
  - key: readability-identifier-naming.FunctionCase  
    value: snake_case
  - key: readability-identifier-naming.MacroCase
    value: UPPER_CASE
  - key: readability-identifier-naming.EnumCase
    value: CamelCase
  - key: readability-identifier-naming.StructCase
    value: CamelCase
  - key: misc-non-private-member-variables-in-classes.IgnoreClassesWithAllMemberVariablesBeingPublic
    value: true

WarningsAsErrors: ''
HeaderFilterRegex: '(src|include)/.*\.h#### Concepts ⚙
- Process creation with fork() and program replacement with exec()
- Inter-process communication mechanisms and their use cases
- Signal handling for asynchronous events
- Process synchronization and resource sharing

#### Errors ⚠
- Race conditions between parent and child processes
- Zombie processes from unreaped children
- Signal handling in multi-threaded environments
- Resource leaks in IPC mechanisms

#### Tips 🧠
- Always check return values from system calls
- Use waitpid() with WNOHANG to avoid blocking
- Implement proper signal handlers with sigaction
- Clean up IPC resources (shared memory, message queues, semaphores)

#### Tools 🔧
- **Process Monitoring**: ps, top, htop, pstree
- **IPC Analysis**: ipcs, ipcrm for System V IPC
- **Signal Debugging**: strace, ltrace
- **System Call Tracing**: strace -f for fork tracking

---

### 25. Advanced Concurrency & Parallelism {#advanced-concurrency}

**Figure Reference: [Threading Models Comparison Diagram]**

Modern C applications require efficient concurrency and parallelism to utilize multi-core systems effectively.

#### POSIX Threads (pthreads) Fundamentals

```c
/* pthreads_basics.c - POSIX threads fundamentals */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

// Thread function signature: void* (*start_routine)(void*)
void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    printf("Thread %d: Starting work (PID: %d, TID: %lu)\n", 
           thread_id, getpid(), pthread_self());
    
    // Simulate work
    for (int i = 0; i < 5; i++) {
        printf("Thread %d: Working... step %d\n", thread_id, i + 1);
        sleep(1);
    }
    
    // Return value (can be retrieved with pthread_join)
    int* result = malloc(sizeof(int));
    *result = thread_id * 100;
    
    printf("Thread %d: Completed work\n", thread_id);
    return result;
}

void basic_pthread_demo(void) {
    printf("=== Basic pthread Demo ===\n");
    
    const int num_threads = 3;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i + 1;
        
        int result = pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]);
        if (result != 0) {
            fprintf(stderr, "Error creating thread %d: %s\n", i, strerror(result));
            exit(1);
        }
        
        printf("Main: Created thread %d\n", i + 1);
    }
    
    // Wait for threads to complete and collect results
    for (int i = 0; i < num_threads; i++) {
        void* thread_result;
        int result = pthread_join(threads[i], &thread_result);
        
        if (result != 0) {
            fprintf(stderr, "Error joining thread %d: %s\n", i, strerror(result));
        } else {
            int* value = (int*)thread_result;
            printf("Main: Thread %d returned: %d\n", i + 1, *value);
            free(value);  // Clean up allocated result
        }
    }
    
    printf("Main: All threads completed\n");
}

// Thread attributes demonstration
void thread_attributes_demo(void) {
    printf("\n=== Thread Attributes Demo ===\n");
    
    pthread_t thread;
    pthread_attr_t attr;
    
    // Initialize thread attributes
    pthread_attr_init(&attr);
    
    // Set thread as detached¹
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    // Set stack size (default is usually 8MB on Linux)
    size_t stack_size = 1024 * 1024;  // 1MB
    pthread_attr_setstacksize(&attr, stack_size);
    
    // Get and display attributes
    int detach_state;
    size_t actual_stack_size;
    
    pthread_attr_getdetachstate(&attr, &detach_state);
    pthread_attr_getstacksize(&attr, &actual_stack_size);
    
    printf("Thread attributes:\n");
    printf("  Detach state: %s\n", 
           detach_state == PTHREAD_CREATE_DETACHED ? "Detached" : "Joinable");
    printf("  Stack size: %zu bytes\n", actual_stack_size);
    
    int thread_id = 99;
    int result = pthread_create(&thread, &attr, worker_thread, &thread_id);
    
    if (result == 0) {
        printf("Detached thread created successfully\n");
        // Note: Cannot join detached threads
        sleep(6);  // Give thread time to complete
    }
    
    // Clean up attributes
    pthread_attr_destroy(&attr);
}
```

**Footnote 1**: *Detached threads automatically clean up their resources when they terminate, but cannot be joined. This is useful for fire-and-forget tasks.*

#### Synchronization Primitives

```c
/* pthread_synchronization.c - Threading synchronization primitives */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

// Shared data structure
typedef struct {
    int counter;
    pthread_mutex_t mutex;          // Protects counter
    pthread_cond_t condition;       // Signals counter changes
    pthread_rwlock_t rwlock;        // Reader-writer lock for data
    int data[100];
    int data_ready;
} SharedData;

SharedData shared_data = {
    .counter = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER,
    .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    .data_ready = 0
};

// Mutex demonstration
void* mutex_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 1000; i++) {
        // Critical section - must be protected by mutex²
        pthread_mutex_lock(&shared_data.mutex);
        
        int old_value = shared_data.counter;
        shared_data.counter = old_value + 1;  // Non-atomic operation
        
        pthread_mutex_unlock(&shared_data.mutex);
        
        // Simulate some work outside critical section
        if (i % 100 == 0) {
            printf("Thread %d: counter = %d (iteration %d)\n", 
                   thread_id, shared_data.counter, i);
        }
    }
    
    return NULL;
}

void mutex_demo(void) {
    printf("=== Mutex Demo ===\n");
    
    const int num_threads = 4;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];
    
    printf("Starting %d threads, each incrementing counter 1000 times\n", num_threads);
    printf("Expected final counter value: %d\n", num_threads * 1000);
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i + 1;
        pthread_create(&threads[i], NULL, mutex_worker, &thread_ids[i]);
    }
    
    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Final counter value: %d\n", shared_data.counter);
    printf("Mutex prevented race conditions: %s\n", 
           shared_data.counter == num_threads * 1000 ? "YES" : "NO");
}

// Condition variable demonstration
void* producer_thread(void* arg) {
    printf("Producer: Generating data...\n");
    
    // Generate data
    pthread_rwlock_wrlock(&shared_data.rwlock);  // Write lock
    
    for (int i = 0; i < 100; i++) {
        shared_data.data[i] = i * i;  // Simple data: squares
    }
    
    pthread_rwlock_unlock(&shared_data.rwlock);
    
    // Signal that data is ready
    pthread_mutex_lock(&shared_data.mutex);
    shared_data.data_ready = 1;
    pthread_cond_broadcast(&shared_data.condition);  // Wake all waiters
    pthread_mutex_unlock(&shared_data.mutex);
    
    printf("Producer: Data ready, consumers notified\n");
    return NULL;
}

void* consumer_thread(void* arg) {
    int consumer_id = *(int*)arg;
    
    printf("Consumer %d: Waiting for data...\n", consumer_id);
    
    // Wait for data to be ready³
    pthread_mutex_lock(&shared_data.mutex);
    while (!shared_data.data_ready) {
        pthread_cond_wait(&shared_data.condition, &shared_data.mutex);
    }
    pthread_mutex_unlock(&shared_data.mutex);
    
    printf("Consumer %d: Data available, processing...\n", consumer_id);
    
    // Read data (multiple readers can read simultaneously)
    pthread_rwlock_rdlock(&shared_data.rwlock);  // Read lock
    
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += shared_data.data[i];
    }
    
    pthread_rwlock_unlock(&shared_data.rwlock);
    
    printf("Consumer %d: Sum of data = %d\n", consumer_id, sum);
    return NULL;
}

void condition_variable_demo(void) {
    printf("\n=== Condition Variable & RWLock Demo ===\n");
    
    pthread_t producer;
    pthread_t consumers[3];
    int consumer_ids[] = {1, 2, 3};
    
    // Reset data_ready flag
    shared_data.data_ready = 0;
    
    // Create consumer threads first
    for (int i = 0; i < 3; i++) {
        pthread_create(&consumers[i], NULL, consumer_thread, &consumer_ids[i]);
    }
    
    sleep(1);  // Let consumers start waiting
    
    // Create producer thread
    pthread_create(&producer, NULL, producer_thread, NULL);
    
    // Wait for all threads
    pthread_join(producer, NULL);
    for (int i = 0; i < 3; i++) {
        pthread_join(consumers[i], NULL);
    }
}
```

**Footnote 2**: *The mutex ensures atomicity of the increment operation. Without it, multiple threads could read the same value, increment it, and write back the same result, causing lost updates.*

**Footnote 3**: *pthread_cond_wait() atomically unlocks the mutex and waits for the condition. When signaled, it re-acquires the mutex before returning. This prevents race conditions in the wait-signal pattern.*

#### Thread Barriers and Advanced Synchronization

```c
/* advanced_sync.c - Advanced synchronization primitives */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

// Barrier demonstration⁴
pthread_barrier_t sync_barrier;
int barrier_thread_count = 4;

void* barrier_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    printf("Thread %d: Starting phase 1\n", thread_id);
    sleep(thread_id);  // Different work times
    printf("Thread %d: Completed phase 1\n", thread_id);
    
    // Wait for all threads to complete phase 1
    printf("Thread %d: Waiting at barrier\n", thread_id);
    int result = pthread_barrier_wait(&sync_barrier);
    
    if (result == PTHREAD_BARRIER_SERIAL_THREAD) {
        printf("Thread %d: Last thread to reach barrier\n", thread_id);
    }
    
    printf("Thread %d: Starting phase 2\n", thread_id);
    sleep(1);
    printf("Thread %d: Completed phase 2\n", thread_id);
    
    return NULL;
}

void barrier_demo(void) {
    printf("\n=== Barrier Demo ===\n");
    
    // Initialize barrier for 4 threads
    pthread_barrier_init(&sync_barrier, NULL, barrier_thread_count);
    
    pthread_t threads[4];
    int thread_ids[] = {1, 2, 3, 4};
    
    printf("Creating %d threads with different work times\n", barrier_thread_count);
    
    for (int i = 0; i < barrier_thread_count; i++) {
        pthread_create(&threads[i], NULL, barrier_worker, &thread_ids[i]);
    }
    
    for (int i = 0; i < barrier_thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    pthread_barrier_destroy(&sync_barrier);
    printf("All threads synchronized and completed\n");
}

// Spinlock demonstration (busy-waiting)
pthread_spinlock_t spinlock;
volatile int spin_counter = 0;

void* spinlock_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 100000; i++) {
        pthread_spin_lock(&spinlock);
        spin_counter++;
        pthread_spin_unlock(&spinlock);
    }
    
    return NULL;
}

void spinlock_demo(void) {
    printf("\n=== Spinlock Demo ===\n");
    
    pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
    
    const int num_threads = 2;
    pthread_t threads[num_threads];
    int thread_ids[] = {1, 2};
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, spinlock_worker, &thread_ids[i]);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    gettimeofday(&end, NULL);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Spinlock result: counter = %d (expected: %d)\n", 
           spin_counter, num_threads * 100000);
    printf("Elapsed time: %.4f seconds\n", elapsed);
    
    pthread_spin_destroy(&spinlock);
}
```

**Footnote 4**: *Barriers synchronize multiple threads at a specific point. All threads must reach the barrier before any can proceed. This is useful for parallel algorithms with distinct phases.*

#### Thread Pool Implementation

```c
/* thread_pool.c - Professional thread pool implementation */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

// Task structure
typedef struct Task {
    void (*function)(void* arg);  // Task function
    void* argument;               // Task argument  
    struct Task* next;           // Next task in queue
} Task;

// Thread pool structure
typedef struct {
    pthread_t* threads;          // Array of worker threads
    Task* task_queue_head;       // Head of task queue
    Task* task_queue_tail;       // Tail of task queue
    pthread_mutex_t queue_mutex; // Protects task queue
    pthread_cond_t queue_cond;   // Signals new tasks
    pthread_cond_t done_cond;    // Signals task completion
    int thread_count;            // Number of worker threads
    int active_tasks;            // Number of active tasks
    int total_tasks;             // Total tasks in queue
    bool shutdown;               // Shutdown flag
} ThreadPool;

// Worker thread function
void* thread_pool_worker(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;
    
    while (true) {
        pthread_mutex_lock(&pool->queue_mutex);
        
        // Wait for tasks or shutdown signal
        while (pool->task_queue_head == NULL && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex);
        }
        
        // Check for shutdown
        if (pool->shutdown && pool->task_queue_head == NULL) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }
        
        // Get next task from queue
        Task* task = pool->task_queue_head;
        if (task != NULL) {
            pool->task_queue_head = task->next;
            if (pool->task_queue_head == NULL) {
                pool->task_queue_tail = NULL;
            }
            pool->total_tasks--;
            pool->active_tasks++;
        }
        
        pthread_mutex_unlock(&pool->queue_mutex);
        
        // Execute task
        if (task != NULL) {
            task->function(task->argument);
            free(task);
            
            // Mark task as completed
            pthread_mutex_lock(&pool->queue_mutex);
            pool->active_tasks--;
            if (pool->active_tasks == 0 && pool->total_tasks == 0) {
                pthread_cond_signal(&pool->done_cond);
            }
            pthread_mutex_unlock(&pool->queue_mutex);
        }
    }
    
    return NULL;
}

// Create thread pool
ThreadPool* thread_pool_create(int thread_count) {
    if (thread_count <= 0) return NULL;
    
    ThreadPool* pool = malloc(sizeof(ThreadPool));
    if (!pool) return NULL;
    
    // Initialize pool structure
    pool->threads = malloc(thread_count * sizeof(pthread_t));
    pool->task_queue_head = NULL;
    pool->task_queue_tail = NULL;
    pool->thread_count = thread_count;
    pool->active_tasks = 0;
    pool->total_tasks = 0;
    pool->shutdown = false;
    
    // Initialize synchronization primitives
    pthread_mutex_init(&pool->queue_mutex, NULL);
    pthread_cond_init(&pool->queue_cond, NULL);
    pthread_cond_init(&pool->done_cond, NULL);
    
    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool) != 0) {
            // Handle thread creation failure
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    
    return pool;
}

// Submit task to thread pool
int thread_pool_submit(ThreadPool* pool, void (*function)(void*), void* argument) {
    if (!pool || !function) return -1;
    
    Task* task = malloc(sizeof(Task));
    if (!task) return -1;
    
    task->function = function;
    task->argument = argument;
    task->next = NULL;
    
    pthread_mutex_lock(&pool->queue_mutex);
    
    if (pool->shutdown) {
        free(task);
        pthread_mutex_unlock(&pool->queue_mutex);
        return -1;
    }
    
    // Add task to queue
    if (pool->task_queue_tail == NULL) {
        pool->task_queue_head = pool->task_queue_tail = task;
    } else {
        pool->task_queue_tail->next = task;
        pool->task_queue_tail = task;
    }
    
    pool->total_tasks++;
    
    // Signal worker threads
    pthread_cond_signal(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return 0;
}

// Wait for all tasks to complete
void thread_pool_wait(ThreadPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    while (pool->active_tasks > 0 || pool->total_tasks > 0) {
        pthread_cond_wait(&pool->done_cond, &pool->queue_mutex);
    }
    pthread_mutex_unlock(&pool->queue_mutex);
}

// Destroy thread pool
void thread_pool_destroy(ThreadPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    // Wait for worker threads to finish
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    // Clean up remaining tasks
    Task* current = pool->task_queue_head;
    while (current != NULL) {
        Task* next = current->next;
        free(current);
        current = next;
    }
    
    // Clean up synchronization primitives
    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_cond);
    pthread_cond_destroy(&pool->done_cond);
    
    free(pool->threads);
    free(pool);
}

// Example task functions
void cpu_intensive_task(void* arg) {
    int task_id = *(int*)arg;
    printf("Task %d: Starting CPU-intensive work\n", task_id);
    
    // Simulate CPU work
    volatile long sum = 0;
    for (long i = 0; i < 1000000; i++) {
        sum += i;
    }
    
    printf("Task %d: Completed (sum = %ld)\n", task_id, sum);
}

void io_task(void* arg) {
    int task_id = *(int*)arg;
    printf("Task %d: Simulating I/O operation\n", task_id);
    
    // Simulate I/O delay
    sleep(1);
    
    printf("Task %d: I/O operation completed\n", task_id);
}

void thread_pool_demo(void) {
    printf("=== Thread Pool Demo ===\n");
    
    // Create thread pool with 4 worker threads
    ThreadPool* pool = thread_pool_create(4);
    if (!pool) {
        printf("Failed to create thread pool\n");
        return;
    }
    
    printf("Created thread pool with 4 worker threads\n");
    
    // Submit CPU-intensive tasks
    int cpu_task_ids[] = {1, 2, 3, 4, 5};
    for (int i = 0; i < 5; i++) {
        thread_pool_submit(pool, cpu_intensive_task, &cpu_task_ids[i]);
    }
    
    // Submit I/O tasks
    int io_task_ids[] = {10, 11, 12};
    for (int i = 0; i < 3; i++) {
        thread_pool_submit(pool, io_task, &io_task_ids[i]);
    }
    
    printf("Submitted 8 tasks total\n");
    
    // Wait for all tasks to complete
    thread_pool_wait(pool);
    printf("All tasks completed\n");
    
    // Clean up
    thread_pool_destroy(pool);
    printf("Thread pool destroyed\n");
}
```

#### Parallel Algorithms

```c
/* parallel_algorithms.c - Map-Reduce style parallel processing */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

// Parallel map operation⁵
typedef struct {
    double* input_array;
    double* output_array;
    int start_index;
    int end_index;
    double (*map_function)(double);
} MapTask;

// Example map functions
double square_function(double x) {
    return x * x;
}

double sqrt_function(double x) {
    return sqrt(x);
}

void* parallel_map_worker(void* arg) {
    MapTask* task = (MapTask*)arg;
    
    for (int i = task->start_index; i < task->end_index; i++) {
        task->output_array[i] = task->map_function(task->input_array[i]);
    }
    
    return NULL;
}

void parallel_map(double* input, double* output, int size, int num_threads, 
                 double (*map_func)(double)) {
    if (num_threads <= 0 || size <= 0) return;
    
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    MapTask* tasks = malloc(num_threads * sizeof(MapTask));
    
    int chunk_size = size / num_threads;
    int remainder = size % num_threads;
    
    // Create and start worker threads
    for (int i = 0; i < num_threads; i++) {
        tasks[i].input_array = input;
        tasks[i].output_array = output;
        tasks[i].map_function = map_func;
        tasks[i].start_index = i * chunk_size;
        tasks[i].end_index = (i + 1) * chunk_size;
        
        // Distribute remainder among first threads
        if (i < remainder) {
            tasks[i].end_index++;
        }
        if (i > 0 && i <= remainder) {
            tasks[i].start_index++;
            tasks[i].end_index++;
        }
        
        pthread_create(&threads[i], NULL, parallel_map_worker, &tasks[i]);
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    free(tasks);
}

// Parallel reduce operation
typedef struct {
    double* array;
    int start_index;
    int end_index;
    double result;
    double (*reduce_function)(double, double);
} ReduceTask;

double sum_function(double a, double b) {
    return a + b;
}

double max_function(double a, double b) {
    return a > b ? a : b;
}

void* parallel_reduce_worker(void* arg) {
    ReduceTask* task = (ReduceTask*)arg;
    
    if (task->start_index >= task->end_index) {
        task->result = 0.0;  // Identity for sum
        return NULL;
    }
    
    task->result = task->array[task->start_index];
    for (int i = task->start_index + 1; i < task->end_index; i++) {
        task->result = task->reduce_function(task->result, task->array[i]);
    }
    
    return NULL;
}

double parallel_reduce(double* array, int size, int num_threads,
                      double (*reduce_func)(double, double)) {
    if (num_threads <= 0 || size <= 0) return 0.0;
    
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    ReduceTask* tasks = malloc(num_threads * sizeof(ReduceTask));
    
    int chunk_size = size / num_threads;
    
    // Create and start worker threads
    for (int i = 0; i < num_threads; i++) {
        tasks[i].array = array;
        tasks[i].reduce_function = reduce_func;
        tasks[i].start_index = i * chunk_size;
        tasks[i].end_index = (i + 1) * chunk_size;
        
        // Last thread handles remainder
        if (i == num_threads - 1) {
            tasks[i].end_index = size;
        }
        
        pthread_create(&threads[i], NULL, parallel_reduce_worker, &tasks[i]);
    }
    
    // Wait for all threads and combine results
    double final_result = 0.0;
    bool first_result = true;
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        
        if (tasks[i].start_index < tasks[i].end_index) {  // Thread had work to do
            if (first_result) {
                final_result = tasks[i].result;
                first_result = false;
            } else {
                final_result = reduce_func(final_result, tasks[i].result);
            }
        }
    }
    
    free(threads);
    free(tasks);
    
    return final_result;
}

void parallel_algorithms_demo(void) {
    printf("=== Parallel Algorithms Demo ===\n");
    
    const int array_size = 1000000;
    const int num_threads = 4;
    
    // Create test data
    double* input_data = malloc(array_size * sizeof(double));
    double* output_data = malloc(array_size * sizeof(double));
    
    for (int i = 0; i < array_size; i++) {
        input_data[i] = (double)(i + 1);
    }
    
    printf("Processing array of %d elements with %d threads\n", 
           array_size, num_threads);
    
    // Parallel map: square all elements
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    parallel_map(input_data, output_data, array_size, num_threads, square_function);
    
    gettimeofday(&end, NULL);
    double map_time = (end.tv_sec - start.tv_sec) + 
                     (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Parallel map (square) completed in %.4f seconds\n", map_time);
    
    // Verify first few results
    printf("First 5 squared values: ");
    for (int i = 0; i < 5; i++) {
        printf("%.0f ", output_data[i]);
    }
    printf("\n");
    
    // Parallel reduce: sum all squared values
    gettimeofday(&start, NULL);
    
    double sum = parallel_reduce(output_data, array_size, num_threads, sum_function);
    
    gettimeofday(&end, NULL);
    double reduce_time = (end.tv_sec - start.tv_sec) + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Parallel reduce (sum) completed in %.4f seconds\n", reduce_time);
    printf("Sum of squares: %.0f\n", sum);
    
    // Find maximum value
    double max_value = parallel_reduce(output_data, array_size, num_threads, max_function);
    printf("Maximum value: %.0f\n", max_value);
    
    free                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Echo back the message that came in
                    buffer[valread] = '\0';
                    printf("Received: %s", buffer);
                    send(sd, buffer, strlen(buffer), 0);
                }
            }
        }
    }
    
    close(server_fd);
}

// UDP Server implementation
void udp_server_demo(int port) {
    int server_fd;
    char buffer[1024];
    struct sockaddr_in servaddr, cliaddr;
    
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    
    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);
    
    // Bind the socket with the server address
    if (bind(server_fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    printf("UDP Server listening on port %d\n", port);
    
    socklen_t len = sizeof(cliaddr);
    
    while (1) {
        int n = recvfrom(server_fd, (char *)buffer, 1024,
                        MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';
        printf("Client: %s\n", buffer);
        
        // Echo back
        sendto(server_fd, buffer, strlen(buffer),
               MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
    }
    
    close(server_fd);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "tcp") == 0) {
        run_echo_server(8080);
    } else if (argc > 1 && strcmp(argv[1], "udp") == 0) {
        udp_server_demo(8081);
    } else {
        printf("Usage: %s [tcp|udp]\n", argv[0]);
    }
    
    return 0;
}
```

#### Concepts ⚙
- Socket programming fundamentals
- TCP vs UDP protocol differences
- Non-blocking I/O with select/poll/epoll
- Network byte order and endianness

#### Errors ⚠
- Not handling partial sends/receives
- Ignoring network byte order conversions
- Resource leaks with unclosed sockets
- Race conditions in multi-threaded servers

#### Tips 🧠
- Always use non-blocking I/O for scalable servers
- Implement proper error handling and retry logic
- Consider using higher-level libraries for complex protocols
- Test network code with various failure scenarios

#### Tools 🔧
- **Network Analysis**: Wireshark, tcpdump, netstat
- **Load Testing**: Apache Bench (ab), wrk, siege
- **Debugging**: strace, ltrace for system call tracing
- **Performance**: iperf, netperf for throughput testing

---

## Part IV: Special Sections

### 24. System Programming {#system-programming}

**Figure Reference: [Unix Process Hierarchy Diagram]**

System programming involves low-level interaction with the operating system, managing processes, and inter-process communication.

#### Process Management

```c
/* process_management.c - Process creation and management */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

void basic_fork_demo(void) {
    printf("=== Basic Fork Demo ===\n");
    printf("Before fork: PID = %d\n", getpid());
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process: PID = %d, Parent PID = %d\n", 
               getpid(), getppid());
        printf("Child: Doing some work...\n");
        sleep(2);
        printf("Child: Work completed\n");
        exit(42);  // Child exits with status 42
    } else {
        // Parent process
        printf("Parent process: PID = %d, Child PID = %d\n", 
               getpid(), pid);
        
        int status;
        pid_t child_pid = wait(&status);
        
        printf("Parent: Child %d terminated\n", child_pid);
        if (WIFEXITED(status)) {
            printf("Parent: Child exit status = %d\n", WEXITSTATUS(status));
        }
    }
}

// Process creation with exec family
void fork_exec_demo(void) {
    printf("\n=== Fork + Exec Demo ===\n");
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return;
    } else if (pid == 0) {
        // Child process - replace with new program
        printf("Child: About to exec 'ls -l'\n");
        
        // Replace process image with 'ls' command
        execlp("ls", "ls", "-l", ".", NULL);
        
        // This line should never be reached if exec succeeds
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        printf("Parent: Waiting for child to complete 'ls' command\n");
        
        int status;
        waitpid(pid, &status, 0);
        printf("Parent: Child completed\n");
    }
}

// Advanced process management
typedef struct {
    pid_t pid;
    char command[256];
    time_t start_time;
    int status;
    enum { PROC_RUNNING, PROC_FINISHED, PROC_FAILED } state;
} ProcessInfo;

#define MAX_PROCESSES 10
ProcessInfo processes[MAX_PROCESSES];
int process_count = 0;

int start_background_process(const char *command) {
    if (process_count >= MAX_PROCESSES) {
        printf("Process limit reached\n");
        return -1;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return -1;
    } else if (pid == 0) {
        // Child process - execute command
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process - record process info
        ProcessInfo *proc = &processes[process_count];
        proc->pid = pid;
        strncpy(proc->command, command, sizeof(proc->command) - 1);
        proc->command[sizeof(proc->command) - 1] = '\0';
        proc->start_time = time(NULL);
        proc->state = PROC_RUNNING;
        
        printf("Started process %d: %s\n", pid, command);
        return process_count++;
    }
}

void check_processes(void) {
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *proc = &processes[i];
        
        if (proc->state == PROC_RUNNING) {
            int status;
            pid_t result = waitpid(proc->pid, &status, WNOHANG);
            
            if (result == proc->pid) {
                // Process finished
                proc->status = status;
                proc->state = WIFEXITED(status) ? PROC_FINISHED : PROC_FAILED;
                
                printf("Process %d (%s) %s\n", 
                       proc->pid, proc->command,
                       proc->state == PROC_FINISHED ? "completed" : "failed");
            } else if (result == -1) {
                perror("waitpid");
                proc->state = PROC_FAILED;
            }
            // result == 0 means process is still running
        }
    }
}

void process_manager_demo(void) {
    printf("\n=== Process Manager Demo ===\n");
    
    // Start some background processes
    start_background_process("sleep 3 && echo 'Task 1 completed'");
    start_background_process("ls -la /tmp > /dev/null");
    start_background_process("echo 'Quick task' && sleep 1");
    
    // Monitor processes
    for (int i = 0; i < 10; i++) {
        check_processes();
        sleep(1);
        
        // Check if all processes are done
        int running_count = 0;
        for (int j = 0; j < process_count; j++) {
            if (processes[j].state == PROC_RUNNING) {
                running_count++;
            }
        }
        
        if (running_count == 0) {
            printf("All processes completed\n");
            break;
        }
    }
}
```

#### Inter-Process Communication (IPC)

**Pipes and Named Pipes:**

```c
/* ipc_pipes.c - Pipe-based inter-process communication */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

void anonymous_pipe_demo(void) {
    printf("=== Anonymous Pipe Demo ===\n");
    
    int pipefd[2];  // pipe file descriptors: [0] = read, [1] = write
    pid_t pid;
    char buffer[100];
    
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }
    
    pid = fork();
    
    if (pid == -1) {
        perror("fork");
        return;
    } else if (pid == 0) {
        // Child process - writer
        close(pipefd[0]);  // Close unused read end
        
        const char *message = "Hello from child process!";
        printf("Child: Sending message: %s\n", message);
        
        write(pipefd[1], message, strlen(message) + 1);
        close(pipefd[1]);
        exit(0);
    } else {
        // Parent process - reader
        close(pipefd[1]);  // Close unused write end
        
        printf("Parent: Waiting for message...\n");
        ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("Parent: Received: %s\n", buffer);
        }
        
        close(pipefd[0]);
        wait(NULL);  // Wait for child to finish
    }
}

void named_pipe_demo(void) {
    printf("\n=== Named Pipe (FIFO) Demo ===\n");
    
    const char *fifo_path = "/tmp/demo_fifo";
    
    // Create named pipe
    if (mkfifo(fifo_path, 0666) == -1) {
        perror("mkfifo");
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        unlink(fifo_path);
        return;
    } else if (pid == 0) {
        // Child process - writer
        sleep(1);  // Ensure parent is ready to read
        
        int fd = open(fifo_path, O_WRONLY);
        if (fd == -1) {
            perror("open fifo for writing");
            exit(1);
        }
        
        const char *message = "Message through named pipe";
        printf("Child: Writing to FIFO: %s\n", message);
        write(fd, message, strlen(message) + 1);
        close(fd);
        exit(0);
    } else {
        // Parent process - reader
        int fd = open(fifo_path, O_RDONLY);
        if (fd == -1) {
            perror("open fifo for reading");
            unlink(fifo_path);
            return;
        }
        
        char buffer[100];
        printf("Parent: Reading from FIFO...\n");
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("Parent: Received: %s\n", buffer);
        }
        
        close(fd);
        wait(NULL);
        unlink(fifo_path);  // Clean up
    }
}
```

**Shared Memory:**

```c
/* ipc_shared_memory.c - Shared memory IPC */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <string.h>

typedef struct {
    int counter;
    char message[100];
    int ready;
} SharedData;

void shared_memory_demo(void) {
    printf("=== Shared Memory Demo ===\n");
    
    // Create shared memory segment
    key_t key = ftok(".", 'A');  // Generate key
    int shmid = shmget(key, sizeof(SharedData), IPC_CREAT | 0666);
    
    if (shmid == -1) {
        perror("shmget");
        return;
    }
    
    // Attach shared memory
    SharedData *shared_data = (SharedData *)shmat(shmid, NULL, 0);
    if (shared_data == (SharedData *)-1) {
        perror("shmat");
        return;
    }
    
    // Initialize shared data
    shared_data->counter = 0;
    strcpy(shared_data->message, "Initial message");
    shared_data->ready = 0;
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        shmdt(shared_data);
        shmctl(shmid, IPC_RMID, NULL);
        return;
    } else if (pid == 0) {
        // Child process
        printf("Child: Modifying shared data...\n");
        
        shared_data->counter = 42;
        strcpy(shared_data->message, "Message from child process");
        shared_data->ready = 1;
        
        printf("Child: Data updated\n");
        
        // Detach shared memory
        shmdt(shared_data);
        exit(0);
    } else {
        // Parent process
        printf("Parent: Waiting for child to update data...\n");
        
        // Poll for data to be ready
        while (!shared_data->ready) {
            usleep(100000);  // Sleep 100ms
        }
        
        printf("Parent: Shared data received:\n");
        printf("  Counter: %d\n", shared_data->counter);
        printf("  Message: %s\n", shared_data->message);
        
        wait(NULL);
        
        // Detach and remove shared memory
        shmdt(shared_data);
        shmctl(shmid, IPC_RMID, NULL);
    }
}
```

**Message Queues and Semaphores:**

```c
/* ipc_msgqueue_semaphore.c - Message queues and semaphores */
#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

// Message structure
typedef struct {
    long mtype;  // Message type
    char mtext[100];  // Message data
} Message;

void message_queue_demo(void) {
    printf("=== Message Queue Demo ===\n");
    
    key_t key = ftok(".", 'B');
    int msgid = msgget(key, IPC_CREAT | 0666);
    
    if (msgid == -1) {
        perror("msgget");
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        msgctl(msgid, IPC_RMID, NULL);
        return;
    } else if (pid == 0) {
        // Child process - sender
        Message msg;
        msg.mtype = 1;  // Message type 1
        strcpy(msg.mtext, "Hello from child via message queue");
        
        printf("Child: Sending message...\n");
        if (msgsnd(msgid, &msg, strlen(msg.mtext) + 1, 0) == -1) {
            perror("msgsnd");
        } else {
            printf("Child: Message sent successfully\n");
        }
        
        exit(0);
    } else {
        // Parent process - receiver
        Message msg;
        
        printf("Parent: Waiting for message...\n");
        if (msgrcv(msgid, &msg, sizeof(msg.mtext), 1, 0) == -1) {
            perror("msgrcv");
        } else {
            printf("Parent: Received message: %s\n", msg.mtext);
        }
        
        wait(NULL);
        msgctl(msgid, IPC_RMID, NULL);  // Remove message queue
    }
}

// Semaphore operations
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

void semaphore_demo(void) {
    printf("\n=== Semaphore Demo ===\n");
    
    key_t key = ftok(".", 'C');
    int semid = semget(key, 1, IPC_CREAT | 0666);
    
    if (semid == -1) {
        perror("semget");
        return;
    }
    
    // Initialize semaphore to 1 (binary semaphore/mutex)
    union semun sem_union;
    sem_union.val = 1;
    if (semctl(semid, 0, SETVAL, sem_union) == -1) {
        perror("semctl");
        semctl(semid, 0, IPC_RMID);
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        semctl(semid, 0, IPC_RMID);
        return;
    } else if (pid == 0) {
        // Child process
        struct sembuf sem_op;
        
        printf("Child: Acquiring semaphore...\n");
        sem_op.sem_num = 0;
        sem_op.sem_op = -1;  // P operation (acquire)
        sem_op.sem_flg = 0;
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
            exit(1);
        }
        
        printf("Child: Semaphore acquired, doing critical work...\n");
        sleep(3);  // Simulate work
        printf("Child: Critical work done\n");
        
        printf("Child: Releasing semaphore...\n");
        sem_op.sem_op = 1;  // V operation (release)
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
            exit(1);
        }
        
        printf("Child: Semaphore released\n");
        exit(0);
    } else {
        // Parent process
        sleep(1);  // Let child acquire first
        
        struct sembuf sem_op;
        
        printf("Parent: Trying to acquire semaphore...\n");
        sem_op.sem_num = 0;
        sem_op.sem_op = -1;  // P operation (acquire)
        sem_op.sem_flg = 0;
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
        } else {
            printf("Parent: Semaphore acquired after child released it\n");
            
            printf("Parent: Releasing semaphore...\n");
            sem_op.sem_op = 1;  // V operation (release)
            semop(semid, &sem_op, 1);
        }
        
        wait(NULL);
        semctl(semid, 0, IPC_RMID);  // Remove semaphore
    }
}
```

#### Advanced Signal Handling

```c
/* advanced_signals.c - Advanced signal handling */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

// Global flag for signal handling (sig_atomic_t is guaranteed atomic)
static volatile sig_atomic_t signal_received = 0;
static volatile sig_atomic_t child_count = 0;

// Simple signal handler
void simple_signal_handler(int sig) {
    signal_received = sig;
    // Note: Only async-signal-safe functions should be called here
    write(STDERR_FILENO, "Signal received\n", 16);
}

// Advanced signal handler with sigaction
void advanced_signal_handler(int sig, siginfo_t *info, void *context) {
    char msg[100];
    int len;
    
    switch (sig) {
        case SIGCHLD:
            // Child process terminated
            len = snprintf(msg, sizeof(msg), 
                          "Child process %d terminated\n", info->si_pid);
            write(STDERR_FILENO, msg, len);
            child_count--;
            break;
            
        case SIGINT:
            len = snprintf(msg, sizeof(msg), 
                          "SIGINT received from PID %d\n", info->si_pid);
            write(STDERR_FILENO, msg, len);
            signal_received = sig;
            break;
            
        case SIGUSR1:
            len = snprintf(msg, sizeof(msg), 
                          "SIGUSR1 received with value %d\n", info->si_value.sival_int);
            write(STDERR_FILENO, msg, len);
            break;
    }
}

void signal_handling_demo(void) {
    printf("=== Advanced Signal Handling Demo ===\n");
    
    // Set up advanced signal handling with sigaction
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_sigaction = advanced_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    
    // Install signal handlers
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    
    printf("Signal handlers installed\n");
    printf("PID: %d (send signals to this process)\n", getpid());
    
    // Create some child processes
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process
            printf("Child %d: PID %d, sleeping for %d seconds\n", 
                   i, getpid(), (i + 1) * 2);
            sleep((i + 1) * 2);
            printf("Child %d: Exiting\n", i);
            exit(i);
        } else if (pid > 0) {
            child_count++;
            printf("Created child %d with PID %d\n", i, pid);
        }
    }
    
    // Wait for signals
    printf("Parent: Waiting for signals... (Ctrl+C to interrupt)\n");
    
    while (child_count > 0 && signal_received != SIGINT) {
        pause();  // Wait for signals
        
        // Reap any zombie children
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            printf("Reaped child %d with status %d\n", pid, status);
        }
    }
    
    if (signal_received == SIGINT) {
        printf("\nInterrupted by SIGINT\n");
        // Kill any remaining children
        signal(SIGCHLD, SIG_IGN);  // Ignore SIGCHLD to avoid handlers
        kill(0, SIGTERM);  // Send SIGTERM to process group
    }
    
    printf("Signal handling demo completed\n");
}

// Signal-safe data structures and operations
typedef struct {
    volatile sig_atomic_t count;
    volatile sig_atomic_t max_count;
} SafeCounter;

SafeCounter safe_counter = {0, 100};

void counter_signal_handler(int sig) {
    if (sig == SIGUSR1) {
        if (safe_counter.count < safe_counter.max_count) {
            safe_counter.count++;
        }
    } else if (sig == SIGUSR2) {
        if (safe_counter.count > 0) {
            safe_counter.count--;
        }
    }
}

void signal_safe_demo(void) {
    printf("\n=== Signal-Safe Programming Demo ===\n");
    
    signal(SIGUSR1, counter_signal_handler);  // Increment counter
    signal(SIGUSR2, counter_signal_handler);  // Decrement counter
    
    printf("PID: %d\n", getpid());
    printf("Send SIGUSR1 to increment, SIGUSR2 to decrement\n");
    printf("Example: kill -USR1 %d\n", getpid());
    
    for (int i = 0; i < 20; i++) {
        printf("Counter: %d\n", safe_counter.count);
        sleep(1);
        
        // Self-test: send some signals
        if (i % 3 == 0) {
            kill(getpid(), SIGUSR1);
        } else if (i % 5 == 0) {
            kill(getpid(), SIGUSR2);
        }
    }
}
```

#### Real-World Example: Simple Shell

```c
/* simple_shell.c - Basic shell implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_COMMAND_LENGTH 1024
#define MAX_ARGS 64

// Built-in commands
int builtin_cd(char **args);
int builtin_exit(char **args);
int builtin_help(char **args);

// Built-in command names and functions
char *builtin_commands[] = {"cd", "exit", "help"};
int (*builtin_functions[])(char **) = {&builtin_cd, &builtin_exit, &builtin_help};

int builtin_count(void) {
    return sizeof(builtin_commands) / sizeof(char *);
}

int builtin_cd(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "cd: expected argument\n");
    } else {
        if (chdir(args[1]) != 0) {
            perror("cd");
        }
    }
    return 1;  // Continue shell
}

int builtin_exit(char **args) {
    return 0;  // Exit shell
}

int builtin_help(char **args) {
    printf("Simple Shell\n");
    printf("Built-in commands:\n");
    for (int i = 0; i < builtin_count(); i++) {
        printf("  %s\n", builtin_commands[i]);
    }
    printf("Use 'man' for information on other programs.\n");
    return 1;
}

// Parse command line into arguments
char **parse_line(char *line) {
    int position = 0;
    char **tokens = malloc(MAX_ARGS * sizeof(char *));
    char *token;
    
    if (!tokens) {
        fprintf(stderr, "allocation error\n");
        exit(EXIT_FAILURE);
    }
    
    token = strtok(line, " \t\r\n\a");
    while (token != NULL) {
        tokens[position] = token;
        position++;
        
        if (position >= MAX_ARGS) {
            fprintf(stderr, "too many arguments\n");
            break;
        }
        
        token = strtok(NULL, " \t\r\n\a");
    }
    tokens[position] = NULL;
    return tokens;
}

// Execute built-in or external command
int execute(char **args) {
    if (args[0] == NULL) {
        return 1;  // Empty command
    }
    
    // Check for built-in commands
    for (int i = 0; i < builtin_count(); i++) {
        if (strcmp(args[0], builtin_commands[i]) == 0) {
            return (*builtin_functions[i])(args);
        }
    }
    
    // Execute external command
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        if (execvp(args[0], args) == -1) {
            perror("shell");
        }
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        perror("shell");
    } else {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);
    }
    
    return 1;
}

// Main shell loop
void shell_loop(void) {
    char *line;
    char **args;
    int status = 1;
    
    do {
        printf("simple_shell> ");
        
        // Read command
        line = malloc(MAX_COMMAND_LENGTH);
        if (fgets(line, MAX_COMMAND_LENGTH, stdin) == NULL) {
            break;  // EOF
        }
        
        // Parse and execute
        args = parse_line(line);
        status = execute(args);
        
        free(line);
        free(args);
    } while (status);
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nUse 'exit' to quit the shell\n");
        printf("simple_shell> ");
        fflush(stdout);
    }
}

int main(void) {
    // Install signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    printf("Simple Shell Started (type 'help' for commands)\n");
    shell_loop();
    printf("Shell exited\n");
    
    return 0;
}
```

#### Concepts ⚙
- Process creation with fork() and program replacement with exec()
- Inter-process communication mechanisms and their use cases
- Signal handling for asynchronous events
- Process synchronization and resource sharing

#### Errors ⚠
- Race    printf("Loop optimization results:\n");
    printf("  Standard loop:     %.4f seconds (sum: %ld)\n", time1, sum1);
    printf("  Unrolled loop:     %.4f seconds (sum: %ld)\n", time2, sum2);
    printf("  Pointer-based:     %.4f seconds (sum: %ld)\n", time3, sum3);
    printf("  Unrolling speedup: %.2fx\n", time1 / time2);
    printf("  Pointer speedup:   %.2fx\n", time1 / time3);
    
    free(array);
}

// SIMD optimization example
#ifdef __SSE2__
#include <emmintrin.h>

void simd_vector_add(float *a, float *b, float *result, size_t size) {
    size_t i;
    
    // Process 4 floats at a time using SSE
    for (i = 0; i < size - 3; i += 4) {
        __m128 va = _mm_load_ps(&a[i]);
        __m128 vb = _mm_load_ps(&b[i]);
        __m128 vr = _mm_add_ps(va, vb);
        _mm_store_ps(&result[i], vr);
    }
    
    // Handle remaining elements
    for (; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}

void simd_demo(void) {
    printf("\n=== SIMD Optimization Demo ===\n");
    
    const size_t size = 1000000;
    
    // Allocate aligned memory for SIMD
    float *a = _mm_malloc(size * sizeof(float), 16);
    float *b = _mm_malloc(size * sizeof(float), 16);
    float *result1 = _mm_malloc(size * sizeof(float), 16);
    float *result2 = _mm_malloc(size * sizeof(float), 16);
    
    if (!a || !b || !result1 || !result2) {
        printf("Failed to allocate aligned memory\n");
        return;
    }
    
    // Initialize data
    for (size_t i = 0; i < size; i++) {
        a[i] = (float)i;
        b[i] = (float)i * 2.0f;
    }
    
    Timer timer;
    
    // Scalar version
    timer_start(&timer);
    for (size_t i = 0; i < size; i++) {
        result1[i] = a[i] + b[i];
    }
    double scalar_time = timer_stop(&timer);
    
    // SIMD version
    timer_start(&timer);
    simd_vector_add(a, b, result2, size);
    double simd_time = timer_stop(&timer);
    
    // Verify results match
    int results_match = 1;
    for (size_t i = 0; i < size && results_match; i++) {
        if (result1[i] != result2[i]) {
            results_match = 0;
        }
    }
    
    printf("Vector addition results:\n");
    printf("  Scalar: %.4f seconds\n", scalar_time);
    printf("  SIMD:   %.4f seconds\n", simd_time);
    printf("  Speedup: %.2fx\n", scalar_time / simd_time);
    printf("  Results match: %s\n", results_match ? "Yes" : "No");
    
    _mm_free(a);
    _mm_free(b);
    _mm_free(result1);
    _mm_free(result2);
}
#else
void simd_demo(void) {
    printf("\n=== SIMD Demo ===\n");
    printf("SSE2 not available on this platform\n");
}
#endif

int main(void) {
    compare_memory_layouts();
    loop_optimizations_demo();
    simd_demo();
    
    return 0;
}
```

---

### 22. Secure Coding Practices {#secure-coding}

**Figure Reference: [Common Security Vulnerabilities in C]**

Security is paramount in C programming due to the language's low-level nature and manual memory management.

#### Buffer Overflow Protection

```c
/* secure_coding.c - Secure coding practices */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

// UNSAFE: Buffer overflow vulnerability
void unsafe_string_copy(void) {
    char buffer[10];
    char *input = "This string is much longer than 10 characters";
    
    printf("=== UNSAFE String Copy ===\n");
    printf("Input: %s\n", input);
    
    // VULNERABILITY: No bounds checking
    strcpy(buffer, input);  // Buffer overflow!
    printf("Buffer: %s\n", buffer);  // Undefined behavior
}

// SAFE: Bounded string operations
void safe_string_copy(void) {
    char buffer[10];
    char *input = "This string is much longer than 10 characters";
    
    printf("\n=== SAFE String Copy ===\n");
    printf("Input: %s\n", input);
    
    // Safe copy with size limit
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    
    printf("Buffer: %s\n", buffer);
    printf("Truncated safely to %zu characters\n", strlen(buffer));
}

// Enhanced safe string operations
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} SafeString;

SafeString* safe_string_create(size_t capacity) {
    SafeString *str = malloc(sizeof(SafeString));
    if (!str) return NULL;
    
    str->data = malloc(capacity + 1);
    if (!str->data) {
        free(str);
        return NULL;
    }
    
    str->data[0] = '\0';
    str->size = 0;
    str->capacity = capacity;
    
    return str;
}

int safe_string_append(SafeString *str, const char *text) {
    if (!str || !text) return 0;
    
    size_t text_len = strlen(text);
    size_t available = str->capacity - str->size;
    
    if (text_len > available) {
        // Truncate to fit
        text_len = available;
    }
    
    if (text_len > 0) {
        memcpy(str->data + str->size, text, text_len);
        str->size += text_len;
        str->data[str->size] = '\0';
    }
    
    return text_len;
}

void safe_string_destroy(SafeString *str) {
    if (str) {
        free(str->data);
        free(str);
    }
}

void safe_string_demo(void) {
    printf("\n=== Safe String Implementation ===\n");
    
    SafeString *str = safe_string_create(20);
    if (!str) {
        printf("Failed to create safe string\n");
        return;
    }
    
    printf("Created safe string with capacity: %zu\n", str->capacity);
    
    int copied1 = safe_string_append(str, "Hello");
    int copied2 = safe_string_append(str, ", World!");
    int copied3 = safe_string_append(str, " This text will be truncated");
    
    printf("Append 1: copied %d chars, result: '%s'\n", copied1, str->data);
    printf("Append 2: copied %d chars, result: '%s'\n", copied2, str->data);
    printf("Append 3: copied %d chars, result: '%s'\n", copied3, str->data);
    printf("Final size: %zu/%zu\n", str->size, str->capacity);
    
    safe_string_destroy(str);
}

// Integer overflow protection
int safe_multiply(int a, int b, int *result) {
    if (!result) return 0;
    
    // Check for overflow
    if (a > 0 && b > 0 && a > INT_MAX / b) return 0;
    if (a < 0 && b < 0 && a < INT_MAX / b) return 0;
    if (a > 0 && b < 0 && b < INT_MIN / a) return 0;
    if (a < 0 && b > 0 && a < INT_MIN / b) return 0;
    
    *result = a * b;
    return 1;
}

size_t safe_array_size(size_t count, size_t element_size) {
    if (count == 0 || element_size == 0) return 0;
    
    // Check for overflow
    if (count > SIZE_MAX / element_size) {
        return 0;  // Overflow would occur
    }
    
    return count * element_size;
}

void integer_overflow_demo(void) {
    printf("\n=== Integer Overflow Protection ===\n");
    
    int result;
    
    // Safe operations
    if (safe_multiply(1000, 2000, &result)) {
        printf("1000 * 2000 = %d\n", result);
    } else {
        printf("1000 * 2000: overflow detected\n");
    }
    
    // Overflow detection
    if (safe_multiply(100000, 50000, &result)) {
        printf("100000 * 50000 = %d\n", result);
    } else {
        printf("100000 * 50000: overflow detected\n");
    }
    
    // Safe array allocation
    size_t count = 1000000;
    size_t element_size = sizeof(int);
    size_t total_size = safe_array_size(count, element_size);
    
    if (total_size > 0) {
        printf("Safe to allocate %zu bytes for %zu elements\n", total_size, count);
    } else {
        printf("Array size calculation would overflow\n");
    }
}
```

#### Format String Vulnerabilities

```c
// UNSAFE: Format string vulnerability
void unsafe_printf(const char *user_input) {
    printf("=== UNSAFE Printf ===\n");
    // VULNERABILITY: User input used directly as format string
    printf(user_input);  // Can lead to information disclosure or code execution
    printf("\n");
}

// SAFE: Proper format string usage
void safe_printf(const char *user_input) {
    printf("=== SAFE Printf ===\n");
    // Safe: User input treated as data, not format string
    printf("%s\n", user_input);
}

// Safe logging function with format validation
void safe_log(const char *level, const char *format, ...) {
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Safe: We control the format string
    printf("[%s] [%s] ", timestamp, level);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);  // Safe because we trust our format string
    va_end(args);
    
    printf("\n");
}

void format_string_demo(void) {
    printf("\n=== Format String Security Demo ===\n");
    
    // Simulated user input that could be malicious
    char *malicious_input = "User data with format specifiers: %x %x %x %n";
    char *normal_input = "Regular user message";
    
    printf("Testing with normal input:\n");
    safe_printf(normal_input);
    
    printf("\nTesting with potentially malicious input:\n");
    safe_printf(malicious_input);
    
    // Demonstrate safe logging
    safe_log("INFO", "Application started");
    safe_log("ERROR", "Failed to open file: %s", "nonexistent.txt");
    safe_log("DEBUG", "Processing %d items", 42);
}
```

#### Memory Safety and RAII-Style Programming

```c
// RAII-style resource management in C
typedef struct {
    FILE *file;
    char *buffer;
    int is_valid;
} FileResource;

FileResource* file_resource_create(const char *filename, size_t buffer_size) {
    FileResource *resource = malloc(sizeof(FileResource));
    if (!resource) return NULL;
    
    resource->file = fopen(filename, "r");
    resource->buffer = malloc(buffer_size);
    resource->is_valid = 0;
    
    if (!resource->file || !resource->buffer) {
        // Cleanup on failure
        if (resource->file) fclose(resource->file);
        if (resource->buffer) free(resource->buffer);
        free(resource);
        return NULL;
    }
    
    resource->is_valid = 1;
    return resource;
}

void file_resource_destroy(FileResource *resource) {
    if (resource) {
        if (resource->file) fclose(resource->file);
        if (resource->buffer) free(resource->buffer);
        resource->is_valid = 0;
        free(resource);
    }
}

// Automatic cleanup using GCC cleanup attribute
#ifdef __GNUC__
#define CLEANUP(func) __attribute__((cleanup(func)))

void cleanup_file(FILE **file) {
    if (file && *file) {
        fclose(*file);
        *file = NULL;
    }
}

void cleanup_free(void **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

void automatic_cleanup_demo(void) {
    printf("\n=== Automatic Cleanup Demo ===\n");
    
    // These will be automatically cleaned up when going out of scope
    FILE *file CLEANUP(cleanup_file) = fopen("test.txt", "w");
    char *buffer CLEANUP(cleanup_free) = malloc(1024);
    
    if (file && buffer) {
        fprintf(file, "Test data\n");
        strcpy(buffer, "Buffer data");
        printf("Resources created and used successfully\n");
    }
    
    printf("Resources will be automatically cleaned up\n");
    // No explicit cleanup needed - destructors called automatically
}
#else
void automatic_cleanup_demo(void) {
    printf("\n=== Automatic Cleanup Demo ===\n");
    printf("Automatic cleanup requires GCC extensions\n");
}
#endif
```

#### Input Validation and Sanitization

```c
// Comprehensive input validation
typedef enum {
    INPUT_VALID,
    INPUT_TOO_SHORT,
    INPUT_TOO_LONG,
    INPUT_INVALID_CHARS,
    INPUT_NULL
} InputValidationResult;

InputValidationResult validate_username(const char *username) {
    if (!username) return INPUT_NULL;
    
    size_t len = strlen(username);
    
    if (len < 3) return INPUT_TOO_SHORT;
    if (len > 32) return INPUT_TOO_LONG;
    
    // Check for valid characters (alphanumeric + underscore)
    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if (!isalnum(c) && c != '_') {
            return INPUT_INVALID_CHARS;
        }
    }
    
    return INPUT_VALID;
}

const char* validation_result_string(InputValidationResult result) {
    switch (result) {
        case INPUT_VALID: return "Valid";
        case INPUT_TOO_SHORT: return "Too short (minimum 3 characters)";
        case INPUT_TOO_LONG: return "Too long (maximum 32 characters)";
        case INPUT_INVALID_CHARS: return "Invalid characters (use only letters, numbers, underscore)";
        case INPUT_NULL: return "NULL input";
        default: return "Unknown error";
    }
}

// SQL injection prevention example
char* escape_sql_string(const char *input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char *escaped = malloc(len * 2 + 1);  // Worst case: every char needs escaping
    if (!escaped) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (c == '\'' || c == '"' || c == '\\') {
            escaped[j++] = '\\';  // Escape character
        }
        escaped[j++] = c;
    }
    escaped[j] = '\0';
    
    return escaped;
}

void input_validation_demo(void) {
    printf("\n=== Input Validation Demo ===\n");
    
    const char *test_usernames[] = {
        "john",
        "ab",  // Too short
        "this_username_is_way_too_long_to_be_valid",  // Too long
        "user@domain.com",  // Invalid chars
        "valid_user123",
        NULL
    };
    
    for (int i = 0; test_usernames[i]; i++) {
        InputValidationResult result = validate_username(test_usernames[i]);
        printf("Username '%s': %s\n", test_usernames[i], validation_result_string(result));
    }
    
    // SQL injection prevention demo
    const char *malicious_input = "'; DROP TABLE users; --";
    char *escaped = escape_sql_string(malicious_input);
    
    printf("\nSQL Injection Prevention:\n");
    printf("Original: %s\n", malicious_input);
    printf("Escaped:  %s\n", escaped);
    
    free(escaped);
}
```

#### Fuzzing and Security Testing

```c
/* fuzz_target.c - Example fuzzing target */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function to be fuzzed - intentionally has bugs for demonstration
int parse_packet(const uint8_t *data, size_t size) {
    if (size < 4) {
        return -1;  // Too small
    }
    
    // Parse header
    uint16_t packet_type = *(uint16_t*)data;
    uint16_t payload_size = *(uint16_t*)(data + 2);
    
    // BUG: No validation of payload_size
    if (size < 4 + payload_size) {
        return -2;  // Inconsistent size
    }
    
    // BUG: Buffer overflow if payload_size is large
    char buffer[256];
    if (payload_size > 0) {
        memcpy(buffer, data + 4, payload_size);  // Potential overflow
    }
    
    // Process packet based on type
    switch (packet_type) {
        case 1:
            printf("Login packet\n");
            break;
        case 2:
            printf("Data packet\n");
            break;
        default:
            return -3;  // Unknown type
    }
    
    return 0;
}

// LibFuzzer target function
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_packet(data, size);
    return 0;  // Always return 0 for libFuzzer
}
#endif

// Manual fuzzing for demonstration
void manual_fuzz_test(void) {
    printf("\n=== Manual Fuzzing Demo ===\n");
    
    // Test cases that might reveal bugs
    struct {
        const char *name;
        uint8_t data[512];
        size_t size;
    } test_cases[] = {
        {"Empty packet", {0}, 0},
        {"Too small", {1, 0, 5, 0}, 3},
        {"Normal login", {1, 0, 4, 0, 'u', 's', 'e', 'r'}, 8},
        {"Oversized payload", {2, 0, 255, 255, 'A'}, 5},  // payload_size = 65535
        {"Unknown type", {99, 0, 0, 0}, 4},
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        printf("Testing: %s\n", test_cases[i].name);
        
        int result = parse_packet(test_cases[i].data, test_cases[i].size);
        printf("  Result: %d\n", result);
        
        // In a real fuzzer, crashes would be detected automatically
    }
}
```

**Fuzzing Build Commands:**

```bash
# Build for AFL fuzzing
afl-gcc -o fuzz_target fuzz_target.c
echo "test input" | afl-fuzz -i input_dir -o output_dir ./fuzz_target

# Build for libFuzzer
clang -fsanitize=fuzzer,address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION fuzz_target.c -o fuzz_target
./fuzz_target

# Build with AddressSanitizer for better crash detection
gcc -fsanitize=address -g -O0 fuzz_target.c -o fuzz_target
```

#### Hardened Builds and Compiler Flags

**Security-focused compilation:**

```bash
# Security hardening flags
SECURITY_FLAGS="-D_FORTIFY_SOURCE=2 \
                -fstack-protector-strong \
                -fPIE \
                -Wformat \
                -Wformat-security \
                -Werror=format-security"

# Link-time security
SECURITY_LDFLAGS="-pie \
                  -Wl,-z,relro \
                  -Wl,-z,now \
                  -Wl,-z,noexecstack"

# Control Flow Integrity (CFI)
CFI_FLAGS="-fsanitize=cfi \
           -flto \
           -fvisibility=hidden"

# Complete secure build
gcc $SECURITY_FLAGS $SECURITY_LDFLAGS -O2 -g secure_program.c -o secure_program
```

```c
/* secure_build_demo.c - Demonstrating hardened build features */
#include <stdio.h>
#include <string.h>

// Function with potential stack buffer overflow
void vulnerable_function(const char *input) {
    char buffer[64];
    
    // Stack protector will detect overflow here
    strcpy(buffer, input);  // Dangerous!
    
    printf("Buffer: %s\n", buffer);
}

// Function demonstrating format string protection
void format_function(const char *user_input) {
    // _FORTIFY_SOURCE will catch this at compile time
    // printf(user_input);  // Compile error with -D_FORTIFY_SOURCE=2
    
    printf("%s\n", user_input);  // Safe version
}

int main(void) {
    printf("=== Secure Build Features Demo ===\n");
    
    // These would trigger security features in a hardened build:
    
    // 1. Stack protector test (would abort in hardened build)
    printf("Testing with normal input:\n");
    vulnerable_function("Normal input");
    
    // 2. Format string protection (prevented at compile time)
    format_function("User input string");
    
    printf("Program completed normally\n");
    return 0;
}
```

#### Concepts ⚙
- Buffer overflow prevention techniques
- Format string vulnerability mitigation
- Integer overflow detection and prevention
- Input validation and sanitization strategies

#### Errors ⚠
- Using unsafe string functions (strcpy, sprintf, gets)
- Trusting user input without validation
- Ignoring compiler security warnings
- Not enabling security hardening features

#### Tips 🧠
- Always use bounded string operations
- Validate all inputs at program boundaries
- Enable compiler security features in production builds
- Use static analysis tools to detect vulnerabilities

#### Tools 🔧
- **Static Analysis**: Clang Static Analyzer, Cppcheck, PVS-Studio
- **Dynamic Analysis**: AddressSanitizer, Valgrind, Dr. Memory
- **Fuzzing**: AFL, libFuzzer, Honggfuzz
- **Security Scanners**: Coverity, SonarQube, Checkmarx

---

### 23. Networking in C {#networking}

**Figure Reference: [TCP/IP Network Stack Diagram]**

Network programming in C provides direct access to sockets and network protocols.

#### TCP/UDP Socket Programming

```c
/* networking.c - Network programming examples */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>

#ifdef __linux__
#include <sys/epoll.h>
#endif

// TCP Server implementation
int create_tcp_server(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }
    
    // Configure address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }
    
    printf("TCP Server listening on port %d\n", port);
    return server_fd;
}

// TCP Client implementation
int create_tcp_client(const char *host, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return -1;
    }
    
    printf("Connected to %s:%d\n", host, port);
    return sock;
}

// Simple echo server using select()
void run_echo_server(int port) {
    int server_fd, client_socket, activity, max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Maximum clients
    #define MAX_CLIENTS 30
    int client_sockets[MAX_CLIENTS];
    char buffer[1025];
    fd_set readfds;
    
    // Initialize client sockets
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
    }
    
    server_fd = create_tcp_server(port);
    if (server_fd < 0) {
        return;
    }
    
    printf("Echo server started on port %d\n", port);
    
    while (1) {
        // Clear the socket set
        FD_ZERO(&readfds);
        
        // Add master socket to set
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;
        
        // Add child sockets to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            
            if (sd > max_sd) {
                max_sd = sd;
            }
        }
        
        // Wait for an activity on one of the sockets
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        
        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        }
        
        // If something happened on the master socket, it's an incoming connection
        if (FD_ISSET(server_fd, &readfds)) {
            if ((client_socket = accept(server_fd,
                                      (struct sockaddr *)&address,
                                      (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            
            printf("New connection: socket fd is %d, ip is: %s, port: %d\n",
                   client_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            
            // Send welcome message
            char *message = "Welcome to the echo server\r\n";
            if (send(client_socket, message, strlen(message), 0) != strlen(message)) {
                perror("send");
            }
            
            // Add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = client_socket;
                    printf("Adding to list of sockets as %d\n", i);
                    break;
                }
            }
        }
        
        // Handle IO operation on some other socket
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (FD_ISSET(sd, &readfds)) {
                int valread;
                
                // Check if it was for closing, and also read the incoming message
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    // Somebody disconnected
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    printf("Host disconnected: ip %s, port %d\n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    
                    close(sd);
                    client_sockets[    fclose(file);
    return ERR_SUCCESS;
}

void error_handling_demo(void) {
    printf("=== Error Handling Demo ===\n");
    
    // Test safe mathematical operations
    double result;
    ErrorCode err;
    
    err = safe_divide(10.0, 2.0, &result);
    if (err == ERR_SUCCESS) {
        printf("10.0 / 2.0 = %.2f\n", result);
    } else {
        print_last_error();
    }
    
    err = safe_divide(10.0, 0.0, &result);
    if (err != ERR_SUCCESS) {
        printf("Division by zero handled:\n");
        print_last_error();
    }
    
    err = safe_sqrt(-1.0, &result);
    if (err != ERR_SUCCESS) {
        printf("\nSquare root of negative number handled:\n");
        print_last_error();
    }
    
    // Test safe buffer operations
    SafeBuffer *buffer;
    err = safe_buffer_create(&buffer, 16);
    if (err == ERR_SUCCESS) {
        printf("\nBuffer created successfully\n");
        
        const char *data1 = "Hello, ";
        const char *data2 = "World!";
        
        err = safe_buffer_append(buffer, data1, strlen(data1));
        if (err == ERR_SUCCESS) {
            err = safe_buffer_append(buffer, data2, strlen(data2));
        }
        
        if (err == ERR_SUCCESS) {
            printf("Buffer content: %.*s\n", (int)buffer->size, (char*)buffer->data);
            printf("Buffer size: %zu, capacity: %zu\n", buffer->size, buffer->capacity);
        }
        
        safe_buffer_destroy(buffer);
    }
    
    // Test file operations
    char *content;
    size_t file_size;
    
    // Try to read a non-existent file
    err = safe_file_read("nonexistent.txt", &content, &file_size);
    if (err != ERR_SUCCESS) {
        printf("\nFile read error handled:\n");
        print_last_error();
    }
    
    // Create a test file and read it
    FILE *test_file = fopen("test.txt", "w");
    if (test_file) {
        fprintf(test_file, "This is a test file for error handling demo.\n");
        fclose(test_file);
        
        err = safe_file_read("test.txt", &content, &file_size);
        if (err == ERR_SUCCESS) {
            printf("\nFile read successfully:\n");
            printf("Size: %zu bytes\n", file_size);
            printf("Content: %s", content);
            free(content);
        }
        
        remove("test.txt");  // Cleanup
    }
}

// Exception-like error handling using setjmp/longjmp
static jmp_buf error_jmp_buf;
static ErrorInfo exception_error;

#define TRY if (setjmp(error_jmp_buf) == 0) {
#define CATCH } else {
#define THROW(code, msg) \
    do { \
        set_exception_error((code), (msg), __FILE__, __LINE__, __func__); \
        longjmp(error_jmp_buf, 1); \
    } while(0)
#define END_TRY }

void set_exception_error(ErrorCode code, const char *message,
                        const char *file, int line, const char *function) {
    exception_error.code = code;
    snprintf(exception_error.message, sizeof(exception_error.message), "%s", message);
    snprintf(exception_error.file, sizeof(exception_error.file), "%s",
             strrchr(file, '/') ? strrchr(file, '/') + 1 : file);
    exception_error.line = line;
    snprintf(exception_error.function, sizeof(exception_error.function), "%s", function);
}

void risky_operation(int value) {
    if (value < 0) {
        THROW(ERR_INVALID_ARGUMENT, "Value cannot be negative");
    }
    
    if (value == 0) {
        THROW(ERR_INVALID_ARGUMENT, "Value cannot be zero");
    }
    
    printf("Processing value: %d\n", value);
    
    if (value > 100) {
        THROW(ERR_INVALID_ARGUMENT, "Value too large");
    }
    
    printf("Value processed successfully\n");
}

void exception_handling_demo(void) {
    printf("\n=== Exception-style Error Handling Demo ===\n");
    
    int test_values[] = {50, -1, 0, 150};
    int num_values = sizeof(test_values) / sizeof(test_values[0]);
    
    for (int i = 0; i < num_values; i++) {
        printf("\nTesting value: %d\n", test_values[i]);
        
        TRY {
            risky_operation(test_values[i]);
        }
        CATCH {
            printf("Exception caught:\n");
            printf("  Code: %d\n", exception_error.code);
            printf("  Message: %s\n", exception_error.message);
            printf("  Location: %s:%d in %s()\n",
                   exception_error.file, exception_error.line, exception_error.function);
        }
        END_TRY;
    }
}

// Signal handling for crash recovery
static volatile sig_atomic_t signal_received = 0;
static int signal_number = 0;

void signal_handler(int sig) {
    signal_received = 1;
    signal_number = sig;
}

void install_signal_handlers(void) {
    signal(SIGSEGV, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGABRT, signal_handler);
    #ifdef SIGBUS
    signal(SIGBUS, signal_handler);
    #endif
}

void signal_handling_demo(void) {
    printf("\n=== Signal Handling Demo ===\n");
    
    install_signal_handlers();
    
    printf("Signal handlers installed\n");
    printf("Testing controlled scenarios...\n");
    
    // Test division by zero (may generate SIGFPE on some systems)
    signal_received = 0;
    
    // Note: Modern systems may not generate SIGFPE for floating point division by zero
    printf("Testing division by zero handling...\n");
    volatile double a = 1.0;
    volatile double b = 0.0;
    volatile double result = a / b;  // May or may not generate signal
    
    if (signal_received) {
        printf("Signal %d caught during division by zero\n", signal_number);
    } else {
        printf("No signal generated (result: %f)\n", result);
    }
    
    printf("Signal handling test completed\n");
}

// Debug logging system
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4,
    LOG_LEVEL_FATAL = 5
} LogLevel;

static LogLevel current_log_level = LOG_LEVEL_INFO;
static FILE *log_file = NULL;

const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_TRACE: return "TRACE";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

void log_init(const char *filename, LogLevel level) {
    current_log_level = level;
    
    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", filename);
            log_file = stderr;
        }
    } else {
        log_file = stderr;
    }
}

void log_cleanup(void) {
    if (log_file && log_file != stderr && log_file != stdout) {
        fclose(log_file);
    }
    log_file = NULL;
}

void log_message(LogLevel level, const char *file, int line, const char *function,
                const char *format, ...) {
    if (level < current_log_level || !log_file) {
        return;
    }
    
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    // Print timestamp and level
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
            log_level_to_string(level));
    
    // Print location info for debug levels
    if (level <= LOG_LEVEL_DEBUG) {
        const char *basename = strrchr(file, '/');
        if (!basename) basename = strrchr(file, '\\');
        if (!basename) basename = file - 1;
        fprintf(log_file, "[%s:%d:%s] ", basename + 1, line, function);
    }
    
    // Print message
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}

// Logging macros
#define LOG_TRACE(fmt, ...) log_message(LOG_LEVEL_TRACE, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) log_message(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

void logging_demo(void) {
    printf("\n=== Logging System Demo ===\n");
    
    log_init("debug.log", LOG_LEVEL_TRACE);
    
    LOG_TRACE("This is a trace message");
    LOG_DEBUG("Debug message with value: %d", 42);
    LOG_INFO("Application started successfully");
    LOG_WARN("This is a warning message");
    LOG_ERROR("An error occurred: %s", "example error");
    LOG_FATAL("Fatal error - application terminating");
    
    printf("Log messages written to debug.log\n");
    
    // Change log level
    current_log_level = LOG_LEVEL_WARN;
    printf("Changed log level to WARN\n");
    
    LOG_DEBUG("This debug message won't appear");
    LOG_INFO("This info message won't appear");
    LOG_WARN("This warning will appear");
    LOG_ERROR("This error will appear");
    
    log_cleanup();
}

// Memory debugging helpers
#ifdef DEBUG_MEMORY
static size_t total_allocated = 0;
static size_t allocation_count = 0;

void* debug_malloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size + sizeof(size_t));
    if (ptr) {
        *(size_t*)ptr = size;
        total_allocated += size;
        allocation_count++;
        printf("MALLOC: %zu bytes at %p (%s:%d) [Total: %zu, Count: %zu]\n",
               size, (char*)ptr + sizeof(size_t), file, line,
               total_allocated, allocation_count);
        return (char*)ptr + sizeof(size_t);
    }
    return NULL;
}

void debug_free(void *ptr, const char *file, int line) {
    if (ptr) {
        void *real_ptr = (char*)ptr - sizeof(size_t);
        size_t size = *(size_t*)real_ptr;
        total_allocated -= size;
        allocation_count--;
        printf("FREE: %zu bytes at %p (%s:%d) [Total: %zu, Count: %zu]\n",
               size, ptr, file, line, total_allocated, allocation_count);
        free(real_ptr);
    }
}

#define malloc(size) debug_malloc(size, __FILE__, __LINE__)
#define free(ptr) debug_free(ptr, __FILE__, __LINE__)
#endif

void memory_debugging_demo(void) {
    printf("\n=== Memory Debugging Demo ===\n");
    
#ifdef DEBUG_MEMORY
    printf("Memory debugging enabled\n");
    
    char *buffer1 = malloc(100);
    char *buffer2 = malloc(200);
    char *buffer3 = malloc(50);
    
    free(buffer2);
    buffer2 = malloc(150);
    
    free(buffer1);
    free(buffer2);
    free(buffer3);
    
    printf("Final allocation count: %zu, total: %zu\n", 
           allocation_count, total_allocated);
#else
    printf("Memory debugging not enabled (compile with -DDEBUG_MEMORY)\n");
    
    // Regular allocation for demo
    char *buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Test data");
        printf("Allocated and used buffer: %s\n", buffer);
        free(buffer);
    }
#endif
}

// Assertion macros with enhanced information
#ifdef DEBUG
#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ASSERTION FAILED: %s\n", #condition); \
            fprintf(stderr, "  File: %s:%d\n", __FILE__, __LINE__); \
            fprintf(stderr, "  Function: %s\n", __func__); \
            abort(); \
        } \
    } while(0)

#define ASSERT_MSG(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ASSERTION FAILED: %s\n", #condition); \
            fprintf(stderr, "  Message: %s\n", message); \
            fprintf(stderr, "  File: %s:%d\n", __FILE__, __LINE__); \
            fprintf(stderr, "  Function: %s\n", __func__); \
            abort(); \
        } \
    } while(0)
#else
#define ASSERT(condition) ((void)0)
#define ASSERT_MSG(condition, message) ((void)0)
#endif

void assertion_demo(void) {
    printf("\n=== Assertion Demo ===\n");
    
#ifdef DEBUG
    printf("Debug assertions enabled\n");
    
    int x = 10;
    ASSERT(x > 0);
    ASSERT_MSG(x < 100, "x should be less than 100");
    
    printf("All assertions passed\n");
    
    // This would abort the program:
    // ASSERT(x < 0);
#else
    printf("Debug assertions disabled (compile with -DDEBUG)\n");
#endif
}

int main(void) {
    error_handling_demo();
    exception_handling_demo();
    signal_handling_demo();
    logging_demo();
    memory_debugging_demo();
    assertion_demo();
    
    return 0;
}
```

#### Debugging Workflows and Tools

**GDB Debugging Session Example:**

```bash
# Compile with debugging symbols
gcc -g -O0 -DDEBUG -DDEBUG_MEMORY error_handling.c -o debug_program

# Start GDB session
gdb ./debug_program

# Common GDB commands:
(gdb) break main                    # Set breakpoint at main
(gdb) break error_handling.c:123   # Set breakpoint at line 123
(gdb) run                          # Start program execution
(gdb) continue                     # Continue execution
(gdb) step                         # Step into function calls
(gdb) next                         # Step over function calls
(gdb) print variable_name          # Print variable value
(gdb) backtrace                    # Show call stack
(gdb) frame 2                      # Switch to stack frame 2
(gdb) info locals                  # Show local variables
(gdb) watch global_var             # Set watchpoint on variable
(gdb) disassemble                  # Show assembly code
```

**AddressSanitizer (ASan) Usage:**

```c
/* asan_example.c - AddressSanitizer demonstration */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function with intentional bugs for ASan to catch
void demonstrate_memory_bugs(void) {
    printf("=== AddressSanitizer Demo ===\n");
    
    // 1. Heap buffer overflow
    char *buffer = malloc(10);
    strcpy(buffer, "This string is too long!");  // Buffer overflow
    printf("Buffer: %s\n", buffer);
    free(buffer);
    
    // 2. Use after free
    char *ptr = malloc(20);
    free(ptr);
    strcpy(ptr, "Use after free!");  // Use after free
    
    // 3. Double free
    char *another_ptr = malloc(30);
    free(another_ptr);
    free(another_ptr);  // Double free
    
    // 4. Memory leak (not freed)
    char *leaked = malloc(100);
    strcpy(leaked, "This memory will leak");
    // Missing free(leaked);
}
```

**Compilation and execution with sanitizers:**

```bash
# Compile with AddressSanitizer
gcc -fsanitize=address -g -O0 asan_example.c -o asan_program

# Compile with UndefinedBehaviorSanitizer
gcc -fsanitize=undefined -g -O0 program.c -o ubsan_program

# Compile with ThreadSanitizer
gcc -fsanitize=thread -g -O0 threaded_program.c -o tsan_program

# Run with sanitizer options
ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 ./asan_program
```

**Valgrind Memory Analysis:**

```bash
# Memory leak detection
valgrind --tool=memcheck --leak-check=full ./program

# Cache profiling
valgrind --tool=cachegrind ./program

# Heap profiling  
valgrind --tool=massif ./program

# Thread error detection
valgrind --tool=helgrind ./threaded_program
```

#### Testing and Coverage

**Simple Unit Testing Framework:**

```c
/* test_framework.c - Simple unit testing framework */
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

static int tests_run = 0;
static int tests_passed = 0;
static jmp_buf test_env;

#define TEST(name) \
    void test_##name(void); \
    void run_test_##name(void) { \
        printf("Running test: %s ... ", #name); \
        tests_run++; \
        if (setjmp(test_env) == 0) { \
            test_##name(); \
            tests_passed++; \
            printf("PASSED\n"); \
        } else { \
            printf("FAILED\n"); \
        } \
    } \
    void test_##name(void)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("\n  Assertion failed: expected %d, got %d\n", (expected), (actual)); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("\n  Assertion failed: expected '%s', got '%s'\n", (expected), (actual)); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("\n  Assertion failed: %s is false\n", #condition); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define RUN_TEST(name) run_test_##name()

// Example tests for our error handling functions
TEST(safe_divide_success) {
    double result;
    ErrorCode err = safe_divide(10.0, 2.0, &result);
    ASSERT_EQ(ERR_SUCCESS, err);
    ASSERT_TRUE(result == 5.0);
}

TEST(safe_divide_by_zero) {
    double result;
    ErrorCode err = safe_divide(10.0, 0.0, &result);
    ASSERT_EQ(ERR_INVALID_ARGUMENT, err);
}

TEST(safe_sqrt_positive) {
    double result;
    ErrorCode err = safe_sqrt(16.0, &result);
    ASSERT_EQ(ERR_SUCCESS, err);
    ASSERT_TRUE(result == 4.0);
}

TEST(safe_sqrt_negative) {
    double result;
    ErrorCode err = safe_sqrt(-1.0, &result);
    ASSERT_EQ(ERR_INVALID_ARGUMENT, err);
}

void run_all_tests(void) {
    printf("=== Running Unit Tests ===\n");
    
    RUN_TEST(safe_divide_success);
    RUN_TEST(safe_divide_by_zero);
    RUN_TEST(safe_sqrt_positive);
    RUN_TEST(safe_sqrt_negative);
    
    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("Success rate: %.1f%%\n", 
           tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0);
}
```

**Coverage Analysis:**

```bash
# Compile with coverage flags
gcc --coverage -g -O0 program.c -o program

# Run program to generate coverage data
./program

# Generate coverage report
gcov program.c

# Generate HTML coverage report with lcov
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html

# View coverage report
open coverage_html/index.html
```

#### Concepts ⚙
- Error propagation strategies and error codes
- Exception-like handling with setjmp/longjmp
- Signal handling for crash recovery
- Memory debugging and leak detection

#### Errors ⚠
- Inconsistent error handling patterns
- Resource leaks in error paths
- Signal handler safety violations
- Race conditions in error reporting

#### Tips 🧠
- Use consistent error codes throughout your application
- Always check return values from system calls
- Implement proper cleanup in error paths
- Use static analysis tools to catch bugs early

#### Tools 🔧
- **GDB/LLDB**: Interactive debuggers
- **AddressSanitizer**: Memory error detection
- **Valgrind**: Memory analysis and profiling
- **Static analyzers**: Clang Static Analyzer, Cppcheck
- **Coverage tools**: gcov, lcov, llvm-cov

---

### 21. Performance Optimization {#performance}

Performance optimization in C requires understanding of hardware characteristics, compiler behavior, and algorithmic complexity.

#### Profiling and Performance Analysis

**Figure Reference: [Performance Optimization Workflow Diagram]**

```c
/* performance_optimization.c - Performance optimization techniques */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// High-resolution timing utilities
typedef struct {
    struct timespec start;
    struct timespec end;
} Timer;

void timer_start(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->start);
}

double timer_stop(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->end);
    
    double start_time = timer->start.tv_sec + timer->start.tv_nsec / 1e9;
    double end_time = timer->end.tv_sec + timer->end.tv_nsec / 1e9;
    
    return end_time - start_time;
}

// Cache-friendly data structures
typedef struct {
    int *data;
    size_t size;
    size_t capacity;
} IntArray;

// Array of Structures (AoS) - cache unfriendly for some operations
typedef struct {
    float x, y, z;
    int id;
    char padding[4];  // Explicit padding
} Point3D_AoS;

// Structure of Arrays (SoA) - cache friendly
typedef struct {
    float *x;
    float *y;
    float *z;
    int *id;
    size_t count;
} Point3D_SoA;

void compare_memory_layouts(void) {
    printf("=== Memory Layout Performance Comparison ===\n");
    
    const size_t num_points = 1000000;
    Timer timer;
    
    // Allocate AoS
    Point3D_AoS *aos_points = malloc(num_points * sizeof(Point3D_AoS));
    if (!aos_points) {
        printf("Failed to allocate AoS points\n");
        return;
    }
    
    // Allocate SoA
    Point3D_SoA soa_points = {0};
    soa_points.x = malloc(num_points * sizeof(float));
    soa_points.y = malloc(num_points * sizeof(float));
    soa_points.z = malloc(num_points * sizeof(float));
    soa_points.id = malloc(num_points * sizeof(int));
    soa_points.count = num_points;
    
    if (!soa_points.x || !soa_points.y || !soa_points.z || !soa_points.id) {
        printf("Failed to allocate SoA points\n");
        free(aos_points);
        return;
    }
    
    // Initialize data
    for (size_t i = 0; i < num_points; i++) {
        aos_points[i].x = (float)i;
        aos_points[i].y = (float)i * 2.0f;
        aos_points[i].z = (float)i * 3.0f;
        aos_points[i].id = (int)i;
        
        soa_points.x[i] = (float)i;
        soa_points.y[i] = (float)i * 2.0f;
        soa_points.z[i] = (float)i * 3.0f;
        soa_points.id[i] = (int)i;
    }
    
    // Test: Sum all X coordinates (cache friendly operation)
    double sum_aos = 0.0, sum_soa = 0.0;
    
    // AoS version - poor cache usage
    timer_start(&timer);
    for (size_t i = 0; i < num_points; i++) {
        sum_aos += aos_points[i].x;
    }
    double aos_time = timer_stop(&timer);
    
    // SoA version - better cache usage
    timer_start(&timer);
    for (size_t i = 0; i < num_points; i++) {
        sum_soa += soa_points.x[i];
    }
    double soa_time = timer_stop(&timer);
    
    printf("Summing X coordinates:\n");
    printf("  AoS: %.4f seconds (sum: %.0f)\n", aos_time, sum_aos);
    printf("  SoA: %.4f seconds (sum: %.0f)\n", soa_time, sum_soa);
    printf("  SoA speedup: %.2fx\n", aos_time / soa_time);
    
    printf("\nMemory usage:\n");
    printf("  AoS: %zu bytes per point (%zu total)\n", 
           sizeof(Point3D_AoS), num_points * sizeof(Point3D_AoS));
    printf("  SoA: %zu bytes per point (%zu total)\n",
           sizeof(float) * 3 + sizeof(int), 
           num_points * (sizeof(float) * 3 + sizeof(int)));
    
    // Cleanup
    free(aos_points);
    free(soa_points.x);
    free(soa_points.y);
    free(soa_points.z);
    free(soa_points.id);
}

// Loop optimization techniques
void loop_optimizations_demo(void) {
    printf("\n=== Loop Optimization Demo ===\n");
    
    const size_t size = 10000000;
    int *array = malloc(size * sizeof(int));
    if (!array) return;
    
    Timer timer;
    
    // Initialize array
    for (size_t i = 0; i < size; i++) {
        array[i] = (int)(i % 1000);
    }
    
    // Unoptimized loop
    timer_start(&timer);
    volatile long sum1 = 0;
    for (size_t i = 0; i < size; i++) {
        sum1 += array[i];
    }
    double time1 = timer_stop(&timer);
    
    // Loop unrolling
    timer_start(&timer);
    volatile long sum2 = 0;
    size_t i;
    for (i = 0; i < size - 3; i += 4) {
        sum2 += array[i] + array[i+1] + array[i+2] + array[i+3];
    }
    // Handle remaining elements
    for (; i < size; i++) {
        sum2 += array[i];
    }
    double time2 = timer_stop(&timer);
    
    // Loop with reduced function calls
    timer_start(&timer);
    volatile long sum3 = 0;
    int *ptr = array;
    int *end = array + size;
    while (ptr < end) {
        sum3 += *ptr++;
    }
    double time3 = timer_stop(&timer);
    
    printf("Loop optimization results:\n");
    printf("  Standard loop:     %.4f seconds (sum: %ld)\n", time1, sum1);
    printf("  Unrolled loop:     %.4f seconds (sum: %ld)\n", time2, sum2);
    printf("  Pointer-based:     %.4f seconds (sum: %l// Boyer-Moore string search algorithm
#define ALPHABET_SIZE 256

void build_bad_char_table(const char *pattern, int pattern_len, int bad_char[ALPHABET_SIZE]) {
    // Initialize all entries as -1
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        bad_char[i] = -1;
    }
    
    // Store the last occurrence of each character
    for (int i = 0; i < pattern_len; i++) {
        bad_char[(unsigned char)pattern[i]] = i;
    }
}

char* boyer_moore_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    int bad_char[ALPHABET_SIZE];
    build_bad_char_table(pattern, pattern_len, bad_char);
    
    int shift = 0;  // Shift of pattern with respect to text
    
    while (shift <= text_len - pattern_len) {
        int j = pattern_len - 1;
        
        // Match pattern from right to left
        while (j >= 0 && pattern[j] == text[shift + j]) {
            j--;
        }
        
        // Pattern found
        if (j < 0) {
            return (char*)(text + shift);
        }
        
        // Calculate shift based on bad character heuristic
        int bad_char_shift = j - bad_char[(unsigned char)text[shift + j]];
        shift += (bad_char_shift > 1) ? bad_char_shift : 1;
    }
    
    return NULL;  // Pattern not found
}

// KMP (Knuth-Morris-Pratt) string search
void compute_lps_array(const char *pattern, int pattern_len, int *lps) {
    int len = 0;  // Length of previous longest prefix suffix
    lps[0] = 0;   // lps[0] is always 0
    int i = 1;
    
    while (i < pattern_len) {
        if (pattern[i] == pattern[len]) {
            len++;
            lps[i] = len;
            i++;
        } else {
            if (len != 0) {
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

char* kmp_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    // Create LPS array
    int *lps = malloc(pattern_len * sizeof(int));
    if (!lps) return NULL;
    
    compute_lps_array(pattern, pattern_len, lps);
    
    int i = 0;  // Index for text
    int j = 0;  // Index for pattern
    
    while (i < text_len) {
        if (pattern[j] == text[i]) {
            i++;
            j++;
        }
        
        if (j == pattern_len) {
            free(lps);
            return (char*)(text + i - j);
        } else if (i < text_len && pattern[j] != text[i]) {
            if (j != 0) {
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }
    
    free(lps);
    return NULL;  // Pattern not found
}

// Rabin-Karp rolling hash search
#define PRIME 101

char* rabin_karp_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    int pattern_hash = 0;  // Hash value for pattern
    int text_hash = 0;     // Hash value for current window of text
    int h = 1;             // Hash multiplier
    
    // Calculate h = pow(d, pattern_len-1) % PRIME
    for (int i = 0; i < pattern_len - 1; i++) {
        h = (h * ALPHABET_SIZE) % PRIME;
    }
    
    // Calculate hash for pattern and first window
    for (int i = 0; i < pattern_len; i++) {
        pattern_hash = (ALPHABET_SIZE * pattern_hash + pattern[i]) % PRIME;
        text_hash = (ALPHABET_SIZE * text_hash + text[i]) % PRIME;
    }
    
    // Slide the pattern over text one by one
    for (int i = 0; i <= text_len - pattern_len; i++) {
        // Check if hash values match
        if (pattern_hash == text_hash) {
            // Check characters one by one
            int j;
            for (j = 0; j < pattern_len; j++) {
                if (text[i + j] != pattern[j]) {
                    break;
                }
            }
            
            if (j == pattern_len) {
                return (char*)(text + i);
            }
        }
        
        // Calculate hash for next window
        if (i < text_len - pattern_len) {
            text_hash = (ALPHABET_SIZE * (text_hash - text[i] * h) + text[i + pattern_len]) % PRIME;
            
            // Convert negative hash to positive
            if (text_hash < 0) {
                text_hash += PRIME;
            }
        }
    }
    
    return NULL;
}

void string_search_comparison(void) {
    printf("=== String Search Algorithm Comparison ===\n");
    
    const char *text = "ABABDABACDABABCABCABCABCABC";
    const char *pattern = "ABABCABCABCABC";
    
    printf("Text: %s\n", text);
    printf("Pattern: %s\n", pattern);
    
    // Test different algorithms
    char *result1 = strstr(text, pattern);
    char *result2 = boyer_moore_search(text, pattern);
    char *result3 = kmp_search(text, pattern);
    char *result4 = rabin_karp_search(text, pattern);
    
    printf("\nSearch Results:\n");
    printf("strstr:      %s\n", result1 ? "Found" : "Not found");
    printf("Boyer-Moore: %s\n", result2 ? "Found" : "Not found");
    printf("KMP:         %s\n", result3 ? "Found" : "Not found");
    printf("Rabin-Karp:  %s\n", result4 ? "Found" : "Not found");
    
    if (result1) {
        printf("Position: %ld\n", result1 - text);
    }
    
    // Performance characteristics
    printf("\nAlgorithm Characteristics:\n");
    printf("• strstr:      O(nm) worst case, optimized in practice\n");
    printf("• Boyer-Moore: O(n/m) average, O(nm) worst case\n");
    printf("• KMP:         O(n+m) guaranteed, good for repeated searches\n");
    printf("• Rabin-Karp:  O(n+m) average, O(nm) worst case with collisions\n");
}

// Advanced string manipulation functions
typedef struct {
    char **strings;
    size_t count;
    size_t capacity;
} StringArray;

StringArray* string_array_create(size_t initial_capacity) {
    StringArray *arr = malloc(sizeof(StringArray));
    if (!arr) return NULL;
    
    arr->strings = malloc(initial_capacity * sizeof(char*));
    if (!arr->strings) {
        free(arr);
        return NULL;
    }
    
    arr->count = 0;
    arr->capacity = initial_capacity;
    return arr;
}

int string_array_add(StringArray *arr, const char *str) {
    if (!arr || !str) return 0;
    
    // Resize if needed
    if (arr->count >= arr->capacity) {
        size_t new_capacity = arr->capacity * 2;
        char **new_strings = realloc(arr->strings, new_capacity * sizeof(char*));
        if (!new_strings) return 0;
        
        arr->strings = new_strings;
        arr->capacity = new_capacity;
    }
    
    // Duplicate string
    arr->strings[arr->count] = malloc(strlen(str) + 1);
    if (!arr->strings[arr->count]) return 0;
    
    strcpy(arr->strings[arr->count], str);
    arr->count++;
    return 1;
}

void string_array_destroy(StringArray *arr) {
    if (!arr) return;
    
    for (size_t i = 0; i < arr->count; i++) {
        free(arr->strings[i]);
    }
    free(arr->strings);
    free(arr);
}

// Advanced tokenization
StringArray* advanced_split(const char *str, const char *delimiters, int max_tokens) {
    if (!str || !delimiters) return NULL;
    
    StringArray *result = string_array_create(16);
    if (!result) return NULL;
    
    char *str_copy = malloc(strlen(str) + 1);
    if (!str_copy) {
        string_array_destroy(result);
        return NULL;
    }
    strcpy(str_copy, str);
    
    char *token = strtok(str_copy, delimiters);
    int token_count = 0;
    
    while (token && (max_tokens <= 0 || token_count < max_tokens)) {
        if (!string_array_add(result, token)) {
            break;
        }
        token = strtok(NULL, delimiters);
        token_count++;
    }
    
    free(str_copy);
    return result;
}

// String trimming with character set
char* trim_charset(char *str, const char *charset) {
    if (!str || !charset) return str;
    
    char *start = str;
    char *end = str + strlen(str) - 1;
    
    // Trim leading characters
    while (*start && strchr(charset, *start)) {
        start++;
    }
    
    // Trim trailing characters
    while (end > start && strchr(charset, *end)) {
        end--;
    }
    
    end[1] = '\0';
    
    // Move trimmed string to beginning if necessary
    if (start != str) {
        memmove(str, start, end - start + 2);
    }
    
    return str;
}

// Case-insensitive string comparison with locale support
int strcasecmp_locale(const char *s1, const char *s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    
    while (*s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        
        if (c1 != c2) {
            return c1 - c2;
        }
        
        s1++;
        s2++;
    }
    
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

// String replacement with limit
char* string_replace(const char *str, const char *old_substr, 
                    const char *new_substr, int max_replacements) {
    if (!str || !old_substr || !new_substr) return NULL;
    
    size_t old_len = strlen(old_substr);
    size_t new_len = strlen(new_substr);
    size_t str_len = strlen(str);
    
    if (old_len == 0) return strdup(str);
    
    // Count occurrences
    int count = 0;
    const char *pos = str;
    while ((pos = strstr(pos, old_substr)) && (max_replacements <= 0 || count < max_replacements)) {
        count++;
        pos += old_len;
    }
    
    if (count == 0) return strdup(str);
    
    // Calculate new string size
    size_t new_str_len = str_len + count * (new_len - old_len);
    char *result = malloc(new_str_len + 1);
    if (!result) return NULL;
    
    // Perform replacements
    char *dest = result;
    const char *src = str;
    int replacements_made = 0;
    
    while ((pos = strstr(src, old_substr)) && (max_replacements <= 0 || replacements_made < max_replacements)) {
        // Copy text before match
        size_t prefix_len = pos - src;
        memcpy(dest, src, prefix_len);
        dest += prefix_len;
        
        // Copy replacement
        memcpy(dest, new_substr, new_len);
        dest += new_len;
        
        src = pos + old_len;
        replacements_made++;
    }
    
    // Copy remaining text
    strcpy(dest, src);
    
    return result;
}

void advanced_string_functions_demo(void) {
    printf("\n=== Advanced String Functions Demo ===\n");
    
    // Test advanced split
    const char *csv_line = "apple,banana,cherry;date:elderberry|fig,grape";
    StringArray *tokens = advanced_split(csv_line, ",;:|", 0);
    
    printf("Original: %s\n", csv_line);
    printf("Split result (%zu tokens):\n", tokens->count);
    for (size_t i = 0; i < tokens->count; i++) {
        printf("  [%zu]: '%s'\n", i, tokens->strings[i]);
    }
    
    string_array_destroy(tokens);
    
    // Test trimming
    char test_str[] = "  \t\n  Hello, World!  \t\n  ";
    printf("\nTrimming test:\n");
    printf("Before: |%s|\n", test_str);
    trim_charset(test_str, " \t\n");
    printf("After:  |%s|\n", test_str);
    
    // Test case-insensitive comparison
    printf("\nCase-insensitive comparison:\n");
    printf("strcasecmp_locale('Hello', 'HELLO') = %d\n", 
           strcasecmp_locale("Hello", "HELLO"));
    printf("strcasecmp_locale('Apple', 'Banana') = %d\n", 
           strcasecmp_locale("Apple", "Banana"));
    
    // Test string replacement
    const char *original = "The quick brown fox jumps over the lazy dog. The fox is quick.";
    char *replaced = string_replace(original, "fox", "cat", 2);
    
    printf("\nString replacement:\n");
    printf("Original: %s\n", original);
    printf("Replaced: %s\n", replaced);
    
    free(replaced);
}

// Unicode and multibyte string handling
#include <locale.h>
#include <wchar.h>
#include <wctype.h>

void unicode_string_demo(void) {
    printf("\n=== Unicode String Handling Demo ===\n");
    
    // Set locale for proper unicode handling
    setlocale(LC_ALL, "");
    
    // Wide character strings
    wchar_t wide_str[] = L"Hello, 世界! 🌍";
    printf("Wide string length: %zu characters\n", wcslen(wide_str));
    
    // Convert to multibyte string
    size_t mb_len = wcstombs(NULL, wide_str, 0);
    if (mb_len != (size_t)-1) {
        char *mb_str = malloc(mb_len + 1);
        if (mb_str) {
            wcstombs(mb_str, wide_str, mb_len + 1);
            printf("Multibyte string: %s\n", mb_str);
            printf("Multibyte length: %zu bytes\n", strlen(mb_str));
            free(mb_str);
        }
    }
    
    // Wide character manipulation
    wchar_t *pos = wcschr(wide_str, L'世');
    if (pos) {
        printf("Found '世' at position: %ld\n", pos - wide_str);
    }
    
    // Character classification for wide characters
    wchar_t test_chars[] = {L'A', L'中', L'5', L'!', L'🌍', 0};
    printf("\nWide character classification:\n");
    for (int i = 0; test_chars[i]; i++) {
        wchar_t wc = test_chars[i];
        printf("'%lc': alpha=%d, digit=%d, punct=%d\n", 
               (wint_t)wc, iswalpha(wc), iswdigit(wc), iswpunct(wc));
    }
}

// String hashing and fingerprinting
typedef struct {
    uint32_t hash;
    uint16_t length;
    char data[];
} HashedString;

// FNV-1a hash algorithm
uint32_t fnv1a_hash(const char *str, size_t len) {
    const uint32_t FNV_PRIME = 0x01000193;
    const uint32_t FNV_OFFSET_BASIS = 0x811c9dc5;
    
    uint32_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)str[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

HashedString* create_hashed_string(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    if (len > UINT16_MAX) return NULL;  // Length limit
    
    HashedString *hs = malloc(sizeof(HashedString) + len + 1);
    if (!hs) return NULL;
    
    hs->length = (uint16_t)len;
    hs->hash = fnv1a_hash(str, len);
    strcpy(hs->data, str);
    
    return hs;
}

int hashed_string_compare(const HashedString *hs1, const HashedString *hs2) {
    if (!hs1 || !hs2) return hs1 ? 1 : (hs2 ? -1 : 0);
    
    // Quick hash comparison
    if (hs1->hash != hs2->hash || hs1->length != hs2->length) {
        return hs1->hash < hs2->hash ? -1 : 1;
    }
    
    // Fallback to string comparison (handle hash collisions)
    return strcmp(hs1->data, hs2->data);
}

void string_hashing_demo(void) {
    printf("\n=== String Hashing Demo ===\n");
    
    const char *test_strings[] = {
        "hello",
        "world",
        "Hello",  // Different case
        "hello",  // Duplicate
        "programming",
        NULL
    };
    
    printf("String hashing comparison:\n");
    
    for (int i = 0; test_strings[i]; i++) {
        HashedString *hs = create_hashed_string(test_strings[i]);
        if (hs) {
            printf("'%s': hash=0x%08x, length=%u\n", 
                   hs->data, hs->hash, hs->length);
            free(hs);
        }
    }
    
    // Demonstrate hash collision detection
    HashedString *hs1 = create_hashed_string("hello");
    HashedString *hs2 = create_hashed_string("hello");
    HashedString *hs3 = create_hashed_string("world");
    
    if (hs1 && hs2 && hs3) {
        printf("\nHash comparison results:\n");
        printf("'hello' vs 'hello': %d\n", hashed_string_compare(hs1, hs2));
        printf("'hello' vs 'world': %d\n", hashed_string_compare(hs1, hs3));
        
        free(hs1);
        free(hs2);
        free(hs3);
    }
}

int main(void) {
    string_search_comparison();
    advanced_string_functions_demo();
    unicode_string_demo();
    string_hashing_demo();
    
    printf("\n=== Advanced String Manipulation Best Practices ===\n");
    printf("1. Choose appropriate search algorithms based on use case\n");
    printf("2. Handle Unicode properly with wide character functions\n");
    printf("3. Use consistent string hashing for fast comparisons\n");
    printf("4. Always validate input parameters\n");
    printf("5. Consider locale settings for character operations\n");
    printf("6. Use memory-safe string functions\n");
    printf("7. Profile string-heavy code for performance bottlenecks\n");
    
    return 0;
}
```

#### Concepts ⚙
- String search algorithm complexity analysis
- Unicode and multibyte character handling
- Hash-based string operations and collision handling
- Memory-efficient string storage techniques

#### Errors ⚠
- Buffer overflows in string manipulation
- Incorrect Unicode character boundary handling
- Hash collision assumptions
- Locale-dependent behavior inconsistencies

#### Tips 🧠
- Use Boyer-Moore for long patterns, KMP for multiple searches
- Consider string interning for frequently used strings
- Profile different algorithms with your specific data
- Handle Unicode normalization for proper comparisons

#### Tools 🔧
- Unicode normalization libraries (ICU)
- String profiling tools
- Memory leak detectors for string operations
- Locale testing frameworks

---

### 20. Error Handling and Debugging {#error-handling}

Robust error handling and effective debugging are crucial for professional C development.

#### Comprehensive Error Handling Strategies

```c
/* error_handling.c - Comprehensive error handling strategies */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <setjmp.h>
#include <signal.h>

// Error code enumeration
typedef enum {
    ERR_SUCCESS = 0,
    ERR_NULL_POINTER = -1,
    ERR_INVALID_ARGUMENT = -2,
    ERR_OUT_OF_MEMORY = -3,
    ERR_FILE_NOT_FOUND = -4,
    ERR_PERMISSION_DENIED = -5,
    ERR_BUFFER_OVERFLOW = -6,
    ERR_NETWORK_ERROR = -7,
    ERR_TIMEOUT = -8,
    ERR_UNKNOWN = -999
} ErrorCode;

// Error information structure
typedef struct {
    ErrorCode code;
    char message[256];
    char file[64];
    int line;
    char function[64];
} ErrorInfo;

// Global error state
static ErrorInfo g_last_error = {ERR_SUCCESS, "", "", 0, ""};

// Error reporting macros
#define SET_ERROR(code, msg) \
    set_error_info((code), (msg), __FILE__, __LINE__, __func__)

#define RETURN_ERROR(code, msg) \
    do { \
        SET_ERROR((code), (msg)); \
        return (code); \
    } while(0)

#define CHECK_NULL(ptr, msg) \
    do { \
        if (!(ptr)) { \
            RETURN_ERROR(ERR_NULL_POINTER, (msg)); \
        } \
    } while(0)

#define CHECK_ALLOC(ptr) \
    do { \
        if (!(ptr)) { \
            RETURN_ERROR(ERR_OUT_OF_MEMORY, "Memory allocation failed"); \
        } \
    } while(0)

// Error handling functions
void set_error_info(ErrorCode code, const char *message, 
                   const char *file, int line, const char *function) {
    g_last_error.code = code;
    snprintf(g_last_error.message, sizeof(g_last_error.message), "%s", message);
    snprintf(g_last_error.file, sizeof(g_last_error.file), "%s", 
             strrchr(file, '/') ? strrchr(file, '/') + 1 : file);
    g_last_error.line = line;
    snprintf(g_last_error.function, sizeof(g_last_error.function), "%s", function);
}

const char* error_code_to_string(ErrorCode code) {
    switch (code) {
        case ERR_SUCCESS: return "Success";
        case ERR_NULL_POINTER: return "Null pointer";
        case ERR_INVALID_ARGUMENT: return "Invalid argument";
        case ERR_OUT_OF_MEMORY: return "Out of memory";
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_PERMISSION_DENIED: return "Permission denied";
        case ERR_BUFFER_OVERFLOW: return "Buffer overflow";
        case ERR_NETWORK_ERROR: return "Network error";
        case ERR_TIMEOUT: return "Timeout";
        default: return "Unknown error";
    }
}

void print_last_error(void) {
    if (g_last_error.code != ERR_SUCCESS) {
        fprintf(stderr, "ERROR [%d]: %s\n", g_last_error.code, g_last_error.message);
        fprintf(stderr, "  Location: %s:%d in %s()\n", 
                g_last_error.file, g_last_error.line, g_last_error.function);
        fprintf(stderr, "  Description: %s\n", error_code_to_string(g_last_error.code));
    }
}

ErrorCode get_last_error_code(void) {
    return g_last_error.code;
}

// Safe mathematical operations with error checking
ErrorCode safe_divide(double a, double b, double *result) {
    CHECK_NULL(result, "Result pointer is null");
    
    if (b == 0.0) {
        RETURN_ERROR(ERR_INVALID_ARGUMENT, "Division by zero");
    }
    
    *result = a / b;
    return ERR_SUCCESS;
}

ErrorCode safe_sqrt(double x, double *result) {
    CHECK_NULL(result, "Result pointer is null");
    
    if (x < 0.0) {
        RETURN_ERROR(ERR_INVALID_ARGUMENT, "Square root of negative number");
    }
    
    *result = sqrt(x);
    return ERR_SUCCESS;
}

// Safe memory operations
typedef struct {
    void *data;
    size_t size;
    size_t capacity;
} SafeBuffer;

ErrorCode safe_buffer_create(SafeBuffer **buffer, size_t initial_capacity) {
    CHECK_NULL(buffer, "Buffer pointer is null");
    
    *buffer = malloc(sizeof(SafeBuffer));
    CHECK_ALLOC(*buffer);
    
    (*buffer)->data = malloc(initial_capacity);
    if (!(*buffer)->data) {
        free(*buffer);
        *buffer = NULL;
        RETURN_ERROR(ERR_OUT_OF_MEMORY, "Buffer data allocation failed");
    }
    
    (*buffer)->size = 0;
    (*buffer)->capacity = initial_capacity;
    return ERR_SUCCESS;
}

ErrorCode safe_buffer_append(SafeBuffer *buffer, const void *data, size_t data_size) {
    CHECK_NULL(buffer, "Buffer is null");
    CHECK_NULL(data, "Data is null");
    
    if (data_size == 0) {
        return ERR_SUCCESS;  // Nothing to append
    }
    
    // Check for potential overflow
    if (buffer->size > SIZE_MAX - data_size) {
        RETURN_ERROR(ERR_BUFFER_OVERFLOW, "Size overflow");
    }
    
    size_t needed_size = buffer->size + data_size;
    
    // Resize if necessary
    if (needed_size > buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        if (new_capacity < needed_size) {
            new_capacity = needed_size;
        }
        
        void *new_data = realloc(buffer->data, new_capacity);
        CHECK_ALLOC(new_data);
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    memcpy((char*)buffer->data + buffer->size, data, data_size);
    buffer->size += data_size;
    
    return ERR_SUCCESS;
}

void safe_buffer_destroy(SafeBuffer *buffer) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
    }
}

// File operations with comprehensive error handling
ErrorCode safe_file_read(const char *filename, char **content, size_t *size) {
    CHECK_NULL(filename, "Filename is null");
    CHECK_NULL(content, "Content pointer is null");
    CHECK_NULL(size, "Size pointer is null");
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        switch (errno) {
            case ENOENT:
                RETURN_ERROR(ERR_FILE_NOT_FOUND, "File does not exist");
            case EACCES:
                RETURN_ERROR(ERR_PERMISSION_DENIED, "Permission denied");
            default:
                RETURN_ERROR(ERR_UNKNOWN, strerror(errno));
        }
    }
    
    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to seek to end of file");
    }
    
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to get file size");
    }
    
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to seek to beginning of file");
    }
    
    // Allocate buffer
    *content = malloc(file_size + 1);
    if (!*content) {
        fclose(file);
        RETURN_ERROR(ERR_OUT_OF_MEMORY, "Failed to allocate file buffer");
    }
    
    // Read file
    size_t bytes_read = fread(*content, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        free(*content);
        *content = NULL;
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to read complete file");
    }
    
    (*content)[file_size] = '\0';
    *size = file_size;
    
    fclose(file);
    return ERR    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Coverage support
if(ENABLE_COVERAGE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

# Find dependencies
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(M REQUIRED m)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add subdirectories
add_subdirectory(src)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Package configuration
include(GNUInstallDirs)
set(MATHUTILS_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/MathUtils)

# Export targets
install(TARGETS mathutils
    EXPORT MathUtilsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MathUtilsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfig.cmake"
    INSTALL_DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfigVersion.cmake"
    DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)

install(EXPORT MathUtilsTargets
    FILE MathUtilsTargets.cmake
    DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)
```

**src/CMakeLists.txt**:
```cmake
# Define library sources
set(MATHUTILS_SOURCES
    mathutils.c
)

set(MATHUTILS_HEADERS
    ../include/mathutils.h
)

# Create library target
if(BUILD_SHARED_LIBS)
    add_library(mathutils SHARED ${MATHUTILS_SOURCES})
    set_target_properties(mathutils PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_compile_definitions(mathutils PRIVATE MATHUTILS_EXPORTS)
else()
    add_library(mathutils STATIC ${MATHUTILS_SOURCES})
endif()

# Set properties
set_target_properties(mathutils PROPERTIES
    PUBLIC_HEADER "${MATHUTILS_HEADERS}"
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Link libraries
target_link_libraries(mathutils PRIVATE m)

# Include directories
target_include_directories(mathutils
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Symbol visibility
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(mathutils PRIVATE -fvisibility=hidden)
endif()
```

**tests/CMakeLists.txt**:
```cmake
# Find testing framework (we'll use a simple custom framework)
add_executable(test_mathutils
    test_mathutils.c
    test_framework.c
)

target_link_libraries(test_mathutils mathutils)

# Add test
add_test(NAME mathutils_tests COMMAND test_mathutils)

# Coverage target
if(ENABLE_COVERAGE)
    find_program(GCOV_PATH gcov)
    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    
    if(GCOV_PATH AND LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${LCOV_PATH} --directory . --zerocounters
            COMMAND ${CMAKE_MAKE_PROGRAM} test
            COMMAND ${LCOV_PATH} --directory . --capture --output-file coverage.info
            COMMAND ${LCOV_PATH} --remove coverage.info '/usr/*' --output-file coverage.info
            COMMAND ${GENHTML_PATH} -o coverage coverage.info
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )
    endif()
endif()
```

#### Package Management and Distribution

**pkg-config file (mathutils.pc.in)**:
```
prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: MathUtils
Description: Mathematical utilities library
Version: @PROJECT_VERSION@
Libs: -L${libdir} -lmathutils -lm
Cflags: -I${includedir}
```

**Creating Distribution Packages:**

```bash
# Create source distribution
mkdir mathutils-1.2.0
cp -r src include tests examples CMakeLists.txt mathutils-1.2.0/
tar czf mathutils-1.2.0.tar.gz mathutils-1.2.0

# Build RPM package (CentOS/RHEL)
rpmbuild -ta mathutils-1.2.0.tar.gz

# Build DEB package (Ubuntu/Debian)
# Create debian/ directory with control files
debuild -us -uc

# Cross-compilation example
mkdir build-arm
cd build-arm
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/arm-linux.cmake ..
make -j4
```

**Cross-compilation toolchain (arm-linux.cmake)**:
```cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

#### Symbol Visibility and Versioning

**Advanced Symbol Management:**

```c
/* symbol_version.h - Symbol versioning support */
#ifndef SYMBOL_VERSION_H
#define SYMBOL_VERSION_H

#ifdef __GNUC__
// Symbol versioning macros
#define SYMVER(name, version) \
    __asm__(".symver " #name "," #name "@" #version)

#define SYMVER_DEFAULT(name, version) \
    __asm__(".symver " #name "," #name "@@" #version)

// Version script example:
/*
MATHUTILS_1.0 {
    global:
        math_add;
        math_multiply;
    local:
        *;
};

MATHUTILS_1.1 {
    global:
        math_power;
} MATHUTILS_1.0;

MATHUTILS_1.2 {
    global:
        point2d_distance;
        circle_area;
} MATHUTILS_1.1;
*/

#endif // __GNUC__

#endif // SYMBOL_VERSION_H
```

```c
/* versioned_functions.c - Example of API versioning */
#include "mathutils.h"
#include "symbol_version.h"

// Version 1.0 implementation (deprecated)
double math_add_v1_0(double a, double b) {
    return a + b;  // Simple addition
}

// Version 1.2 implementation (current)
double math_add_v1_2(double a, double b) {
    // Enhanced with overflow checking
    double result = a + b;
    if ((a > 0 && b > 0 && result < a) ||
        (a < 0 && b < 0 && result > a)) {
        // Overflow detected
        return (a > 0) ? INFINITY : -INFINITY;
    }
    return result;
}

// Set up symbol versioning
#ifdef __GNUC__
SYMVER(math_add_v1_0, MATHUTILS_1.0);
SYMVER_DEFAULT(math_add_v1_2, MATHUTILS_1.2);

// Create aliases
double math_add(double a, double b) __attribute__((alias("math_add_v1_2")));
#else
// Fallback for non-GCC compilers
double math_add(double a, double b) {
    return math_add_v1_2(a, b);
}
#endif
```

### 18. C Standards Evolution (C11 → C23) {#c-standards}

**Figure Reference: [C Standards Timeline and Features]**

The evolution of C standards brings new features, improved safety, and better performance. Understanding these changes is crucial for modern C development.

#### C11 Features and Improvements

**Threading Support:**

```c
/* c11_threads.c - C11 threading example */
#include <stdio.h>
#include <threads.h>
#include <time.h>

// Thread-local storage
_Thread_local int thread_id = 0;
_Thread_local char thread_name[32];

// Mutex for thread-safe printing
mtx_t print_mutex;
atomic_int global_counter = ATOMIC_VAR_INIT(0);

typedef struct {
    int id;
    int iterations;
} thread_data_t;

int worker_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    thread_id = data->id;
    snprintf(thread_name, sizeof(thread_name), "Worker-%d", thread_id);
    
    for (int i = 0; i < data->iterations; i++) {
        // Thread-safe increment
        int old_value = atomic_fetch_add(&global_counter, 1);
        
        // Thread-safe printing
        mtx_lock(&print_mutex);
        printf("[%s] Iteration %d, global counter: %d -> %d\n", 
               thread_name, i, old_value, old_value + 1);
        mtx_unlock(&print_mutex);
        
        // Simulate work
        struct timespec ts = {0, 10000000}; // 10ms
        thrd_sleep(&ts, NULL);
    }
    
    return thread_id;
}

void c11_threading_demo(void) {
    printf("=== C11 Threading Demo ===\n");
    
    if (mtx_init(&print_mutex, mtx_plain) != thrd_success) {
        printf("Failed to initialize mutex\n");
        return;
    }
    
    const int num_threads = 3;
    thrd_t threads[num_threads];
    thread_data_t thread_data[num_threads];
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].id = i + 1;
        thread_data[i].iterations = 5;
        
        if (thrd_create(&threads[i], worker_thread, &thread_data[i]) != thrd_success) {
            printf("Failed to create thread %d\n", i);
            continue;
        }
    }
    
    // Wait for threads to complete
    for (int i = 0; i < num_threads; i++) {
        int result;
        thrd_join(threads[i], &result);
        printf("Thread %d completed with result: %d\n", i + 1, result);
    }
    
    printf("Final global counter: %d\n", atomic_load(&global_counter));
    
    mtx_destroy(&print_mutex);
}
```

**Static Assertions:**

```c
/* c11_static_assert.c - Compile-time assertions */
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

// Basic static assertions
_Static_assert(sizeof(int) >= 4, "int must be at least 32 bits");
_Static_assert(sizeof(void*) == sizeof(uintptr_t), "pointer size mismatch");

// Structure layout assertions
typedef struct {
    char flag;
    int value;
    double data;
} TestStruct;

_Static_assert(sizeof(TestStruct) >= sizeof(char) + sizeof(int) + sizeof(double),
               "TestStruct appears to have negative padding");

// Conditional compilation with static assertions
#define MAX_BUFFER_SIZE 1024
_Static_assert(MAX_BUFFER_SIZE >= 512, "Buffer size too small");
_Static_assert(MAX_BUFFER_SIZE <= 4096, "Buffer size too large");

// Array size validation
#define ARRAY_SIZE 10
int test_array[ARRAY_SIZE];
_Static_assert(sizeof(test_array) == ARRAY_SIZE * sizeof(int), 
               "Array size calculation error");

void static_assertions_demo(void) {
    printf("=== C11 Static Assertions Demo ===\n");
    
    printf("All static assertions passed at compile time!\n");
    printf("sizeof(int): %zu\n", sizeof(int));
    printf("sizeof(void*): %zu\n", sizeof(void*));
    printf("sizeof(TestStruct): %zu\n", sizeof(TestStruct));
    printf("MAX_BUFFER_SIZE: %d\n", MAX_BUFFER_SIZE);
    
    // Runtime assertion for comparison
    assert(MAX_BUFFER_SIZE > 0);  // This could fail at runtime
    printf("Runtime assertion also passed\n");
}
```

**Generic Selections (_Generic):**

```c
/* c11_generic.c - Generic programming support */
#include <stdio.h>
#include <math.h>
#include <complex.h>

// Generic macro for different types
#define ABS(x) _Generic((x), \
    int: abs, \
    long: labs, \
    long long: llabs, \
    float: fabsf, \
    double: fabs, \
    long double: fabsl, \
    float complex: cabsf, \
    double complex: cabs, \
    long double complex: cabsl \
)(x)

// Generic print macro
#define PRINT_TYPE(x) _Generic((x), \
    char: "char", \
    signed char: "signed char", \
    unsigned char: "unsigned char", \
    short: "short", \
    unsigned short: "unsigned short", \
    int: "int", \
    unsigned int: "unsigned int", \
    long: "long", \
    unsigned long: "unsigned long", \
    long long: "long long", \
    unsigned long long: "unsigned long long", \
    float: "float", \
    double: "double", \
    long double: "long double", \
    char*: "char*", \
    void*: "void*", \
    default: "unknown" \
)

// Generic comparison
#define MAX_GENERIC(a, b) _Generic((a), \
    int: ((a) > (b) ? (a) : (b)), \
    float: fmaxf((a), (b)), \
    double: fmax((a), (b)), \
    long double: fmaxl((a), (b)), \
    default: ((a) > (b) ? (a) : (b)) \
)((a), (b))

void generic_demo(void) {
    printf("=== C11 Generic Programming Demo ===\n");
    
    // Test ABS macro with different types
    int i = -42;
    float f = -3.14f;
    double d = -2.718;
    double complex c = -1.0 + 2.0*I;
    
    printf("ABS(%d) = %d (type: %s)\n", i, ABS(i), PRINT_TYPE(i));
    printf("ABS(%.2f) = %.2f (type: %s)\n", f, ABS(f), PRINT_TYPE(f));
    printf("ABS(%.3f) = %.3f (type: %s)\n", d, ABS(d), PRINT_TYPE(d));
    printf("ABS(%.1f + %.1fi) = %.3f (type: %s)\n", 
           creal(c), cimag(c), ABS(c), PRINT_TYPE(c));
    
    // Test type detection
    char ch = 'A';
    char *str = "Hello";
    void *ptr = &i;
    
    printf("Type of '%c': %s\n", ch, PRINT_TYPE(ch));
    printf("Type of \"%s\": %s\n", str, PRINT_TYPE(str));
    printf("Type of pointer: %s\n", PRINT_TYPE(ptr));
    
    // Generic MAX
    printf("MAX_GENERIC(10, 20) = %d\n", MAX_GENERIC(10, 20));
    printf("MAX_GENERIC(3.14, 2.71) = %.2f\n", MAX_GENERIC(3.14, 2.71));
}
```

#### C17 Improvements

C17 (C18) was primarily a bug-fix release with no major new features, but it clarified several ambiguities:

```c
/* c17_improvements.c - C17 clarifications */
#include <stdio.h>
#include <string.h>

// C17 clarified behavior of these constructs
void c17_clarifications_demo(void) {
    printf("=== C17 Clarifications Demo ===\n");
    
    // Clarified: evaluation order in function calls
    int i = 0;
    printf("Evaluation order: i = %d, ++i = %d\n", i, ++i);
    // C17 clarifies this has unspecified behavior
    
    // Clarified: anonymous structure/union members
    struct {
        int a;
        struct {
            int b;
            int c;
        }; // Anonymous struct - C17 clarified this is valid
    } example = {1, {2, 3}};
    
    printf("Anonymous struct access: a=%d, b=%d, c=%d\n", 
           example.a, example.b, example.c);
    
    // Clarified: atomic operations memory ordering
    printf("C17 clarified memory ordering for atomic operations\n");
    
    // Clarified: thread storage duration
    printf("C17 clarified _Thread_local behavior\n");
}
```

#### C23 New Features

C23 introduces significant new features and improvements:

**New Keywords and Types:**

```c
/* c23_features.c - C23 new features */
#include <stdio.h>

// C23: nullptr constant and nullptr_t type
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 202311L

#include <stddef.h>

void c23_nullptr_demo(void) {
    printf("=== C23 nullptr Demo ===\n");
    
    // nullptr is a new keyword in C23
    int *ptr = nullptr;  // Instead of NULL
    printf("ptr initialized to nullptr: %p\n", (void*)ptr);
    
    // nullptr_t type
    nullptr_t null_value = nullptr;
    ptr = null_value;
    
    if (ptr == nullptr) {
        printf("ptr is nullptr\n");
    }
    
    // nullptr is implicitly convertible to any pointer type
    void *void_ptr = nullptr;
    char *char_ptr = nullptr;
    
    printf("Different pointer types can be set to nullptr\n");
}

// C23: typeof and typeof_unqual operators
void c23_typeof_demo(void) {
    printf("=== C23 typeof Demo ===\n");
    
    int x = 42;
    typeof(x) y = x;  // y has the same type as x
    printf("x = %d, y = %d\n", x, y);
    
    const int cx = 100;
    typeof(cx) cy = 200;         // cy is const int
    typeof_unqual(cx) cz = 300;  // cz is int (qualification removed)
    
    printf("cx = %d, cy = %d, cz = %d\n", cx, cy, cz);
    
    // typeof with expressions
    typeof(x + y) sum = x + y;
    printf("sum = %d\n", sum);
    
    // Array types
    int arr[10];
    typeof(arr) arr2;  // arr2 is int[10]
    printf("sizeof(arr) = %zu, sizeof(arr2) = %zu\n", sizeof(arr), sizeof(arr2));
}

// C23: _BitInt(N) - arbitrary precision integers
void c23_bitint_demo(void) {
    printf("=== C23 _BitInt Demo ===\n");
    
    // _BitInt can have any width from 1 to implementation-defined maximum
    _BitInt(128) big_int = 0;
    _BitInt(7) small_int = 100;  // 7-bit signed integer (-64 to 63)
    
    big_int = 1;
    for (int i = 0; i < 100; i++) {
        big_int *= 2;  // 2^100
    }
    
    printf("2^100 calculated with _BitInt(128)\n");
    printf("small_int (7-bit) = %d\n", (int)small_int);
    
    // Unsigned _BitInt
    unsigned _BitInt(64) ubig = 18446744073709551615UWB;  // Max uint64
    printf("Large unsigned _BitInt value set\n");
}

// C23: char8_t for UTF-8
void c23_char8_demo(void) {
    printf("=== C23 char8_t Demo ===\n");
    
    // char8_t for UTF-8 encoded data
    char8_t utf8_string[] = u8"Hello, 世界! 🌍";
    printf("UTF-8 string length: %zu bytes\n", sizeof(utf8_string));
    
    // Print UTF-8 string (cast to char* for printf)
    printf("UTF-8 content: %s\n", (char*)utf8_string);
}

// C23: Enhanced Enums
enum Color : unsigned char {  // Underlying type specification
    RED = 1,
    GREEN = 2,
    BLUE = 4,
    YELLOW = RED | GREEN,  // Expression in initializer
    CYAN = GREEN | BLUE,
    MAGENTA = RED | BLUE,
    WHITE = RED | GREEN | BLUE
};

void c23_enhanced_enums_demo(void) {
    printf("=== C23 Enhanced Enums Demo ===\n");
    
    enum Color color = YELLOW;
    printf("Color value: %u\n", color);
    printf("sizeof(enum Color): %zu\n", sizeof(enum Color));
    
    // Bitwise operations with enum values
    enum Color purple = RED | BLUE;
    printf("Purple (RED | BLUE): %u\n", purple);
}

// C23: Attributes
[[deprecated("Use new_function() instead")]]
void old_function(void) {
    printf("This is a deprecated function\n");
}

[[nodiscard]]
int important_calculation(int x) {
    return x * x + 2 * x + 1;
}

[[maybe_unused]]
static int debug_value = 42;

void c23_attributes_demo(void) {
    printf("=== C23 Attributes Demo ===\n");
    
    old_function();  // Should generate deprecation warning
    
    // This should generate a warning if result is unused
    important_calculation(5);
    
    // This usage is correct
    int result = important_calculation(10);
    printf("Calculation result: %d\n", result);
}

// C23: Improved Unicode support
void c23_unicode_demo(void) {
    printf("=== C23 Unicode Demo ===\n");
    
    // Named universal character constants (implementation-dependent)
    char32_t emoji = U'🌟';  // Unicode star emoji
    char16_t chinese = u'中'; // Chinese character
    
    printf("Unicode support improved in C23\n");
    printf("char32_t size: %zu\n", sizeof(char32_t));
    printf("char16_t size: %zu\n", sizeof(char16_t));
}

// C23: constexpr for compile-time constants
constexpr int BUFFER_SIZE = 1024;
constexpr double PI = 3.14159265358979323846;

void c23_constexpr_demo(void) {
    printf("=== C23 constexpr Demo ===\n");
    
    char buffer[BUFFER_SIZE];  // Can be used in constant expressions
    printf("Buffer size: %d\n", BUFFER_SIZE);
    printf("PI value: %.10f\n", PI);
    
    // constexpr ensures compile-time evaluation
    constexpr int factorial_5 = 5 * 4 * 3 * 2 * 1;
    printf("Factorial of 5: %d\n", factorial_5);
}

#endif // C23 check
#endif // __STDC_VERSION__ check

// Fallback for older standards
void c23_features_demo(void) {
    printf("=== C23 Features Demo ===\n");
    
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 202311L
    printf("C23 features available!\n");
    c23_nullptr_demo();
    c23_typeof_demo();
    c23_bitint_demo();
    c23_char8_demo();
    c23_enhanced_enums_demo();
    c23_attributes_demo();
    c23_unicode_demo();
    c23_constexpr_demo();
#else
    printf("C23 features not available in this compiler version\n");
    printf("Current standard version: %ld\n", __STDC_VERSION__);
    printf("C23 requires __STDC_VERSION__ >= 202311L\n");
#endif
#else
    printf("Standard version not defined\n");
#endif
}
```

#### Feature Comparison and Migration Guide

**Figure Reference: [C Standards Feature Comparison Table]**

```c
/* standards_comparison.c - Feature comparison across standards */
#include <stdio.h>

void standards_comparison_demo(void) {
    printf("=== C Standards Feature Comparison ===\n");
    
    printf("Standard    | Year | Key Features\n");
    printf("------------|------|------------------------------------------\n");
    printf("C89/C90     | 1989 | First standardized C, function prototypes\n");
    printf("C99         | 1999 | VLA, inline, _Bool, complex, restrict\n");
    printf("C11         | 2011 | threads, atomics, _Generic, _Static_assert\n");
    printf("C17/C18     | 2017 | Bug fixes, clarifications\n");
    printf("C23         | 2023 | nullptr, typeof, _BitInt, attributes\n");
    
    printf("\nFeature availability check:\n");
    
    // C99 features
    #if __STDC_VERSION__ >= 199901L
    printf("✓ C99: Variable Length Arrays available\n");
    printf("✓ C99: inline keyword available\n");
    printf("✓ C99: _Bool type available\n");
    #else
    printf("✗ C99 features not available\n");
    #endif
    
    // C11 features
    #if __STDC_VERSION__ >= 201112L
    printf("✓ C11: _Generic available\n");
    printf("✓ C11: _Static_assert available\n");
    printf("✓ C11: _Atomic available\n");
    #ifndef __STDC_NO_THREADS__
    printf("✓ C11: Threading support available\n");
    #else
    printf("⚠ C11: Threading support not available\n");
    #endif
    #else
    printf("✗ C11 features not available\n");
    #endif
    
    // C23 features
    #if __STDC_VERSION__ >= 202311L
    printf("✓ C23: typeof available\n");
    printf("✓ C23: nullptr available\n");
    printf("✓ C23: _BitInt available\n");
    printf("✓ C23: constexpr available\n");
    #else
    printf("✗ C23 features not available\n");
    #endif
}

// Migration strategies
void migration_strategies(void) {
    printf("\n=== Migration Strategies ===\n");
    
    printf("When migrating between C standards:\n");
    printf("1. Use feature test macros for compatibility\n");
    printf("2. Provide fallback implementations\n");
    printf("3. Use compiler-specific extensions carefully\n");
    printf("4. Test thoroughly on target platforms\n");
    
    // Example: Safe _Generic usage with fallback
    #if __STDC_VERSION__ >= 201112L
    #define TYPE_SAFE_ABS(x) _Generic((x), \
        int: abs, \
        long: labs, \
        double: fabs, \
        float: fabsf \
    )(x)
    #else
    // Fallback macro (less type-safe)
    #define TYPE_SAFE_ABS(x) ((x) < 0 ? -(x) : (x))
    #endif
    
    int test_val = -42;
    printf("TYPE_SAFE_ABS(-42) = %d\n", TYPE_SAFE_ABS(test_val));
}

int main(void) {
    c11_threading_demo();
    static_assertions_demo();
    generic_demo();
    c17_clarifications_demo();
    c23_features_demo();
    standards_comparison_demo();
    migration_strategies();
    
    return 0;
}
```

#### Concepts ⚙
- Thread-local storage and atomic operations
- Generic programming with _Generic
- Compile-time assertions and constexpr
- Modern C type system improvements

#### Errors ⚠
- Threading race conditions without proper synchronization
- Misusing _Generic with incompatible types
- Assuming C23 features in older compilers
- Incorrect attribute usage

#### Tips 🧠
- Use feature test macros for portable code
- Prefer standard threading over platform-specific APIs
- Leverage _Generic for type-safe generic programming
- Consider compiler support before adopting new standards

#### Tools 🔧
- Thread sanitizer for concurrency bug detection
- Static analyzers for modern C features
- Compiler feature detection tools
- Cross-platform build systems with standard selection

---

### 19. Advanced String Manipulation {#advanced-strings}

Advanced string processing involves efficient algorithms, Unicode handling, pattern matching, and memory-safe operations.

#### Efficient String Algorithms

```c
/* advanced_strings.c - Advanced string manipulation techniques */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

// Boyer-Moore string search algorithm    cmp = strcmp("hello", "hello");
    printf("strcmp(\"hello\", \"hello\") = %d\n", cmp);
    
    // Safe string functions (bounds checking)
    char safe_str[10];
    strncpy(safe_str, "This is a very long string", sizeof(safe_str) - 1);
    safe_str[sizeof(safe_str) - 1] = '\0';  // Ensure null termination
    printf("strncpy result: \"%s\"\n", safe_str);
    
    // String search
    char *found = strstr("Hello, World!", "World");
    if (found) {
        printf("Found \"World\" at position: %ld\n", found - "Hello, World!");
    }
    
    // Character search
    found = strchr("programming", 'g');
    if (found) {
        printf("Found 'g' at position: %ld\n", found - "programming");
    }
}

void string_advanced_functions(void) {
    printf("\n=== Advanced String Functions ===\n");
    
    char text[] = "apple,banana,cherry,date";
    char *token;
    char delimiters[] = ",";
    
    printf("Original string: \"%s\"\n", text);
    printf("Tokens:\n");
    
    // String tokenization
    token = strtok(text, delimiters);
    int count = 1;
    while (token != NULL) {
        printf("  Token %d: \"%s\"\n", count++, token);
        token = strtok(NULL, delimiters);
    }
    
    // String to number conversions
    printf("\nString to number conversions:\n");
    
    char *int_str = "42";
    char *float_str = "3.14159";
    char *hex_str = "0xFF";
    char *invalid_str = "abc123";
    
    int int_val = atoi(int_str);
    double float_val = atof(float_str);
    long hex_val = strtol(hex_str, NULL, 16);
    
    printf("atoi(\"%s\") = %d\n", int_str, int_val);
    printf("atof(\"%s\") = %f\n", float_str, float_val);
    printf("strtol(\"%s\", NULL, 16) = %ld\n", hex_str, hex_val);
    
    // Safe conversion with error checking
    char *endptr;
    long safe_val = strtol(invalid_str, &endptr, 10);
    if (*endptr != '\0') {
        printf("strtol(\"%s\") failed at character: '%c'\n", invalid_str, *endptr);
    } else {
        printf("strtol(\"%s\") = %ld\n", invalid_str, safe_val);
    }
    
    // String formatting
    char buffer[200];
    int written = snprintf(buffer, sizeof(buffer), 
                          "Formatted: int=%d, float=%.2f, string=\"%s\"", 
                          42, 3.14159, "test");
    printf("snprintf result: \"%s\" (%d characters)\n", buffer, written);
}

void string_manipulation_functions(void) {
    printf("\n=== String Manipulation Functions ===\n");
    
    char text[] = "  Hello, World!  ";
    printf("Original: \"|%s|\"\n", text);
    
    // Manual string trimming function
    char* trim_whitespace(char *str) {
        // Trim leading whitespace
        while (isspace((unsigned char)*str)) str++;
        
        if (*str == '\0') return str;  // All spaces
        
        // Trim trailing whitespace
        char *end = str + strlen(str) - 1;
        while (end > str && isspace((unsigned char)*end)) end--;
        
        end[1] = '\0';
        return str;
    }
    
    char trimmed[100];
    strcpy(trimmed, text);
    char *result = trim_whitespace(trimmed);
    printf("Trimmed: \"|%s|\"\n", result);
    
    // Case conversion
    char mixed_case[] = "Hello, World!";
    printf("Original case: \"%s\"\n", mixed_case);
    
    // Convert to uppercase
    for (size_t i = 0; mixed_case[i]; i++) {
        mixed_case[i] = toupper((unsigned char)mixed_case[i]);
    }
    printf("Uppercase: \"%s\"\n", mixed_case);
    
    // Convert to lowercase
    for (size_t i = 0; mixed_case[i]; i++) {
        mixed_case[i] = tolower((unsigned char)mixed_case[i]);
    }
    printf("Lowercase: \"%s\"\n", mixed_case);
    
    // String replacement (simple version)
    char source[] = "The quick brown fox jumps over the lazy dog";
    char target[] = "quick";
    char replacement[] = "slow";
    
    printf("Original: \"%s\"\n", source);
    
    char *pos = strstr(source, target);
    if (pos) {
        char result[200];
        size_t prefix_len = pos - source;
        
        // Copy prefix
        strncpy(result, source, prefix_len);
        result[prefix_len] = '\0';
        
        // Add replacement
        strcat(result, replacement);
        
        // Add suffix
        strcat(result, pos + strlen(target));
        
        printf("After replacement: \"%s\"\n", result);
    }
}

// Mathematical Functions
#include <math.h>

void math_basic_functions(void) {
    printf("\n=== Basic Mathematical Functions ===\n");
    
    double x = 16.0, y = 2.5;
    
    // Power and root functions
    printf("pow(%.1f, %.1f) = %.3f\n", x, y, pow(x, y));
    printf("sqrt(%.1f) = %.3f\n", x, sqrt(x));
    printf("cbrt(%.1f) = %.3f\n", x, cbrt(x));  // C99
    
    // Exponential and logarithmic
    printf("exp(%.1f) = %.3f\n", y, exp(y));
    printf("log(%.1f) = %.3f\n", x, log(x));      // Natural log
    printf("log10(%.1f) = %.3f\n", x, log10(x));  // Base-10 log
    printf("log2(%.1f) = %.3f\n", x, log2(x));    // Base-2 log (C99)
    
    // Trigonometric functions
    double angle_deg = 45.0;
    double angle_rad = angle_deg * M_PI / 180.0;
    
    printf("sin(%.0f°) = %.3f\n", angle_deg, sin(angle_rad));
    printf("cos(%.0f°) = %.3f\n", angle_deg, cos(angle_rad));
    printf("tan(%.0f°) = %.3f\n", angle_deg, tan(angle_rad));
    
    // Inverse trigonometric
    double ratio = 0.707;  // approximately sin(45°)
    printf("asin(%.3f) = %.1f°\n", ratio, asin(ratio) * 180.0 / M_PI);
    
    // Hyperbolic functions
    printf("sinh(%.1f) = %.3f\n", y, sinh(y));
    printf("cosh(%.1f) = %.3f\n", y, cosh(y));
    printf("tanh(%.1f) = %.3f\n", y, tanh(y));
}

void math_utility_functions(void) {
    printf("\n=== Mathematical Utility Functions ===\n");
    
    double values[] = {-3.7, -2.3, 0.0, 1.8, 4.2};
    size_t count = sizeof(values) / sizeof(values[0]);
    
    for (size_t i = 0; i < count; i++) {
        double x = values[i];
        printf("x = %.1f:\n", x);
        printf("  fabs(x) = %.1f\n", fabs(x));
        printf("  ceil(x) = %.1f\n", ceil(x));
        printf("  floor(x) = %.1f\n", floor(x));
        printf("  round(x) = %.1f\n", round(x));    // C99
        printf("  trunc(x) = %.1f\n", trunc(x));    // C99
        printf("\n");
    }
    
    // Modulo operations
    double a = 10.5, b = 3.2;
    printf("fmod(%.1f, %.1f) = %.3f\n", a, b, fmod(a, b));
    printf("remainder(%.1f, %.1f) = %.3f\n", a, b, remainder(a, b));  // C99
    
    // Min/Max functions (C99)
    printf("fmin(%.1f, %.1f) = %.1f\n", a, b, fmin(a, b));
    printf("fmax(%.1f, %.1f) = %.1f\n", a, b, fmax(a, b));
    
    // Special values
    printf("\nSpecial floating-point values:\n");
    printf("INFINITY: %f\n", INFINITY);
    printf("NAN: %f\n", NAN);
    printf("isfinite(INFINITY): %d\n", isfinite(INFINITY));
    printf("isnan(NAN): %d\n", isnan(NAN));
    printf("isinf(INFINITY): %d\n", isinf(INFINITY));
}

// Memory Functions
void memory_functions(void) {
    printf("\n=== Memory Functions ===\n");
    
    // Memory allocation functions covered elsewhere
    // Focus on memory manipulation functions
    
    char buffer1[20] = "Hello, World!";
    char buffer2[20];
    
    printf("Original buffer1: \"%s\"\n", buffer1);
    
    // Memory copy
    memcpy(buffer2, buffer1, strlen(buffer1) + 1);
    printf("After memcpy to buffer2: \"%s\"\n", buffer2);
    
    // Memory move (safe for overlapping regions)
    memmove(buffer1 + 2, buffer1, strlen(buffer1) + 1);
    printf("After memmove (shift right 2): \"%s\"\n", buffer1);
    
    // Memory set
    memset(buffer2, '*', 5);
    buffer2[5] = '\0';
    printf("After memset with '*': \"%s\"\n", buffer2);
    
    // Memory comparison
    char data1[] = {1, 2, 3, 4, 5};
    char data2[] = {1, 2, 3, 4, 6};
    
    int cmp = memcmp(data1, data2, 5);
    printf("memcmp result: %d\n", cmp);
    
    // Find byte in memory
    char text[] = "Find the letter 'e' in this text";
    void *found = memchr(text, 'e', strlen(text));
    if (found) {
        printf("Found 'e' at position: %ld\n", (char*)found - text);
    }
}

// Time Functions
#include <time.h>

void time_functions(void) {
    printf("\n=== Time Functions ===\n");
    
    // Current time
    time_t current_time = time(NULL);
    printf("Current timestamp: %ld\n", (long)current_time);
    
    // Convert to string
    printf("Current time string: %s", ctime(&current_time));
    
    // Structured time
    struct tm *local_time = localtime(&current_time);
    printf("Structured time:\n");
    printf("  Year: %d\n", local_time->tm_year + 1900);
    printf("  Month: %d\n", local_time->tm_mon + 1);
    printf("  Day: %d\n", local_time->tm_mday);
    printf("  Hour: %d\n", local_time->tm_hour);
    printf("  Minute: %d\n", local_time->tm_min);
    printf("  Second: %d\n", local_time->tm_sec);
    printf("  Day of week: %d\n", local_time->tm_wday);
    printf("  Day of year: %d\n", local_time->tm_yday);
    
    // Formatted time
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);
    printf("Formatted time: %s\n", time_str);
    
    strftime(time_str, sizeof(time_str), "%A, %B %d, %Y", local_time);
    printf("Long format: %s\n", time_str);
    
    // Timing operations
    clock_t start = clock();
    
    // Simulate some work
    volatile long sum = 0;
    for (long i = 0; i < 1000000; i++) {
        sum += i;
    }
    
    clock_t end = clock();
    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("CPU time for calculation: %.4f seconds\n", cpu_time);
    
    // High-resolution timing (C11)
    #ifdef __STDC_VERSION__
    #if __STDC_VERSION__ >= 201112L
    #include <time.h>
    struct timespec start_time, end_time;
    
    if (timespec_get(&start_time, TIME_UTC)) {
        // Some quick operation
        volatile int result = 0;
        for (int i = 0; i < 1000; i++) result += i;
        
        timespec_get(&end_time, TIME_UTC);
        
        double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
        printf("High-resolution elapsed time: %.6f seconds\n", elapsed);
    }
    #endif
    #endif
}

// Random Number Functions
void random_functions(void) {
    printf("\n=== Random Number Functions ===\n");
    
    // Seed the random number generator
    srand((unsigned int)time(NULL));
    
    printf("Random integers (0 to RAND_MAX):\n");
    for (int i = 0; i < 5; i++) {
        printf("  %d\n", rand());
    }
    
    printf("Random integers (1 to 100):\n");
    for (int i = 0; i < 10; i++) {
        int random_val = rand() % 100 + 1;
        printf("%3d ", random_val);
    }
    printf("\n");
    
    printf("Random doubles (0.0 to 1.0):\n");
    for (int i = 0; i < 5; i++) {
        double random_double = (double)rand() / RAND_MAX;
        printf("  %.6f\n", random_double);
    }
    
    printf("RAND_MAX = %d\n", RAND_MAX);
    
    // Better random number generation (demonstration)
    void generate_random_range(int min, int max, int count) {
        printf("Random numbers in range [%d, %d]:\n", min, max);
        for (int i = 0; i < count; i++) {
            int range = max - min + 1;
            int random_val = min + rand() / (RAND_MAX / range + 1);
            printf("%3d ", random_val);
        }
        printf("\n");
    }
    
    generate_random_range(10, 50, 10);
}

// Character Classification Functions
void character_functions(void) {
    printf("\n=== Character Classification Functions ===\n");
    
    char test_chars[] = "Hello123! @#$";
    
    printf("Character analysis for: \"%s\"\n", test_chars);
    printf("Char | Alpha | Digit | Space | Upper | Lower | Punct | Print\n");
    printf("-----|-------|-------|-------|-------|-------|-------|------\n");
    
    for (size_t i = 0; test_chars[i]; i++) {
        char c = test_chars[i];
        printf(" '%c' |   %d   |   %d   |   %d   |   %d   |   %d   |   %d   |   %d\n",
               c,
               isalpha(c) ? 1 : 0,
               isdigit(c) ? 1 : 0,
               isspace(c) ? 1 : 0,
               isupper(c) ? 1 : 0,
               islower(c) ? 1 : 0,
               ispunct(c) ? 1 : 0,
               isprint(c) ? 1 : 0);
    }
    
    // Character conversion
    printf("\nCharacter conversion examples:\n");
    char mixed[] = "Hello, World!";
    printf("Original: %s\n", mixed);
    
    printf("Uppercase: ");
    for (size_t i = 0; mixed[i]; i++) {
        putchar(toupper(mixed[i]));
    }
    printf("\n");
    
    printf("Lowercase: ");
    for (size_t i = 0; mixed[i]; i++) {
        putchar(tolower(mixed[i]));
    }
    printf("\n");
}

// System Functions
void system_functions(void) {
    printf("\n=== System Functions ===\n");
    
    // Environment variables
    printf("Environment variables:\n");
    char *path = getenv("PATH");
    if (path) {
        printf("PATH length: %zu characters\n", strlen(path));
        printf("PATH starts with: %.50s...\n", path);
    } else {
        printf("PATH not found\n");
    }
    
    char *home = getenv("HOME");  // Unix/Linux
    if (!home) {
        home = getenv("USERPROFILE");  // Windows
    }
    if (home) {
        printf("Home directory: %s\n", home);
    }
    
    // Program termination
    printf("Program termination constants:\n");
    printf("EXIT_SUCCESS = %d\n", EXIT_SUCCESS);
    printf("EXIT_FAILURE = %d\n", EXIT_FAILURE);
    
    // Temporary files
    printf("Temporary filename: %s\n", tmpnam(NULL));
    
    // Note: system() function exists but is dangerous and should be avoided
    printf("Warning: system() function exists but should be avoided for security\n");
}

// Real-world example: String utilities library
typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} String;

String* string_create(const char *initial) {
    String *str = malloc(sizeof(String));
    if (!str) return NULL;
    
    size_t len = initial ? strlen(initial) : 0;
    str->capacity = len + 16;  // Some extra capacity
    str->data = malloc(str->capacity);
    
    if (!str->data) {
        free(str);
        return NULL;
    }
    
    if (initial) {
        strcpy(str->data, initial);
        str->length = len;
    } else {
        str->data[0] = '\0';
        str->length = 0;
    }
    
    return str;
}

void string_append(String *str, const char *text) {
    if (!str || !text) return;
    
    size_t text_len = strlen(text);
    size_t new_length = str->length + text_len;
    
    // Resize if necessary
    if (new_length >= str->capacity) {
        size_t new_capacity = new_length * 2;
        char *new_data = realloc(str->data, new_capacity);
        if (!new_data) return;  // Failed to resize
        
        str->data = new_data;
        str->capacity = new_capacity;
    }
    
    strcat(str->data, text);
    str->length = new_length;
}

void string_destroy(String *str) {
    if (str) {
        free(str->data);
        free(str);
    }
}

void string_utilities_demo(void) {
    printf("\n=== String Utilities Demo ===\n");
    
    String *str = string_create("Hello");
    if (!str) {
        printf("Failed to create string\n");
        return;
    }
    
    printf("Initial string: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    string_append(str, ", ");
    string_append(str, "World!");
    printf("After appends: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    // Force reallocation
    string_append(str, " This is a longer text that should force reallocation.");
    printf("After long append: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    string_destroy(str);
    printf("String destroyed\n");
}

int main(void) {
    string_basic_functions();
    string_advanced_functions();
    string_manipulation_functions();
    math_basic_functions();
    math_utility_functions();
    memory_functions();
    time_functions();
    random_functions();
    character_functions();
    system_functions();
    string_utilities_demo();
    
    printf("\n=== Standard Library Best Practices ===\n");
    printf("1. Always check return values for allocation functions\n");
    printf("2. Use bounds-checking string functions (strncpy, snprintf)\n");
    printf("3. Be aware of locale-dependent functions (isalpha, toupper)\n");
    printf("4. Understand the difference between memcpy and memmove\n");
    printf("5. Initialize random seed appropriately for your use case\n");
    printf("6. Use appropriate math functions for your precision needs\n");
    printf("7. Handle special floating-point values (NaN, infinity)\n");
    
    return 0;
}
```

#### Concepts ⚙
- String manipulation and safety considerations
- Mathematical function accuracy and domains
- Memory manipulation vs string functions
- Locale-dependent character operations

#### Errors ⚠
- Buffer overflows with string functions
- Not null-terminating strings after strncpy
- Ignoring return values from conversion functions
- Using uninitialized random number generator

#### Tips 🧠
- Use `snprintf` instead of `sprintf` for safety
- Check `errno` after math functions for error conditions
- Consider locale settings for character classification
- Use `strtol` family instead of `atoi` for better error handling

#### Tools 🔧
- Address Sanitizer for buffer overflow detection
- Math library unit testing frameworks
- Locale testing tools
- Performance profilers for string-heavy code

---

## Part III: Advanced Level - Professional Development

### 17. Modular Programming and Libraries {#modular-programming}

Modular programming is essential for creating maintainable, reusable, and scalable C applications. This section covers library creation, linking, and best practices.

#### Creating Static and Dynamic Libraries

**Figure Reference: [Library Types Comparison Diagram]**

```c
/* mathutils.h - Header file for mathematical utilities */
#ifndef MATHUTILS_H
#define MATHUTILS_H

#ifdef __cplusplus
extern "C" {
#endif

// Version information
#define MATHUTILS_VERSION_MAJOR 1
#define MATHUTILS_VERSION_MINOR 2
#define MATHUTILS_VERSION_PATCH 0

// API visibility macros
#ifdef _WIN32
    #ifdef MATHUTILS_EXPORTS
        #define MATHUTILS_API __declspec(dllexport)
    #else
        #define MATHUTILS_API __declspec(dllimport)
    #endif
#else
    #ifdef MATHUTILS_EXPORTS
        #define MATHUTILS_API __attribute__((visibility("default")))
    #else
        #define MATHUTILS_API
    #endif
#endif

// Data structures
typedef struct {
    double x, y;
} Point2D;

typedef struct {
    double x, y, z;
} Point3D;

typedef struct {
    Point2D center;
    double radius;
} Circle;

// Basic math operations
MATHUTILS_API double math_add(double a, double b);
MATHUTILS_API double math_multiply(double a, double b);
MATHUTILS_API double math_power(double base, double exponent);

// Geometry functions
MATHUTILS_API double point2d_distance(const Point2D *p1, const Point2D *p2);
MATHUTILS_API Point2D point2d_midpoint(const Point2D *p1, const Point2D *p2);
MATHUTILS_API double circle_area(const Circle *circle);
MATHUTILS_API double circle_circumference(const Circle *circle);

// Advanced operations
MATHUTILS_API int is_point_in_circle(const Point2D *point, const Circle *circle);
MATHUTILS_API double* matrix_multiply(const double *a, const double *b, 
                                     int rows_a, int cols_a, int cols_b);

// Utility functions
MATHUTILS_API const char* mathutils_version(void);
MATHUTILS_API void mathutils_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* MATHUTILS_H */
```

```c
/* mathutils.c - Implementation file */
#include "mathutils.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

// Version string
static char version_string[32];

// Initialize version string
static void init_version_string(void) {
    snprintf(version_string, sizeof(version_string), "%d.%d.%d",
             MATHUTILS_VERSION_MAJOR, MATHUTILS_VERSION_MINOR, MATHUTILS_VERSION_PATCH);
}

// Basic math operations
MATHUTILS_API double math_add(double a, double b) {
    return a + b;
}

MATHUTILS_API double math_multiply(double a, double b) {
    return a * b;
}

MATHUTILS_API double math_power(double base, double exponent) {
    return pow(base, exponent);
}

// Geometry functions
MATHUTILS_API double point2d_distance(const Point2D *p1, const Point2D *p2) {
    if (!p1 || !p2) return -1.0;
    
    double dx = p2->x - p1->x;
    double dy = p2->y - p1->y;
    return sqrt(dx * dx + dy * dy);
}

MATHUTILS_API Point2D point2d_midpoint(const Point2D *p1, const Point2D *p2) {
    Point2D result = {0};
    if (p1 && p2) {
        result.x = (p1->x + p2->x) / 2.0;
        result.y = (p1->y + p2->y) / 2.0;
    }
    return result;
}

MATHUTILS_API double circle_area(const Circle *circle) {
    if (!circle || circle->radius < 0) return -1.0;
    return M_PI * circle->radius * circle->radius;
}

MATHUTILS_API double circle_circumference(const Circle *circle) {
    if (!circle || circle->radius < 0) return -1.0;
    return 2.0 * M_PI * circle->radius;
}

// Advanced operations
MATHUTILS_API int is_point_in_circle(const Point2D *point, const Circle *circle) {
    if (!point || !circle) return 0;
    
    double distance = point2d_distance(point, &circle->center);
    return distance <= circle->radius;
}

MATHUTILS_API double* matrix_multiply(const double *a, const double *b, 
                                     int rows_a, int cols_a, int cols_b) {
    if (!a || !b || rows_a <= 0 || cols_a <= 0 || cols_b <= 0) {
        return NULL;
    }
    
    double *result = calloc(rows_a * cols_b, sizeof(double));
    if (!result) return NULL;
    
    for (int i = 0; i < rows_a; i++) {
        for (int j = 0; j < cols_b; j++) {
            for (int k = 0; k < cols_a; k++) {
                result[i * cols_b + j] += a[i * cols_a + k] * b[k * cols_b + j];
            }
        }
    }
    
    return result;
}

// Utility functions
MATHUTILS_API const char* mathutils_version(void) {
    static int initialized = 0;
    if (!initialized) {
        init_version_string();
        initialized = 1;
    }
    return version_string;
}

MATHUTILS_API void mathutils_cleanup(void) {
    // Cleanup any global resources if needed
    // For this simple library, nothing to clean up
}

// Library constructor/destructor (GCC/Clang)
#ifdef __GNUC__
__attribute__((constructor))
static void mathutils_init(void) {
    printf("MathUtils library loaded (version %s)\n", mathutils_version());
}

__attribute__((destructor))
static void mathutils_fini(void) {
    printf("MathUtils library unloaded\n");
    mathutils_cleanup();
}
#endif
```

**Building the Library:**

```bash
# Static library
gcc -c -fPIC mathutils.c -o mathutils.o
ar rcs libmathutils.a mathutils.o

# Dynamic library (Linux)
gcc -shared -fPIC -DMATHUTILS_EXPORTS mathutils.c -o libmathutils.so -lm

# Dynamic library (macOS)
gcc -dynamiclib -fPIC -DMATHUTILS_EXPORTS mathutils.c -o libmathutils.dylib -lm

# Dynamic library (Windows with MinGW)
gcc -shared -fPIC -DMATHUTILS_EXPORTS mathutils.c -o mathutils.dll -lm
```

#### CMake Build System Integration

**Figure Reference: [CMake Project Structure Diagram]**

**CMakeLists.txt (Root)**:
```cmake
cmake_minimum_required(VERSION 3.15)
project(MathUtils VERSION 1.2.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)

# Compiler-specific settings
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(# Complete Professional Guide to C Programming Language
*From Beginner to Professional Developer*

---

## Table of Contents

### Part I: Beginner Level - Core Foundations
1. [Introduction to C Programming](#introduction)
2. [Development Environment Setup](#environment-setup)
3. [Variables and Constants](#variables-constants)
4. [Data Types and Memory](#data-types)
5. [Operators and Expressions](#operators)
6. [Control Flow Structures](#control-flow)
7. [Functions Fundamentals](#functions-fundamentals)
8. [Scope and Storage Classes](#scope-storage)
9. [Basic Input/Output Operations](#basic-io)

### Part II: Intermediate Level - Advanced Concepts
10. [Pointers and Memory Management](#pointers-memory)
11. [Arrays and Multidimensional Data](#arrays)
12. [Dynamic Memory Allocation](#dynamic-memory)
13. [Structures, Unions, and Enumerations](#structures-unions)
14. [File Input/Output Operations](#file-io)
15. [Preprocessor and Macros](#preprocessor)
16. [Standard Library Deep Dive](#standard-library)

### Part III: Advanced Level - Professional Development
17. [Modular Programming and Libraries](#modular-programming)
18. [Advanced String Manipulation](#advanced-strings)
19. [Error Handling and Debugging](#error-handling)
20. [Multithreading and Concurrency](#multithreading)
21. [System-Level Programming](#system-programming)
22. [C Standards Evolution](#c-standards)
23. [Performance Optimization](#performance)
24. [Secure Coding Practices](#secure-coding)

### Part IV: Special Sections
25. [Professional Development Practices](#professional-practices)
26. [Game Development with C](#game-development)

---

## Part I: Beginner Level - Core Foundations

### 1. Introduction to C Programming {#introduction}

#### Why Learn C?

C programming language, developed by Dennis Ritchie at Bell Labs in 1972, remains one of the most influential and widely-used programming languages today. Its impact extends far beyond its original purpose, serving as the foundation for numerous modern languages and systems.

**Modern Applications of C:**
- **Operating Systems**: Linux kernel, Windows NT components, macOS kernel components
- **Embedded Systems**: IoT devices, microcontrollers, automotive systems
- **Database Systems**: MySQL, PostgreSQL, SQLite core engines
- **Compilers**: GCC, Clang, and many language interpreters
- **Game Engines**: Unreal Engine components, id Tech engines
- **Network Infrastructure**: Router firmware, network protocols
- **Scientific Computing**: High-performance numerical libraries

#### C's Philosophy and Design Principles

C embodies several key design principles that make it enduringly relevant:

1. **Simplicity**: Small set of keywords (32 in C89, expanded in later standards)
2. **Efficiency**: Close-to-hardware performance with minimal runtime overhead
3. **Portability**: Write once, compile anywhere with standard-compliant code
4. **Flexibility**: Powerful enough for system programming, simple enough for learning
5. **Explicitness**: Programmer controls memory management and system resources

#### The C Compilation Process

Understanding how C code becomes executable is crucial for professional development:

```
Source Code (.c) → Preprocessor → Compiler → Assembler → Linker → Executable
     ↓               ↓            ↓          ↓         ↓         ↓
   hello.c    →   hello.i   →  hello.s  → hello.o  →   ld    → hello
```

**Detailed Process:**
1. **Preprocessing**: Handles `#include`, `#define`, conditional compilation
2. **Compilation**: Converts preprocessed C to assembly language
3. **Assembly**: Converts assembly to machine code (object files)
4. **Linking**: Combines object files with libraries to create executable

### 2. Development Environment Setup {#environment-setup}

#### Essential Tools for C Development

**Compiler Options:**
- **GCC (GNU Compiler Collection)**: Most widely used, excellent standards support
- **Clang**: Modern alternative with better error messages and static analysis
- **MSVC**: Microsoft's compiler for Windows development
- **Intel C Compiler**: Optimized for Intel processors

**Development Environments:**
- **Command Line**: Traditional approach, full control
- **IDE Options**: Code::Blocks, Dev-C++, CLion, Visual Studio
- **Text Editors**: VS Code with C extensions, Vim with plugins, Emacs

#### First Program: Beyond "Hello World"

Instead of the typical "Hello World," let's start with a practical program that demonstrates multiple C concepts:

```c
/* file_analyzer.c - A practical first program */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }
    
    // Analyze file content
    int lines = 0, words = 0, chars = 0;
    int ch, in_word = 0;
    
    while ((ch = fgetc(file)) != EOF) {
        chars++;
        
        if (ch == '\n') {
            lines++;
        }
        
        if (ch == ' ' || ch == '\t' || ch == '\n') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            words++;
        }
    }
    
    fclose(file);
    
    // Display results
    printf("File Analysis for: %s\n", argv[1]);
    printf("Lines: %d\n", lines);
    printf("Words: %d\n", words);
    printf("Characters: %d\n", chars);
    
    return EXIT_SUCCESS;
}
```

**Compilation and Execution:**
```bash
gcc -o file_analyzer file_analyzer.c
./file_analyzer sample.txt
```

This program demonstrates:
- Command-line argument handling
- File operations
- Control structures
- Error handling
- Standard library usage

### 3. Variables and Constants {#variables-constants}

#### Variable Declaration and Initialization

C requires explicit variable declaration before use, promoting clear code structure:

```c
#include <stdio.h>

int main(void) {
    // Basic variable declarations
    int age;                    // Declaration only
    int height = 175;          // Declaration with initialization
    double salary = 75000.50;  // Floating-point number
    char grade = 'A';          // Single character
    
    // Multiple variables of same type
    int x, y, z;
    int a = 10, b = 20, c = 30;
    
    // Using variables
    age = 25;
    printf("Age: %d, Height: %d cm, Salary: %.2f, Grade: %c\n",
           age, height, salary, grade);
    
    return 0;
}
```

---

## Part II Continued: Advanced Intermediate Concepts

### 14. File Input/Output Operations {#file-io}

File operations are essential for persistent data storage and inter-process communication in C programs.

#### File Opening, Reading, and Writing

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

// Basic file operations
void basic_file_operations(void) {
    printf("=== Basic File Operations ===\n");
    
    // Writing to a file
    FILE *write_file = fopen("example.txt", "w");
    if (write_file == NULL) {
        perror("Failed to open file for writing");
        return;
    }
    
    fprintf(write_file, "Hello, File I/O!\n");
    fprintf(write_file, "Line 2: Numbers: %d, %.2f\n", 42, 3.14159);
    fprintf(write_file, "Line 3: Character: %c\n", 'A');
    
    fclose(write_file);
    printf("Data written to example.txt\n");
    
    // Reading from a file
    FILE *read_file = fopen("example.txt", "r");
    if (read_file == NULL) {
        perror("Failed to open file for reading");
        return;
    }
    
    char line[256];
    int line_number = 1;
    
    printf("\nFile contents:\n");
    while (fgets(line, sizeof(line), read_file) != NULL) {
        printf("Line %d: %s", line_number++, line);
    }
    
    fclose(read_file);
    
    // Check for errors
    if (ferror(read_file)) {
        printf("Error occurred while reading file\n");
    }
    
    // Cleanup
    remove("example.txt");
}

// Binary file operations
typedef struct {
    int id;
    char name[50];
    double salary;
} Employee;

void binary_file_operations(void) {
    printf("\n=== Binary File Operations ===\n");
    
    Employee employees[] = {
        {1, "John Doe", 75000.0},
        {2, "Jane Smith", 82000.0},
        {3, "Bob Johnson", 68000.0}
    };
    
    int num_employees = sizeof(employees) / sizeof(employees[0]);
    
    // Write binary data
    FILE *bin_file = fopen("employees.dat", "wb");
    if (bin_file == NULL) {
        perror("Failed to create binary file");
        return;
    }
    
    size_t written = fwrite(employees, sizeof(Employee), num_employees, bin_file);
    printf("Wrote %zu employee records\n", written);
    fclose(bin_file);
    
    // Read binary data
    bin_file = fopen("employees.dat", "rb");
    if (bin_file == NULL) {
        perror("Failed to open binary file");
        return;
    }
    
    Employee read_employees[10];
    size_t read_count = fread(read_employees, sizeof(Employee), 10, bin_file);
    printf("Read %zu employee records:\n", read_count);
    
    for (size_t i = 0; i < read_count; i++) {
        printf("  ID: %d, Name: %s, Salary: $%.2f\n",
               read_employees[i].id, read_employees[i].name, read_employees[i].salary);
    }
    
    fclose(bin_file);
    remove("employees.dat");
}

// File positioning and seeking
void file_positioning_demo(void) {
    printf("\n=== File Positioning Demo ===\n");
    
    // Create a test file
    FILE *file = fopen("positions.txt", "w+");
    if (file == NULL) {
        perror("Failed to create positioning test file");
        return;
    }
    
    // Write some data
    fprintf(file, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    
    // Get current position
    long pos = ftell(file);
    printf("Position after writing: %ld\n", pos);
    
    // Seek to beginning
    rewind(file);
    pos = ftell(file);
    printf("Position after rewind: %ld\n", pos);
    
    // Read and display character at different positions
    char ch;
    
    // Position 10
    fseek(file, 10, SEEK_SET);
    ch = fgetc(file);
    printf("Character at position 10: '%c'\n", ch);
    
    // Relative positioning
    fseek(file, 5, SEEK_CUR);
    ch = fgetc(file);
    pos = ftell(file);
    printf("Character at position %ld (after seeking +5 from current): '%c'\n", pos-1, ch);
    
    // Seek from end
    fseek(file, -5, SEEK_END);
    ch = fgetc(file);
    printf("Character 5 positions from end: '%c'\n", ch);
    
    fclose(file);
    remove("positions.txt");
}

// Error handling and file status
void file_error_handling(void) {
    printf("\n=== File Error Handling ===\n");
    
    // Try to open non-existent file
    FILE *file = fopen("nonexistent.txt", "r");
    if (file == NULL) {
        printf("Failed to open file: %s (errno: %d)\n", strerror(errno), errno);
    }
    
    // Create a file for testing
    file = fopen("test_errors.txt", "w+");
    if (file == NULL) {
        perror("Failed to create test file");
        return;
    }
    
    fprintf(file, "Test data for error handling\n");
    
    // Test various file status functions
    printf("\nFile status after writing:\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    printf("  Position: %ld\n", ftell(file));
    
    // Read past end of file
    rewind(file);
    char buffer[1000];
    size_t read_bytes = fread(buffer, 1, sizeof(buffer), file);
    printf("Read %zu bytes\n", read_bytes);
    printf("After reading past end:\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    
    // Clear error state
    clearerr(file);
    printf("After clearerr():\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    
    fclose(file);
    remove("test_errors.txt");
}

// Real-world example: Configuration file parser
typedef struct {
    char key[50];
    char value[200];
} ConfigItem;

typedef struct {
    ConfigItem items[100];
    int count;
} Config;

int parse_config_file(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return -1;
    }
    
    config->count = 0;
    char line[512];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file) != NULL && config->count < 100) {
        line_number++;
        
        // Remove newline
        line[strcspn(line, "\n")] = '\0';
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Find key=value separator
        char *equals = strchr(line, '=');
        if (equals == NULL) {
            printf("Warning: Invalid format at line %d: %s\n", line_number, line);
            continue;
        }
        
        // Split key and value
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;
        
        // Trim whitespace
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;
        
        // Remove trailing whitespace from key
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end = '\0';
            key_end--;
        }
        
        // Store configuration item
        strncpy(config->items[config->count].key, key, sizeof(config->items[config->count].key) - 1);
        strncpy(config->items[config->count].value, value, sizeof(config->items[config->count].value) - 1);
        config->items[config->count].key[sizeof(config->items[config->count].key) - 1] = '\0';
        config->items[config->count].value[sizeof(config->items[config->count].value) - 1] = '\0';
        
        config->count++;
    }
    
    fclose(file);
    return config->count;
}

const char* get_config_value(const Config *config, const char *key) {
    for (int i = 0; i < config->count; i++) {
        if (strcmp(config->items[i].key, key) == 0) {
            return config->items[i].value;
        }
    }
    return NULL;
}

void config_file_demo(void) {
    printf("\n=== Configuration File Parser Demo ===\n");
    
    // Create sample config file
    FILE *config_file = fopen("app.conf", "w");
    if (config_file == NULL) {
        perror("Failed to create config file");
        return;
    }
    
    fprintf(config_file, "# Application Configuration\n");
    fprintf(config_file, "app_name = My Application\n");
    fprintf(config_file, "version = 1.2.3\n");
    fprintf(config_file, "debug_mode = true\n");
    fprintf(config_file, "max_connections = 100\n");
    fprintf(config_file, "database_url = postgresql://localhost:5432/mydb\n");
    fprintf(config_file, "\n");
    fprintf(config_file, "; This is also a comment\n");
    fprintf(config_file, "log_level = INFO\n");
    
    fclose(config_file);
    
    // Parse configuration
    Config config;
    int result = parse_config_file("app.conf", &config);
    
    if (result < 0) {
        printf("Failed to parse configuration file\n");
        return;
    }
    
    printf("Parsed %d configuration items:\n", config.count);
    for (int i = 0; i < config.count; i++) {
        printf("  %s = %s\n", config.items[i].key, config.items[i].value);
    }
    
    // Lookup specific values
    printf("\nConfiguration lookup:\n");
    const char *app_name = get_config_value(&config, "app_name");
    const char *max_conn = get_config_value(&config, "max_connections");
    const char *missing = get_config_value(&config, "missing_key");
    
    printf("  App name: %s\n", app_name ? app_name : "Not found");
    printf("  Max connections: %s\n", max_conn ? max_conn : "Not found");
    printf("  Missing key: %s\n", missing ? missing : "Not found");
    
    remove("app.conf");
}

// Large file handling and buffering
void large_file_demo(void) {
    printf("\n=== Large File Handling Demo ===\n");
    
    const char *filename = "large_test.txt";
    const int num_lines = 10000;
    
    // Create a moderately large file
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Failed to create large test file");
        return;
    }
    
    printf("Creating file with %d lines...\n", num_lines);
    for (int i = 1; i <= num_lines; i++) {
        fprintf(file, "Line %05d: This is test data for line number %d\n", i, i);
    }
    fclose(file);
    
    // Get file size
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("File size: %ld bytes\n", st.st_size);
    }
    
    // Read file in chunks
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open large file for reading");
        return;
    }
    
    char buffer[8192];  // 8KB buffer
    size_t total_bytes = 0;
    int chunks = 0;
    
    printf("Reading file in chunks...\n");
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        total_bytes += strlen(buffer);
        chunks++;
        
        // Process every 1000th line
        if (chunks % 1000 == 0) {
            // Remove newline for display
            buffer[strcspn(buffer, "\n")] = '\0';
            printf("  Chunk %d: %s\n", chunks, buffer);
        }
    }
    
    printf("Total bytes read: %zu in %d chunks\n", total_bytes, chunks);
    
    fclose(file);
    remove(filename);
}

int main(void) {
    basic_file_operations();
    binary_file_operations();
    file_positioning_demo();
    file_error_handling();
    config_file_demo();
    large_file_demo();
    
    printf("\n=== File I/O Best Practices ===\n");
    printf("1. Always check return values from file operations\n");
    printf("2. Close files when done (use RAII pattern when possible)\n");
    printf("3. Use appropriate file modes ('r', 'w', 'a', 'rb', 'wb', etc.)\n");
    printf("4. Handle errors gracefully with meaningful messages\n");
    printf("5. Use buffering appropriately for performance\n");
    printf("6. Be careful with binary vs text modes on Windows\n");
    printf("7. Consider using memory-mapped files for large datasets\n");
    
    return 0;
}
```

#### Concepts ⚙
- File modes and permissions
- Text vs binary file handling
- Stream positioning and seeking
- File buffering strategies

#### Errors ⚠
- Forgetting to check fopen() return value
- Not closing files (resource leaks)
- Mixing text and binary operations
- Platform-specific newline handling

#### Tips 🧠
- Use `fflush()` to force write operations
- Check `ferror()` and `feof()` for operation status
- Prefer `snprintf()` over `sprintf()` for safety
- Consider using `mmap()` for large files on Unix systems

#### Tools 🔧
- `strace`/`dtrace` for file operation tracing
- `lsof` to check open file descriptors
- File integrity tools (checksums)
- Performance profilers for I/O bottlenecks

---

### 15. Preprocessor and Macros {#preprocessor}

The C preprocessor is a powerful text processing tool that runs before compilation, enabling conditional compilation, code generation, and symbolic constants.

#### Macro Definition and Usage

```c
#include <stdio.h>
#include <string.h>

// Simple macros
#define PI 3.14159265359
#define MAX_BUFFER_SIZE 1024
#define PROGRAM_VERSION "2.1.0"

// Function-like macros
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Multi-line macros
#define SWAP(type, a, b) \
    do { \
        type temp = (a); \
        (a) = (b); \
        (b) = temp; \
    } while(0)

// Stringification
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Token pasting
#define CONCAT(a, b) a ## b
#define MAKE_FUNCTION(name) \
    void CONCAT(process_, name)(void) { \
        printf("Processing " #name "\n"); \
    }

// Create functions using token pasting
MAKE_FUNCTION(data)
MAKE_FUNCTION(file)
MAKE_FUNCTION(network)

void basic_macros_demo(void) {
    printf("=== Basic Macros Demo ===\n");
    
    // Simple constant macros
    printf("PI value: %f\n", PI);
    printf("Buffer size: %d\n", MAX_BUFFER_SIZE);
    printf("Program version: %s\n", PROGRAM_VERSION);
    
    // Function-like macros
    int a = 5, b = 3;
    printf("SQUARE(%d) = %d\n", a, SQUARE(a));
    printf("MAX(%d, %d) = %d\n", a, b, MAX(a, b));
    printf("MIN(%d, %d) = %d\n", a, b, MIN(a, b));
    
    // Multi-line macro
    printf("Before swap: a=%d, b=%d\n", a, b);
    SWAP(int, a, b);
    printf("After swap: a=%d, b=%d\n", a, b);
    
    // Stringification
    printf("Stringified PI: %s\n", STRINGIFY(PI));
    printf("Converted to string: %s\n", TOSTRING(MAX_BUFFER_SIZE));
    
    // Generated functions
    process_data();
    process_file();
    process_network();
}

// Advanced macro techniques
#define DEBUG_PRINT(fmt, ...) \
    do { \
        printf("[DEBUG %s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while(0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define SAFE_FREE(ptr) \
    do { \
        if (ptr) { \
            free(ptr); \
            ptr = NULL; \
        } \
    } while(0)

// Macro for structure initialization
#define INIT_POINT(x, y) {.x = (x), .y = (y)}

// Generic macro (C11)
#if __STDC_VERSION__ >= 201112L
#define GENERIC_MAX(x, y) _Generic((x), \
    int: MAX, \
    float: fmaxf, \
    double: fmax, \
    default: MAX \
)(x, y)
#endif

void advanced_macros_demo(void) {
    printf("\n=== Advanced Macros Demo ===\n");
    
    // Variadic macros
    DEBUG_PRINT("Application started");
    DEBUG_PRINT("User %s logged in with ID %d", "Alice", 123);
    DEBUG_PRINT("Processing %d items", 42);
    
    // Array size macro
    int numbers[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    printf("Array size: %zu\n", ARRAY_SIZE(numbers));
    
    // Structure initialization macro
    struct Point { double x, y; };
    struct Point p1 = INIT_POINT(3.0, 4.0);
    printf("Point: (%.1f, %.1f)\n", p1.x, p1.y);
    
    // Safe free demonstration
    char *buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Test data");
        printf("Buffer content: %s\n", buffer);
    }
    
    printf("Freeing buffer...\n");
    SAFE_FREE(buffer);
    printf("Buffer pointer after SAFE_FREE: %p\n", (void*)buffer);
    
    // Generic macro (C11)
    #if __STDC_VERSION__ >= 201112L
    printf("Generic max(10, 5): %d\n", GENERIC_MAX(10, 5));
    printf("Generic max(3.14, 2.71): %f\n", GENERIC_MAX(3.14, 2.71));
    #endif
}

// Conditional compilation
#define FEATURE_LOGGING 1
#define FEATURE_NETWORKING 0
#define DEBUG_LEVEL 2

#if FEATURE_LOGGING
void log_message(const char *message) {
    printf("[LOG] %s\n", message);
}
#else
#define log_message(msg) ((void)0)  // No-op macro
#endif

#if DEBUG_LEVEL >= 1
#define DBG1(fmt, ...) printf("[DBG1] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG1(fmt, ...) ((void)0)
#endif

#if DEBUG_LEVEL >= 2
#define DBG2(fmt, ...) printf("[DBG2] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG2(fmt, ...) ((void)0)
#endif

void conditional_compilation_demo(void) {
    printf("\n=== Conditional Compilation Demo ===\n");
    
    #if FEATURE_LOGGING
    printf("Logging feature is enabled\n");
    log_message("This is a log message");
    #else
    printf("Logging feature is disabled\n");
    #endif
    
    #if FEATURE_NETWORKING
    printf("Networking feature is enabled\n");
    #else
    printf("Networking feature is disabled\n");
    #endif
    
    DBG1("Debug level 1 message");
    DBG2("Debug level 2 message with value: %d", 42);
    
    // Compiler-specific code
    #ifdef __GNUC__
    printf("Compiled with GCC version %d.%d.%d\n", 
           __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    #elif defined(_MSC_VER)
    printf("Compiled with Microsoft Visual C++ version %d\n", _MSC_VER);
    #elif defined(__clang__)
    printf("Compiled with Clang version %s\n", __clang_version__);
    #else
    printf("Compiled with unknown compiler\n");
    #endif
    
    // Platform-specific code
    #ifdef _WIN32
    printf("Running on Windows\n");
    #elif defined(__linux__)
    printf("Running on Linux\n");
    #elif defined(__APPLE__)
    printf("Running on macOS\n");
    #else
    printf("Running on unknown platform\n");
    #endif
}

// Predefined macros
void predefined_macros_demo(void) {
    printf("\n=== Predefined Macros Demo ===\n");
    
    printf("File: %s\n", __FILE__);
    printf("Line: %d\n", __LINE__);
    printf("Function: %s\n", __func__);  // C99
    printf("Date: %s\n", __DATE__);
    printf("Time: %s\n", __TIME__);
    printf("Standard version: %ld\n", __STDC_VERSION__);
    
    #ifdef __STDC__
    printf("Standard C compiler: Yes\n");
    #endif
    
    #ifdef __STDC_HOSTED__
    printf("Hosted implementation: %d\n", __STDC_HOSTED__);
    #endif
    
    // C11 and later features
    #if __STDC_VERSION__ >= 201112L
    printf("C11 features available\n");
    
    #ifdef __STDC_NO_ATOMICS__
    printf("Atomics: Not available\n");
    #else
    printf("Atomics: Available\n");
    #endif
    
    #ifdef __STDC_NO_THREADS__
    printf("Threads: Not available\n");
    #else
    printf("Threads: Available\n");
    #endif
    #endif
}

// Macro pitfalls and best practices
#define BAD_MAX(a, b) (a > b ? a : b)  // Side effects!
#define GOOD_MAX(a, b) ((a) > (b) ? (a) : (b))  // Proper parentheses

// Multi-evaluation problem
#define INCREMENT_BAD(x) (++x)  // Dangerous
#define INCREMENT_GOOD(x) ((x) + 1)  // Safe

// Statement-like macros
#define ASSERT_BAD(cond) if (!(cond)) { printf("Assertion failed\n"); exit(1); }
#define ASSERT_GOOD(cond) \
    do { \
        if (!(cond)) { \
            printf("Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while(0)

void macro_pitfalls_demo(void) {
    printf("\n=== Macro Pitfalls and Solutions ===\n");
    
    // Side effect demonstration
    int x = 5, y = 3;
    
    printf("Before: x=%d, y=%d\n", x, y);
    
    // This works fine
    int result1 = GOOD_MAX(x, y);
    printf("GOOD_MAX(x, y) = %d, x=%d, y=%d\n", result1, x, y);
    
    // This has side effects with increment
    x = 5;
    // int bad_result = BAD_MAX(++x, y);  // x incremented twice!
    int good_result = GOOD_MAX(++x, y);   // x incremented once
    printf("After GOOD_MAX(++x, y): result=%d, x=%d\n", good_result, x);
    
    // Statement-like macro usage
    int value = 10;
    if (value > 0)
        ASSERT_GOOD(value > 5);  // This works correctly
    
    printf("Assertion passed\n");
    
    // Show macro expansion (conceptual)
    printf("\nMacro expansion examples:\n");
    printf("SQUARE(3+2) expands to: ((3+2) * (3+2)) = %d\n", SQUARE(3+2));
    printf("Without parentheses it would be: 3+2 * 3+2 = %d\n", 3+2 * 3+2);
}

// Real-world example: Logging system with macros
typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO = 2,
    LOG_WARN = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5
} LogLevel;

static LogLevel current_log_level = LOG_INFO;

#define LOG(level, fmt, ...) \
    do { \
        if ((level) >= current_log_level) { \
            const char* level_names[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}; \
            printf("[%s %s:%d] " fmt "\n", \
                   level_names[level], __FILE__, __LINE__, ##__VA_ARGS__); \
        } \
    } while(0)

#define LOG_TRACE(fmt, ...) LOG(LOG_TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG(LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG(LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) LOG(LOG_FATAL, fmt, ##__VA_ARGS__)

void logging_system_demo(void) {
    printf("\n=== Logging System Demo ===\n");
    
    printf("Current log level: INFO\n");
    
    LOG_TRACE("This trace message won't appear");
    LOG_DEBUG("This debug message won't appear");
    LOG_INFO("Application started");
    LOG_WARN("Low disk space: %d%% full", 85);
    LOG_ERROR("Failed to connect to database: %s", "Connection timeout");
    LOG_FATAL("Critical system error occurred");
    
    // Change log level
    current_log_level = LOG_DEBUG;
    printf("\nChanged log level to DEBUG:\n");
    
    LOG_TRACE("This trace message still won't appear");
    LOG_DEBUG("Now debug messages appear");
    LOG_INFO("Debug mode enabled");
}

int main(void) {
    basic_macros_demo();
    advanced_macros_demo();
    conditional_compilation_demo();
    predefined_macros_demo();
    macro_pitfalls_demo();
    logging_system_demo();
    
    return 0;
}
```

#### Concepts ⚙
- Macro expansion phases
- Token stringification and pasting
- Variadic macros with `__VA_ARGS__`
- Conditional compilation directives

#### Errors ⚠
- Multiple evaluation of macro arguments
- Missing parentheses in macro definitions  
- Side effects in macro arguments
- Macro name collisions with functions

#### Tips 🧠
- Use `do-while(0)` for statement-like macros
- Always parenthesize macro parameters
- Use `##__VA_ARGS__` for optional arguments
- Prefer `const` variables over simple `#define` when possible

#### Tools 🔧
- `gcc -E` to see preprocessor output
- Static analysis tools for macro complexity
- IDE macro expansion viewers
- Compiler warnings for macro redefinition

---

### 16. Standard Library Deep Dive {#standard-library}

The C Standard Library provides essential functions for string manipulation, mathematical operations, memory management, and system interfaces.

#### String Handling Functions

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <locale.h>

void string_basic_functions(void) {
    printf("=== Basic String Functions ===\n");
    
    char str1[100] = "Hello";
    char str2[100] = "World";
    char str3[100];
    
    // String length
    printf("strlen(\"%s\") = %zu\n", str1, strlen(str1));
    
    // String copy
    strcpy(str3, str1);
    printf("strcpy result: \"%s\"\n", str3);
    
    // String concatenation
    strcat(str1, ", ");
    strcat(str1, str2);
    printf("After strcat: \"%s\"\n", str1);
    
    // String comparison
    int cmp = strcmp("apple", "banana");
    printf("strcmp(\"apple\", \"banana\") = %d\n", cmp);
    
    cmp = strcmp("hello", "hello");
    printf
```

#### Naming Conventions and Best Practices

**Valid Identifiers:**
- Must start with letter or underscore
- Can contain letters, digits, underscores
- Case-sensitive (`myVar` ≠ `myvar`)

**Professional Naming Conventions:**
```c
// Variables: snake_case (preferred) or camelCase
int user_count;        // snake_case
int userCount;         // camelCase

// Constants: SCREAMING_SNAKE_CASE
#define MAX_BUFFER_SIZE 1024
const int DEFAULT_PORT = 8080;

// Functions: snake_case
int calculate_area(int width, int height);

// Types: PascalCase or snake_case with _t suffix
typedef struct {
    int x, y;
} Point;

typedef struct user_data_s {
    char name[50];
    int age;
} user_data_t;
```

#### Constants: Multiple Approaches

C provides several ways to define constants, each with specific use cases:

**1. Preprocessor Macros:**
```c
#define PI 3.14159265359
#define MAX_USERS 100
#define WELCOME_MSG "Welcome to the system"

// Advantages: Compile-time substitution, no memory usage
// Disadvantages: No type checking, no scope respect
```

**2. Const Keyword:**
```c
const double PI = 3.14159265359;
const int MAX_USERS = 100;
const char WELCOME_MSG[] = "Welcome to the system";

// Advantages: Type safety, scope rules apply
// Disadvantages: Uses memory, runtime initialization
```

**3. Enumerated Constants:**
```c
enum Status {
    STATUS_INACTIVE,    // 0
    STATUS_ACTIVE,      // 1
    STATUS_PENDING,     // 2
    STATUS_SUSPENDED = 10,  // Explicit value
    STATUS_DELETED      // 11
};

// Usage
enum Status user_status = STATUS_ACTIVE;
```

**Real-World Example: Configuration System**
```c
/* config.h - Application configuration */
#ifndef CONFIG_H
#define CONFIG_H

// Compile-time configuration
#define APP_VERSION "2.1.4"
#define BUILD_DATE __DATE__
#define MAX_CONNECTIONS 1000

// Runtime configuration
extern const char* const DEFAULT_CONFIG_PATH;
extern const int DEFAULT_TIMEOUT;

// Status codes
enum ErrorCode {
    ERR_SUCCESS = 0,
    ERR_INVALID_INPUT = -1,
    ERR_OUT_OF_MEMORY = -2,
    ERR_FILE_NOT_FOUND = -3,
    ERR_NETWORK_ERROR = -4
};

#endif /* CONFIG_H */
```

### 4. Data Types and Memory {#data-types}

#### Fundamental Data Types

C provides several fundamental data types, with sizes that can vary by platform:

**Integer Types:**
```c
#include <stdio.h>
#include <limits.h>
#include <stdint.h>

int main(void) {
    // Basic integer types
    char c = 'A';              // At least 8 bits
    short s = 32767;           // At least 16 bits
    int i = 2147483647;        // At least 16 bits (usually 32)
    long l = 2147483647L;      // At least 32 bits
    long long ll = 9223372036854775807LL; // At least 64 bits (C99)
    
    // Unsigned variants
    unsigned char uc = 255;
    unsigned short us = 65535;
    unsigned int ui = 4294967295U;
    unsigned long ul = 4294967295UL;
    unsigned long long ull = 18446744073709551615ULL;
    
    // Fixed-width integers (C99, recommended for portability)
    int8_t i8 = 127;           // Exactly 8 bits
    int16_t i16 = 32767;       // Exactly 16 bits
    int32_t i32 = 2147483647;  // Exactly 32 bits
    int64_t i64 = 9223372036854775807LL; // Exactly 64 bits
    
    uint8_t u8 = 255;
    uint16_t u16 = 65535;
    uint32_t u32 = 4294967295U;
    uint64_t u64 = 18446744073709551615ULL;
    
    // Display sizes
    printf("Size of char: %zu bytes\n", sizeof(char));
    printf("Size of int: %zu bytes\n", sizeof(int));
    printf("Size of long: %zu bytes\n", sizeof(long));
    printf("Size of long long: %zu bytes\n", sizeof(long long));
    printf("Size of pointer: %zu bytes\n", sizeof(void*));
    
    return 0;
}
```

**Floating-Point Types:**
```c
#include <stdio.h>
#include <float.h>

int main(void) {
    float f = 3.14159f;        // Single precision (usually 32 bits)
    double d = 3.14159265359;  // Double precision (usually 64 bits)
    long double ld = 3.14159265358979323846L; // Extended precision
    
    printf("Float: %.7f (precision: %d digits)\n", f, FLT_DIG);
    printf("Double: %.15f (precision: %d digits)\n", d, DBL_DIG);
    printf("Long Double: %.18Lf (precision: %d digits)\n", ld, LDBL_DIG);
    
    // Scientific notation
    double large_number = 1.23e6;   // 1,230,000
    double small_number = 1.23e-6;  // 0.00000123
    
    printf("Large: %e, Small: %e\n", large_number, small_number);
    
    return 0;
}
```

#### Memory Layout and Alignment

Understanding how data is stored in memory is crucial for efficient C programming:

```c
#include <stdio.h>
#include <stddef.h>

struct UnalignedData {
    char a;      // 1 byte
    int b;       // 4 bytes
    char c;      // 1 byte
    double d;    // 8 bytes
}; // Total: 24 bytes (with padding)

struct AlignedData {
    double d;    // 8 bytes
    int b;       // 4 bytes
    char a;      // 1 byte
    char c;      // 1 byte
}; // Total: 16 bytes (with padding)

int main(void) {
    printf("Unaligned struct size: %zu bytes\n", sizeof(struct UnalignedData));
    printf("Aligned struct size: %zu bytes\n", sizeof(struct AlignedData));
    
    // Demonstrate memory addresses and alignment
    struct UnalignedData unaligned;
    
    printf("\nMemory layout of unaligned struct:\n");
    printf("Address of a: %p (offset: %zu)\n", 
           (void*)&unaligned.a, offsetof(struct UnalignedData, a));
    printf("Address of b: %p (offset: %zu)\n", 
           (void*)&unaligned.b, offsetof(struct UnalignedData, b));
    printf("Address of c: %p (offset: %zu)\n", 
           (void*)&unaligned.c, offsetof(struct UnalignedData, c));
    printf("Address of d: %p (offset: %zu)\n", 
           (void*)&unaligned.d, offsetof(struct UnalignedData, d));
    
    return 0;
}
```

#### Type Qualifiers and Modifiers

**Storage Class Specifiers:**
```c
// auto - default for local variables (rarely used explicitly)
auto int local_var = 10;

// register - hint to store in CPU register (deprecated in modern C)
register int counter;

// static - retains value between function calls, internal linkage
static int function_calls = 0;

// extern - declares variable defined elsewhere
extern int global_variable;
```

**Type Qualifiers:**
```c
// const - immutable after initialization
const int MAX_SIZE = 100;
const char* const filename = "config.txt"; // Immutable pointer to immutable data

// volatile - prevents compiler optimization, value may change unexpectedly
volatile int hardware_register;
volatile sig_atomic_t signal_flag; // Common in signal handlers

// restrict - pointer is the only way to access the object (C99)
void process_arrays(int* restrict input, int* restrict output, size_t count);
```

**Real-World Example: Embedded System Register Mapping**
```c
/* Hardware abstraction for embedded system */
#include <stdint.h>

// Memory-mapped I/O registers
#define GPIO_BASE_ADDR 0x40020000

typedef struct {
    volatile uint32_t MODER;    // Mode register
    volatile uint32_t OTYPER;   // Output type register
    volatile uint32_t OSPEEDR;  // Output speed register
    volatile uint32_t PUPDR;    // Pull-up/pull-down register
    volatile uint32_t IDR;      // Input data register
    volatile uint32_t ODR;      // Output data register
} GPIO_TypeDef;

// Map structure to hardware address
#define GPIOA ((GPIO_TypeDef*)GPIO_BASE_ADDR)

void configure_gpio_pin(void) {
    // Configure pin 5 as output
    GPIOA->MODER |= (1 << (5 * 2));
    
    // Set pin 5 high
    GPIOA->ODR |= (1 << 5);
}
```

### 5. Operators and Expressions {#operators}

#### Arithmetic and Assignment Operators

C provides a comprehensive set of operators for mathematical operations and variable manipulation:

```c
#include <stdio.h>

int main(void) {
    int a = 10, b = 3;
    double x = 10.0, y = 3.0;
    
    // Basic arithmetic operators
    printf("Integer arithmetic:\n");
    printf("%d + %d = %d\n", a, b, a + b);    // Addition: 13
    printf("%d - %d = %d\n", a, b, a - b);    // Subtraction: 7
    printf("%d * %d = %d\n", a, b, a * b);    // Multiplication: 30
    printf("%d / %d = %d\n", a, b, a / b);    // Integer division: 3
    printf("%d %% %d = %d\n", a, b, a % b);   // Modulo: 1
    
    printf("\nFloating-point arithmetic:\n");
    printf("%.2f / %.2f = %.2f\n", x, y, x / y); // 3.33
    
    // Compound assignment operators
    int c = 20;
    printf("\nCompound assignments (starting with c = %d):\n", c);
    
    c += 5; // c = c + 5
    printf("After c += 5: %d\n", c);
    
    c -= 3; // c = c - 3
    printf("After c -= 3: %d\n", c);
    
    c *= 2; // c = c * 2
    printf("After c *= 2: %d\n", c);
    
    c /= 4; // c = c / 4
    printf("After c /= 4: %d\n", c);
    
    c %= 7; // c = c % 7
    printf("After c %%= 7: %d\n", c);
    
    // Increment and decrement operators
    int i = 10;
    printf("\nIncrement/Decrement (starting with i = %d):\n", i);
    printf("i++ returns %d, i is now %d\n", i++, i);
    printf("++i returns %d, i is now %d\n", ++i, i);
    printf("i-- returns %d, i is now %d\n", i--, i);
    printf("--i returns %d, i is now %d\n", --i, i);
    
    return 0;
}
```

#### Bitwise Operations

Bitwise operations are essential for low-level programming, embedded systems, and performance optimization:

```c
#include <stdio.h>

// Function to display binary representation
void print_binary(unsigned int n) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
        if (i % 4 == 0) printf(" ");
    }
    printf("\n");
}

int main(void) {
    unsigned int a = 60;  // 0011 1100
    unsigned int b = 13;  // 0000 1101
    
    printf("a = %u: ", a);
    print_binary(a);
    printf("b = %u: ", b);
    print_binary(b);
    
    // Bitwise AND
    printf("\nBitwise AND (a & b):\n");
    unsigned int and_result = a & b; // 0000 1100 = 12
    printf("Result = %u: ", and_result);
    print_binary(and_result);
    
    // Bitwise OR
    printf("\nBitwise OR (a | b):\n");
    unsigned int or_result = a | b; // 0011 1101 = 61
    printf("Result = %u: ", or_result);
    print_binary(or_result);
    
    // Bitwise XOR
    printf("\nBitwise XOR (a ^ b):\n");
    unsigned int xor_result = a ^ b; // 0011 0001 = 49
    printf("Result = %u: ", xor_result);
    print_binary(xor_result);
    
    // Bitwise NOT
    printf("\nBitwise NOT (~a):\n");
    unsigned int not_result = ~a;
    printf("Result = %u: ", not_result);
    print_binary(not_result);
    
    // Left shift
    printf("\nLeft shift (a << 2):\n");
    unsigned int left_shift = a << 2; // 1111 0000 = 240
    printf("Result = %u: ", left_shift);
    print_binary(left_shift);
    
    // Right shift
    printf("\nRight shift (a >> 2):\n");
    unsigned int right_shift = a >> 2; // 0000 1111 = 15
    printf("Result = %u: ", right_shift);
    print_binary(right_shift);
    
    return 0;
}
```

**Practical Bitwise Operations:**
```c
#include <stdio.h>
#include <stdint.h>

// Set bit at position
#define SET_BIT(x, pos) ((x) |= (1U << (pos)))

// Clear bit at position
#define CLEAR_BIT(x, pos) ((x) &= ~(1U << (pos)))

// Toggle bit at position
#define TOGGLE_BIT(x, pos) ((x) ^= (1U << (pos)))

// Check if bit is set
#define IS_BIT_SET(x, pos) (((x) >> (pos)) & 1U)

// Extract bits from position with mask
#define EXTRACT_BITS(x, pos, len) (((x) >> (pos)) & ((1U << (len)) - 1))

// Permission system example
typedef enum {
    PERM_READ    = 1 << 0,  // 001
    PERM_WRITE   = 1 << 1,  // 010
    PERM_EXECUTE = 1 << 2   // 100
} Permission;

void demonstrate_permissions(void) {
    uint8_t user_perms = 0;
    
    // Grant permissions
    user_perms |= PERM_READ;
    user_perms |= PERM_WRITE;
    
    printf("User permissions: ");
    if (user_perms & PERM_READ) printf("READ ");
    if (user_perms & PERM_WRITE) printf("WRITE ");
    if (user_perms & PERM_EXECUTE) printf("EXECUTE ");
    printf("\n");
    
    // Check specific permission
    if (user_perms & PERM_EXECUTE) {
        printf("User can execute\n");
    } else {
        printf("User cannot execute\n");
    }
    
    // Revoke write permission
    user_perms &= ~PERM_WRITE;
    printf("After revoking WRITE: %s\n", 
           (user_perms & PERM_WRITE) ? "Has WRITE" : "No WRITE");
}

int main(void) {
    // Demonstrate bit manipulation functions
    uint32_t flags = 0x12345678;
    
    printf("Original: 0x%08X\n", flags);
    
    SET_BIT(flags, 3);
    printf("After SET_BIT(3): 0x%08X\n", flags);
    
    CLEAR_BIT(flags, 4);
    printf("After CLEAR_BIT(4): 0x%08X\n", flags);
    
    TOGGLE_BIT(flags, 0);
    printf("After TOGGLE_BIT(0): 0x%08X\n", flags);
    
    printf("Bit 5 is %s\n", IS_BIT_SET(flags, 5) ? "set" : "clear");
    
    // Extract nibble (4 bits) starting at position 8
    uint32_t extracted = EXTRACT_BITS(flags, 8, 4);
    printf("Extracted 4 bits from position 8: 0x%X\n", extracted);
    
    demonstrate_permissions();
    
    return 0;
}
```

#### Logical and Relational Operators

```c
#include <stdio.h>
#include <stdbool.h>

int main(void) {
    int a = 10, b = 20, c = 10;
    bool result;
    
    // Relational operators
    printf("Relational operators (a=%d, b=%d, c=%d):\n", a, b, c);
    printf("a == c: %s\n", (a == c) ? "true" : "false");
    printf("a != b: %s\n", (a != b) ? "true" : "false");
    printf("a < b: %s\n", (a < b) ? "true" : "false");
    printf("a > b: %s\n", (a > b) ? "true" : "false");
    printf("a <= c: %s\n", (a <= c) ? "true" : "false");
    printf("b >= a: %s\n", (b >= a) ? "true" : "false");
    
    // Logical operators
    printf("\nLogical operators:\n");
    result = (a < b) && (b > c);  // Logical AND
    printf("(a < b) && (b > c): %s\n", result ? "true" : "false");
    
    result = (a > b) || (a == c); // Logical OR
    printf("(a > b) || (a == c): %s\n", result ? "true" : "false");
    
    result = !(a > b);            // Logical NOT
    printf("!(a > b): %s\n", result ? "true" : "false");
    
    // Short-circuit evaluation
    printf("\nShort-circuit evaluation:\n");
    int x = 0, y = 0;
    
    // AND: if first is false, second isn't evaluated
    if ((x = 1) && (y = 2)) {
        printf("Both conditions evaluated\n");
    }
    printf("After AND: x=%d, y=%d\n", x, y); // x=1, y=0
    
    x = 0; y = 0;
    // OR: if first is true, second isn't evaluated
    if ((x = 1) || (y = 2)) {
        printf("At least one condition was true\n");
    }
    printf("After OR: x=%d, y=%d\n", x, y); // x=1, y=0
    
    return 0;
}
```

#### Operator Precedence and Associativity

Understanding operator precedence is crucial for writing correct expressions:

**Operator Precedence Table (High to Low):**
```c
// 1. Postfix: () [] -> . ++ --
// 2. Prefix: ++ -- + - ! ~ (type) * & sizeof
// 3. Multiplicative: * / %
// 4. Additive: + -
// 5. Shift: << >>
// 6. Relational: < <= > >=
// 7. Equality: == !=
// 8. Bitwise AND: &
// 9. Bitwise XOR: ^
// 10. Bitwise OR: |
// 11. Logical AND: &&
// 12. Logical OR: ||
// 13. Conditional: ?:
// 14. Assignment: = += -= *= /= %= &= ^= |= <<= >>=
// 15. Comma: ,

#include <stdio.h>

int main(void) {
    int a = 5, b = 3, c = 2, d = 8;
    
    // Without parentheses - relies on precedence
    int result1 = a + b * c;        // 5 + (3 * 2) = 11
    int result2 = a < b + c * d;    // a < (b + (c * d)) = 5 < (3 + 16) = true
    int result3 = a & b << c;       // a & (b << c) = 5 & (3 << 2) = 5 & 12 = 4
    
    // With parentheses - explicit grouping
    int result4 = (a + b) * c;      // (5 + 3) * 2 = 16
    int result5 = (a < b) + c * d;  // (5 < 3) + (2 * 8) = 0 + 16 = 16
    int result6 = (a & b) << c;     // (5 & 3) << 2 = 1 << 2 = 4
    
    printf("Without parentheses:\n");
    printf("a + b * c = %d\n", result1);
    printf("a < b + c * d = %d\n", result2);
    printf("a & b << c = %d\n", result3);
    
    printf("\nWith parentheses:\n");
    printf("(a + b) * c = %d\n", result4);
    printf("(a < b) + c * d = %d\n", result5);
    printf("(a & b) << c = %d\n", result6);
    
    // Common mistakes
    printf("\nCommon precedence mistakes:\n");
    
    // Mistake 1: Bitwise AND with comparison
    if (a & 1 == 0) {  // Wrong: a & (1 == 0) = a & 0 = 0
        printf("This might not work as expected\n");
    }
    
    if ((a & 1) == 0) {  // Correct: (a & 1) == 0
        printf("a is even\n");
    } else {
        printf("a is odd\n");
    }
    
    // Mistake 2: Assignment in condition
    int x = 0;
    if (x = 5) {  // Assignment, not comparison!
        printf("x was assigned 5, condition is true\n");
    }
    
    x = 0;
    if (x == 5) {  // Correct comparison
        printf("x equals 5\n");
    } else {
        printf("x does not equal 5\n");
    }
    
    return 0;
}
```

### 6. Control Flow Structures {#control-flow}

#### Conditional Statements

**Basic if-else Structures:**
```c
#include <stdio.h>

// Function to demonstrate grade classification
char classify_grade(int score) {
    if (score >= 90) {
        return 'A';
    } else if (score >= 80) {
        return 'B';
    } else if (score >= 70) {
        return 'C';
    } else if (score >= 60) {
        return 'D';
    } else {
        return 'F';
    }
}

// Real-world example: HTTP status code handling
const char* get_status_message(int status_code) {
    if (status_code >= 200 && status_code < 300) {
        return "Success";
    } else if (status_code >= 300 && status_code < 400) {
        return "Redirection";
    } else if (status_code >= 400 && status_code < 500) {
        return "Client Error";
    } else if (status_code >= 500 && status_code < 600) {
        return "Server Error";
    } else {
        return "Unknown Status";
    }
}

int main(void) {
    int scores[] = {95, 87, 72, 61, 45};
    int num_scores = sizeof(scores) / sizeof(scores[0]);
    
    printf("Grade Classification:\n");
    for (int i = 0; i < num_scores; i++) {
        printf("Score %d: Grade %c\n", scores[i], classify_grade(scores[i]));
    }
    
    // HTTP status code examples
    int status_codes[] = {200, 301, 404, 500, 999};
    int num_codes = sizeof(status_codes) / sizeof(status_codes[0]);
    
    printf("\nHTTP Status Messages:\n");
    for (int i = 0; i < num_codes; i++) {
        printf("Status %d: %s\n", status_codes[i], 
               get_status_message(status_codes[i]));
    }
    
    return 0;
}
```

**Switch Statements:**
```c
#include <stdio.h>
#include <ctype.h>

// Calculator function using switch
double calculate(double a, double b, char operator) {
    switch (operator) {
        case '+':
            return a + b;
        case '-':
            return a - b;
        case '*':
            return a * b;
        case '/':
            if (b != 0) {
                return a / b;
            } else {
                printf("Error: Division by zero\n");
                return 0;
            }
        case '%':
            // Modulo only works with integers
            if (b != 0) {
                return (int)a % (int)b;
            } else {
                printf("Error: Modulo by zero\n");
                return 0;
            }
        default:
            printf("Error: Unknown operator '%c'\n", operator);
            return 0;
    }
}

// Real-world example: Menu system
void handle_menu_choice(int choice) {
    switch (choice) {
        case 1:
            printf("Opening file...\n");
            // file_open_dialog();
            break;
            
        case 2:
            printf("Saving file...\n");
            // file_save();
            break;
            
        case 3:
        case 4:  // Fall-through for multiple cases
            printf("Import/Export operation...\n");
            // handle_import_export(choice);
            break;
            
        case 5:
            printf("Settings menu...\n");
            // show_settings();
            break;
            
        case 6:
            printf("Help and documentation...\n");
            // show_help();
            break;
            
        case 0:
            printf("Exiting application...\n");
            break;
            
        default:
            printf("Invalid choice. Please select 0-6.\n");
            break;
    }
}

// State machine example using switch
typedef enum {
    STATE_IDLE,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_DISCONNECTING,
    STATE_ERROR
} ConnectionState;

void process_connection_event(ConnectionState *state, int event) {
    switch (*state) {
        case STATE_IDLE:
            if (event == 1) {  // Connect event
                printf("Starting connection...\n");
                *state = STATE_CONNECTING;
            }
            break;
            
        case STATE_CONNECTING:
            if (event == 2) {  // Connection successful
                printf("Connected successfully\n");
                *state = STATE_CONNECTED;
            } else if (event == 3) {  // Connection failed
                printf("Connection failed\n");
                *state = STATE_ERROR;
            }
            break;
            
        case STATE_CONNECTED:
            if (event == 4) {  // Disconnect event
                printf("Disconnecting...\n");
                *state = STATE_DISCONNECTING;
            } else if (event == 3) {  // Connection lost
                printf("Connection lost\n");
                *state = STATE_ERROR;
            }
            break;
            
        case STATE_DISCONNECTING:
            if (event == 5) {  // Disconnect complete
                printf("Disconnected\n");
                *state = STATE_IDLE;
            }
            break;
            
        case STATE_ERROR:
            if (event == 6) {  // Reset
                printf("Resetting to idle\n");
                *state = STATE_IDLE;
            }
            break;
            
        default:
            printf("Unknown state\n");
            break;
    }
}

int main(void) {
    // Calculator demo
    printf("Calculator Demo:\n");
    printf("10 + 5 = %.2f\n", calculate(10, 5, '+'));
    printf("10 / 3 = %.2f\n", calculate(10, 3, '/'));
    printf("10 %% 3 = %.0f\n", calculate(10, 3, '%'));
    printf("10 & 5 = %.2f\n", calculate(10, 5, '&')); // Invalid operator
    
    printf("\nMenu System Demo:\n");
    int menu_choices[] = {1, 3, 7, 0};
    for (int i = 0; i < 4; i++) {
        printf("Choice %d: ", menu_choices[i]);
        handle_menu_choice(menu_choices[i]);
    }
    
    printf("\nState Machine Demo:\n");
    ConnectionState state = STATE_IDLE;
    int events[] = {1, 2, 4, 5, 6}; // Connect, Success, Disconnect, Complete, Reset
    
    for (int i = 0; i < 5; i++) {
        printf("Event %d: ", events[i]);
        process_connection_event(&state, events[i]);
    }
    
    return 0;
}
```

#### Loops: for, while, and do-while

**For Loops:**
```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Basic for loop
    printf("Basic counting:\n");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Reverse counting
    printf("Reverse counting:\n");
    for (int i = 10; i >= 0; i--) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Step by different values
    printf("Even numbers from 0 to 20:\n");
    for (int i = 0; i <= 20; i += 2) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Multiple variables in for loop
    printf("Multiple variables:\n");
    for (int i = 0, j = 10; i < j; i++, j--) {
        printf("i=%d, j=%d\n", i, j);
    }
    
    // Nested loops - multiplication table
    printf("\nMultiplication Table (5x5):\n");
    for (int i = 1; i <= 5; i++) {
        for (int j = 1; j <= 5; j++) {
            printf("%3d", i * j);
        }
        printf("\n");
    }
    
    // Loop through string characters
    char message[] = "Hello, World!";
    printf("\nCharacter analysis of '%s':\n", message);
    int vowel_count = 0;
    
    for (int i = 0; message[i] != '\0'; i++) {
        printf("message[%d] = '%c'\n", i, message[i]);
        
        // Count vowels
        char c = tolower(message[i]);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    printf("Total vowels: %d\n", vowel_count);
    
    return 0;
}
```

**While Loops:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function to demonstrate input validation with while loop
int get_valid_input(int min, int max) {
    int input;
    while (1) {
        printf("Enter a number between %d and %d: ", min, max);
        if (scanf("%d", &input) == 1) {
            if (input >= min && input <= max) {
                return input;
            } else {
                printf("Number out of range. Please try again.\n");
            }
        } else {
            printf("Invalid input. Please enter a number.\n");
            // Clear input buffer
            while (getchar() != '\n');
        }
    }
}

// Simple number guessing game
void number_guessing_game(void) {
    srand(time(NULL));
    int secret = rand() % 100 + 1;  // Random number 1-100
    int guess, attempts = 0;
    
    printf("Welcome to the Number Guessing Game!\n");
    printf("I'm thinking of a number between 1 and 100.\n");
    
    while (1) {
        printf("Enter your guess: ");
        if (scanf("%d", &guess) != 1) {
            printf("Please enter a valid number.\n");
            while (getchar() != '\n'); // Clear buffer
            continue;
        }
        
        attempts++;
        
        if (guess == secret) {
            printf("Congratulations! You guessed it in %d attempts!\n", attempts);
            break;
        } else if (guess < secret) {
            printf("Too low! Try again.\n");
        } else {
            printf("Too high! Try again.\n");
        }
        
        // Optional: Limit attempts
        if (attempts >= 10) {
            printf("Sorry, you've used all 10 attempts. The number was %d.\n", secret);
            break;
        }
    }
}

int main(void) {
    // Basic while loop - countdown
    printf("Countdown:\n");
    int count = 5;
    while (count > 0) {
        printf("%d...\n", count);
        count--;
    }
    printf("Blast off!\n");
    
    // While loop for processing data until condition met
    printf("\nProcessing data:\n");
    double values[] = {1.5, 2.3, -1.0, 4.7, 0.0, 3.2, -2.1};
    int index = 0;
    double sum = 0.0;
    
    // Process until we hit a negative number or end of array
    while (index < 7 && values[index] >= 0) {
        sum += values[index];
        printf("Added %.1f, running sum: %.1f\n", values[index], sum);
        index++;
    }
    
    if (index < 7) {
        printf("Stopped at negative value: %.1f\n", values[index]);
    }
    
    // Uncomment to run interactive examples
    // printf("\nInput validation demo:\n");
    // int user_choice = get_valid_input(1, 10);
    // printf("You entered: %d\n", user_choice);
    
    // number_guessing_game();
    
    return 0;
}
```

**Do-While Loops:**
```c
#include <stdio.h>
#include <ctype.h>

// Menu system using do-while
void display_menu(void) {
    printf("\n=== Application Menu ===\n");
    printf("1. Create new document\n");
    printf("2. Open existing document\n");
    printf("3. Save document\n");
    printf("4. Print document\n");
    printf("5. Settings\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
}

int get_menu_choice(void) {
    int choice;
    char buffer[100];
    
    do {
        display_menu();
        
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            if (sscanf(buffer, "%d", &choice) == 1) {
                if (choice >= 0 && choice <= 5) {
                    return choice;
                }
            }
        }
        
        printf("Invalid choice. Please enter 0-5.\n");
    } while (1);
}

// Data validation with do-while
double get_positive_double(const char* prompt) {
    double value;
    char buffer[100];
    
    do {
        printf("%s", prompt);
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            if (sscanf(buffer, "%lf", &value) == 1 && value > 0) {
                return value;
            }
        }
        printf("Please enter a positive number.\n");
    } while (1);
}

// Password strength checker
int check_password_strength(const char* password) {
    int length = strlen(password);
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    
    if (length < 8) {
        return 0; // Too short
    }
    
    for (int i = 0; i < length; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else if (strchr("!@#$%^&*()_+-=[]{}|;:,.<>?", password[i])) has_special = 1;
    }
    
    int strength = has_upper + has_lower + has_digit + has_special;
    return strength; // 0-4, where 4 is strongest
}

void password_creation_demo(void) {
    char password[100];
    int strength;
    
    printf("Password Creation Demo:\n");
    printf("Password must be at least 8 characters long and contain:\n");
    printf("- Uppercase letters\n- Lowercase letters\n- Numbers\n- Special characters\n\n");
    
    do {
        printf("Enter password: ");
        if (fgets(password, sizeof(password), stdin) != NULL) {
            // Remove newline
            password[strcspn(password, "\n")] = '\0';
            
            strength = check_password_strength(password);
            
            if (strength < 2) {
                printf("Password too weak (strength: %d/4). Please try again.\n", strength);
            } else {
                printf("Password accepted (strength: %d/4)\n", strength);
                break;
            }
        }
    } while (1);
}

int main(void) {
    printf("Do-While Loop Examples\n");
    printf("======================\n");
    
    // Simple do-while example
    int i = 0;
    printf("Basic do-while (executes at least once):\n");
    do {
        printf("i = %d\n", i);
        i++;
    } while (i < 3);
    
    // Compare with while loop that might not execute
    int j = 10;
    printf("\nWhile loop with initial condition false:\n");
    while (j < 3) {
        printf("j = %d\n", j); // This won't execute
        j++;
    }
    printf("j remains %d\n", j);
    
    // Do-while with same condition
    printf("\nDo-while with same condition:\n");
    do {
        printf("j = %d\n", j); // This executes once
        j++;
    } while (j < 3);
    
    // Interactive examples (commented out for demo)
    /*
    printf("\nMenu System Demo:\n");
    int choice;
    do {
        choice = get_menu_choice();
        
        switch (choice) {
            case 1: printf("Creating new document...\n"); break;
            case 2: printf("Opening existing document...\n"); break;
            case 3: printf("Saving document...\n"); break;
            case 4: printf("Printing document...\n"); break;
            case 5: printf("Opening settings...\n"); break;
            case 0: printf("Goodbye!\n"); break;
        }
        
    } while (choice != 0);
    
    // Data validation demo
    printf("\nData Validation Demo:\n");
    double radius = get_positive_double("Enter circle radius: ");
    double area = 3.14159 * radius * radius;
    printf("Circle area: %.2f\n", area);
    
    // Password demo
    password_creation_demo();
    */
    
    return 0;
}
```

#### Loop Control: break and continue

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Find first occurrence of a character in string
int find_first_char(const char* str, char target) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == target) {
            return i; // Found it, break out of loop
        }
    }
    return -1; // Not found
}

// Process array until specific condition using break
void process_until_negative(int arr[], int size) {
    printf("Processing array until negative number:\n");
    
    for (int i = 0; i < size; i++) {
        if (arr[i] < 0) {
            printf("Encountered negative number %d at index %d. Stopping.\n", 
                   arr[i], i);
            break; // Exit loop immediately
        }
        
        printf("Processing arr[%d] = %d\n", i, arr[i]);
        // Some processing logic here
    }
}

// Skip processing of certain elements using continue
void process_positive_numbers(int arr[], int size) {
    printf("\nProcessing only positive numbers:\n");
    int processed_count = 0;
    
    for (int i = 0; i < size; i++) {
        if (arr[i] <= 0) {
            printf("Skipping non-positive number: %d\n", arr[i]);
            continue; // Skip rest of loop body, go to next iteration
        }
        
        // This code only executes for positive numbers
        printf("Processing positive number: %d\n", arr[i]);
        processed_count++;
    }
    
    printf("Total positive numbers processed: %d\n", processed_count);
}

// Real-world example: Log file parser
void parse_log_entries(const char* log_data[], int num_entries) {
    printf("\nParsing log entries:\n");
    
    for (int i = 0; i < num_entries; i++) {
        // Skip empty lines
        if (strlen(log_data[i]) == 0) {
            continue;
        }
        
        // Skip comment lines (starting with #)
        if (log_data[i][0] == '#') {
            continue;
        }
        
        // Stop processing if we encounter "END" marker
        if (strncmp(log_data[i], "END", 3) == 0) {
            printf("End marker found. Stopping log processing.\n");
            break;
        }
        
        // Process valid log entry
        printf("Processing log entry %d: %s\n", i + 1, log_data[i]);
        
        // Example: Extract log level
        if (strncmp(log_data[i], "ERROR", 5) == 0) {
            printf("  -> Error detected! Needs attention.\n");
        } else if (strncmp(log_data[i], "WARN", 4) == 0) {
            printf("  -> Warning logged.\n");
        } else if (strncmp(log_data[i], "INFO", 4) == 0) {
            printf("  -> Information logged.\n");
        }
    }
}

// Nested loop control
void find_in_2d_array(int matrix[][4], int rows, int target) {
    printf("\nSearching for %d in 2D array:\n", target);
    int found = 0;
    
    for (int i = 0; i < rows && !found; i++) {
        for (int j = 0; j < 4; j++) {
            printf("Checking matrix[%d][%d] = %d\n", i, j, matrix[i][j]);
            
            if (matrix[i][j] == target) {
                printf("Found %d at position [%d][%d]\n", target, i, j);
                found = 1;
                break; // Break inner loop
            }
        }
        // The !found condition in outer loop prevents unnecessary iterations
    }
    
    if (!found) {
        printf("%d not found in matrix\n", target);
    }
}

// Input validation with break and continue
void validate_user_inputs(void) {
    printf("\nInput validation demo (enter 'quit' to stop):\n");
    char input[100];
    int valid_inputs = 0;
    
    while (1) {
        printf("Enter a positive integer (or 'quit'): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break; // End of input
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = '\0';
        
        // Check for quit command
        if (strcmp(input, "quit") == 0) {
            printf("Exiting input validation.\n");
            break;
        }
        
        // Convert to integer
        char* endptr;
        long value = strtol(input, &endptr, 10);
        
        // Check if conversion was successful and value is positive
        if (*endptr != '\0') {
            printf("Invalid input: not a number. Please try again.\n");
            continue;
        }
        
        if (value <= 0) {
            printf("Invalid input: must be positive. Please try again.\n");
            continue;
        }
        
        // Valid input - process it
        printf("Valid input received: %ld\n", value);
        valid_inputs++;
        
        if (valid_inputs >= 5) {
            printf("Collected enough valid inputs. Thank you!\n");
            break;
        }
    }
    
    printf("Total valid inputs collected: %d\n", valid_inputs);
}

int main(void) {
    // Break example with array processing
    int numbers[] = {10, 25, 33, -5, 42, 17};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    process_until_negative(numbers, size);
    
    // Continue example with same array
    process_positive_numbers(numbers, size);
    
    // Log parsing example
    const char* log_entries[] = {
        "# This is a comment",
        "",  // Empty line
        "INFO: Application started",
        "INFO: User logged in",
        "WARN: Low disk space",
        "ERROR: Database connection failed",
        "INFO: Retrying connection",
        "END",
        "INFO: This won't be processed"
    };
    
    int num_entries = sizeof(log_entries) / sizeof(log_entries[0]);
    parse_log_entries(log_entries, num_entries);
    
    // 2D array search example
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    find_in_2d_array(matrix, 3, 7);
    find_in_2d_array(matrix, 3, 15);
    
    // String search example
    const char* text = "Hello, World!";
    char search_char = 'o';
    int position = find_first_char(text, search_char);
    
    if (position != -1) {
        printf("\nFound '%c' at position %d in \"%s\"\n", 
               search_char, position, text);
    } else {
        printf("\n'%c' not found in \"%s\"\n", search_char, text);
    }
    
    // Interactive validation (commented for demo)
    // validate_user_inputs();
    
    return 0;
}
```

### 7. Functions Fundamentals {#functions-fundamentals}

Functions are the building blocks of modular C programming, enabling code reuse, organization, and abstraction.

#### Function Declaration, Definition, and Calling

**Basic Function Structure:**
```c
#include <stdio.h>
#include <math.h>

// Function declarations (prototypes)
double calculate_circle_area(double radius);
double calculate_circle_circumference(double radius);
void print_circle_info(double radius);
int factorial(int n);
double power(double base, int exponent);

// Function definitions
double calculate_circle_area(double radius) {
    if (radius < 0) {
        printf("Error: Radius cannot be negative\n");
        return -1.0;
    }
    return M_PI * radius * radius;
}

double calculate_circle_circumference(double radius) {
    if (radius < 0) {
        printf("Error: Radius cannot be negative\n");
        return -1.0;
    }
    return 2 * M_PI * radius;
}

void print_circle_info(double radius) {
    printf("\nCircle Information (radius = %.2f):\n", radius);
    printf("Area: %.2f square units\n", calculate_circle_area(radius));
    printf("Circumference: %.2f units\n", calculate_circle_circumference(radius));
}

// Recursive function
int factorial(int n) {
    if (n < 0) {
        printf("Error: Factorial not defined for negative numbers\n");
        return -1;
    }
    if (n == 0 || n == 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Iterative alternative to power function
double power(double base, int exponent) {
    if (exponent == 0) return 1.0;
    
    double result = 1.0;
    int abs_exp = abs(exponent);
    
    for (int i = 0; i < abs_exp; i++) {
        result *= base;
    }
    
    return (exponent < 0) ? 1.0 / result : result;
}

int main(void) {
    // Function calls
    double radius = 5.0;
    print_circle_info(radius);
    
    // Factorial examples
    printf("\nFactorial calculations:\n");
    for (int i = 0; i <= 10; i++) {
        printf("%d! = %d\n", i, factorial(i));
    }
    
    // Power function examples
    printf("\nPower calculations:\n");
    printf("2^8 = %.0f\n", power(2.0, 8));
    printf("3^4 = %.0f\n", power(3.0, 4));
    printf("2^(-3) = %.3f\n", power(2.0, -3));
    
    return 0;
}
```

#### Parameter Passing: Pass by Value vs Pass by Reference

**Pass by Value (Default in C):**
```c
#include <stdio.h>

// Pass by value - function receives copies of arguments
void modify_value(int x) {
    printf("Inside modify_value: x = %d\n", x);
    x = 100;  // This only modifies the local copy
    printf("Inside modify_value after change: x = %d\n", x);
}

// Function that returns a modified value
int double_value(int x) {
    return x * 2;
}

// Pass by reference using pointers
void modify_by_reference(int *x) {
    printf("Inside modify_by_reference: *x = %d\n", *x);
    *x = 200;  // This modifies the original variable
    printf("Inside modify_by_reference after change: *x = %d\n", *x);
}

// Swap function - demonstrates why pointers are necessary
void swap_values(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

// Function that modifies an array (arrays are always passed by reference)
void modify_array(int arr[], int size) {
    printf("Inside modify_array, modifying elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;  // Double each element
        printf("arr[%d] = %d\n", i, arr[i]);
    }
}

// Calculate array statistics using pointers for output parameters
void calculate_stats(int arr[], int size, int *min, int *max, double *average) {
    if (size <= 0) return;
    
    *min = arr[0];
    *max = arr[0];
    int sum = 0;
    
    for (int i = 0; i < size; i++) {
        sum += arr[i];
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
    }
    
    *average = (double)sum / size;
}

int main(void) {
    // Pass by value demonstration
    printf("Pass by Value Demo:\n");
    int original = 42;
    printf("Before function call: original = %d\n", original);
    modify_value(original);
    printf("After function call: original = %d\n", original);  // Still 42
    
    // Returning modified value
    int doubled = double_value(original);
    printf("Double of %d is %d\n", original, doubled);
    
    printf("\nPass by Reference Demo:\n");
    printf("Before function call: original = %d\n", original);
    modify_by_reference(&original);  // Pass address of original
    printf("After function call: original = %d\n", original);   // Now 200
    
    // Swap demonstration
    printf("\nSwap Demo:\n");
    int x = 10, y = 20;
    printf("Before swap: x = %d, y = %d\n", x, y);
    swap_values(&x, &y);
    printf("After swap: x = %d, y = %d\n", x, y);
    
    // Array modification
    printf("\nArray Modification Demo:\n");
    int numbers[] = {1, 2, 3, 4, 5};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    printf("Original array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    modify_array(numbers, size);
    
    printf("Array after modification: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Statistics calculation
    printf("\nArray Statistics Demo:\n");
    int data[] = {15, 23, 8, 42, 16, 4, 38, 12};
    int data_size = sizeof(data) / sizeof(data[0]);
    int min, max;
    double avg;
    
    calculate_stats(data, data_size, &min, &max, &avg);
    printf("Array: ");
    for (int i = 0; i < data_size; i++) {
        printf("%d ", data[i]);
    }
    printf("\nMin: %d, Max: %d, Average: %.2f\n", min, max, avg);
    
    return 0;
}
```

#### Return Values and Multiple Return Values

**Single Return Values:**
```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// Return different types
int add(int a, int b) {
    return a + b;
}

double calculate_bmi(double weight_kg, double height_m) {
    if (height_m <= 0) {
        return -1.0; // Error indicator
    }
    return weight_kg / (height_m * height_m);
}

// Return boolean (using stdbool.h)
bool is_prime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

// Return pointer to string
char* get_grade_description(char grade) {
    switch (grade) {
        case 'A': return "Excellent";
        case 'B': return "Good";
        case 'C': return "Average";
        case 'D': return "Below Average";
        case 'F': return "Failing";
        default: return "Invalid Grade";
    }
}

// Multiple return values using structure
typedef struct {
    int quotient;
    int remainder;
    bool valid;
} DivisionResult;

DivisionResult divide_with_remainder(int dividend, int divisor) {
    DivisionResult result;
    
    if (divisor == 0) {
        result.quotient = 0;
        result.remainder = 0;
        result.valid = false;
    } else {
        result.quotient = dividend / divisor;
        result.remainder = dividend % divisor;
        result.valid = true;
    }
    
    return result;
}

// Multiple return values using output parameters
void polar_to_cartesian(double radius, double angle_radians, 
                       double *x, double *y) {
    *x = radius * cos(angle_radians);
    *y = radius * sin(angle_radians);
}

// String processing with multiple outputs
typedef struct {
    int length;
    int word_count;
    int vowel_count;
    int digit_count;
} StringAnalysis;

StringAnalysis analyze_string(const char *str) {
    StringAnalysis analysis = {0, 0, 0, 0};
    bool in_word = false;
    
    for (int i = 0; str[i] != '\0'; i++) {
        analysis.length++;
        
        char c = tolower(str[i]);
        
        // Count words
        if (isalpha(str[i])) {
            if (!in_word) {
                analysis.word_count++;
                in_word = true;
            }
        } else {
            in_word = false;
        }
        
        // Count vowels
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            analysis.vowel_count++;
        }
        
        // Count digits
        if (isdigit(str[i])) {
            analysis.digit_count++;
        }
    }
    
    return analysis;
}

int main(void) {
    // Simple return values
    printf("Addition: 15 + 27 = %d\n", add(15, 27));
    
    double bmi = calculate_bmi(70.0, 1.75);
    printf("BMI: %.2f\n", bmi);
    
    // Boolean return
    printf("\nPrime number check:\n");
    for (int i = 10; i <= 20; i++) {
        printf("%d is %s\n", i, is_prime(i) ? "prime" : "not prime");
    }
    
    // String return
    printf("\nGrade descriptions:\n");
    char grades[] = {'A', 'C', 'F', 'X'};
    for (int i = 0; i < 4; i++) {
        printf("Grade %c: %s\n", grades[i], get_grade_description(grades[i]));
    }
    
    // Multiple return values with structure
    printf("\nDivision with remainder:\n");
    DivisionResult div_result = divide_with_remainder(17, 5);
    if (div_result.valid) {
        printf("17 ÷ 5 = %d remainder %d\n", 
               div_result.quotient, div_result.remainder);
    }
    
    div_result = divide_with_remainder(10, 0);
    if (!div_result.valid) {
        printf("Division by zero detected\n");
    }
    
    // Multiple return values with output parameters
    printf("\nPolar to Cartesian conversion:\n");
    double x, y;
    polar_to_cartesian(5.0, M_PI / 4, &x, &y);  // 45 degrees
    printf("Polar (5.0, π/4) = Cartesian (%.2f, %.2f)\n", x, y);
    
    // String analysis
    printf("\nString analysis:\n");
    const char *text = "Hello World! I have 123 characters.";
    StringAnalysis analysis = analyze_string(text);
    
    printf("Text: \"%s\"\n", text);
    printf("Length: %d characters\n", analysis.length);
    printf("Words: %d\n", analysis.word_count);
    printf("Vowels: %d\n", analysis.vowel_count);
    printf("Digits: %d\n", analysis.digit_count);
    
    return 0;
}
```

#### Function Pointers and Callbacks

Function pointers enable powerful programming patterns like callbacks, function tables, and dynamic behavior selection.

**Basic Function Pointers:**
```c
#include <stdio.h>
#include <stdlib.h>

// Simple mathematical functions
double add_double(double a, double b) { return a + b; }
double subtract_double(double a, double b) { return a - b; }
double multiply_double(double a, double b) { return a * b; }
double divide_double(double a, double b) { 
    return (b != 0) ? a / b : 0.0; 
}

// Function that takes a function pointer as parameter
double apply_operation(double x, double y, double (*operation)(double, double)) {
    return operation(x, y);
}

// Array of function pointers for calculator
typedef double (*MathOperation)(double, double);

// Calculator using function pointer array
void calculator_demo(void) {
    MathOperation operations[] = {
        add_double,
        subtract_double,
        multiply_double,
        divide_double
    };
    
    const char *op_names[] = {"Addition", "Subtraction", "Multiplication", "Division"};
    double a = 15.0, b = 4.0;
    
    printf("Calculator Demo (%.1f and %.1f):\n", a, b);
    for (int i = 0; i < 4; i++) {
        double result = operations[i](a, b);
        printf("%s: %.2f\n", op_names[i], result);
    }
}

// Callback example: Processing arrays with different functions
typedef void (*ArrayProcessor)(int[], int);

void print_array(int arr[], int size) {
    printf("Array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

void double_array(int arr[], int size) {
    printf("Doubling array elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}

void square_array(int arr[], int size) {
    printf("Squaring array elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= arr[i];
    }
}

void process_array(int arr[], int size, ArrayProcessor processor) {
    processor(arr, size);
}

// Real-world example: Event handling system
typedef enum {
    EVENT_CLICK,
    EVENT_KEYPRESS,
    EVENT_MOUSE_MOVE,
    EVENT_WINDOW_CLOSE
} EventType;

typedef struct {
    EventType type;
    int x, y;  // For mouse events
    char key;  // For key events
} Event;

typedef void (*EventHandler)(Event*);

// Event handlers
void handle_click(Event *e) {
    printf("Click handled at (%d, %d)\n", e->x, e->y);
}

void handle_keypress(Event *e) {
    printf("Key '%c' pressed\n", e->key);
}

void handle_mouse_move(Event *e) {
    printf("Mouse moved to (%d, %d)\n", e->x, e->y);
}

void handle_window_close(Event *e) {
    printf("Window close requested\n");
}

// Event system
typedef struct {
    EventHandler handlers[4];
} EventSystem;

void register_handlers(EventSystem *system) {
    system->handlers[EVENT_CLICK] = handle_click;
    system->handlers[EVENT_KEYPRESS] = handle_keypress;
    system->handlers[EVENT_MOUSE_MOVE] = handle_mouse_move;
    system->handlers[EVENT_WINDOW_CLOSE] = handle_window_close;
}

void dispatch_event(EventSystem *system, Event *event) {
    if (event->type >= 0 && event->type < 4) {
        system->handlers[event->type](event);
    }
}

// Sorting with comparison function pointers
typedef int (*ComparisonFunc)(const void *a, const void *b);

int compare_int_ascending(const void *a, const void *b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);  // Clever comparison
}

int compare_int_descending(const void *a, const void *b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ib > ia) - (ib < ia);
}

void print_int_array(int arr[], int size, const char* label) {
    printf("%s: ", label);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    // Basic function pointer usage
    printf("Function Pointer Basics:\n");
    double (*math_op)(double, double) = add_double;
    printf("Using function pointer for addition: %.2f\n", math_op(10.5, 3.7));
    
    math_op = multiply_double;
    printf("Using same pointer for multiplication: %.2f\n", math_op(10.5, 3.7));
    
    // Using function pointer as parameter
    printf("\nFunction as Parameter:\n");
    printf("Apply addition: %.2f\n", apply_operation(8.0, 2.0, add_double));
    printf("Apply division: %.2f\n", apply_operation(8.0, 2.0, divide_double));
    
    // Calculator demo
    printf("\n");
    calculator_demo();
    
    // Array processing with callbacks
    printf("\nArray Processing with Callbacks:\n");
    int numbers[] = {2, 4, 6, 8, 10};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    process_array(numbers, size, print_array);
    process_array(numbers, size, double_array);
    process_array(numbers, size, print_array);
    
    // Reset array
    int numbers2[] = {2, 4, 6, 8, 10};
    process_array(numbers2, size, square_array);
    process_array(numbers2, size, print_array);
    
    // Event handling system
    printf("\nEvent Handling System:\n");
    EventSystem event_system;
    register_handlers(&event_system);
    
    Event events[] = {
        {EVENT_CLICK, 100, 200, 0},
        {EVENT_KEYPRESS, 0, 0, 'A'},
        {EVENT_MOUSE_MOVE, 150, 250, 0},
        {EVENT_WINDOW_CLOSE, 0, 0, 0}
    };
    
    for (int i = 0; i < 4; i++) {
        dispatch_event(&event_system, &events[i]);
    }
    
    // Sorting with function pointers
    printf("\nSorting with Function Pointers:\n");
    int data[] = {64, 34, 25, 12, 22, 11, 90};
    int data_size = sizeof(data) / sizeof(data[0]);
    
    // Make copies for different sorts
    int ascending[7], descending[7];
    memcpy(ascending, data, sizeof(data));
    memcpy(descending, data, sizeof(data));
    
    print_int_array(data, data_size, "Original");
    
    qsort(ascending, data_size, sizeof(int), compare_int_ascending);
    print_int_array(ascending, data_size, "Ascending");
    
    qsort(descending, data_size, sizeof(int), compare_int_descending);
    print_int_array(descending, data_size, "Descending");
    
    return 0;
}
```

### 8. Scope and Storage Classes {#scope-storage}

Understanding scope and storage classes is crucial for writing maintainable and efficient C programs.

#### Local vs Global Scope

```c
#include <stdio.h>

// Global variables - accessible throughout the program
int global_counter = 0;
const char* program_name = "Scope Demo";

// Global function accessible from other files (external linkage)
void increment_global_counter(void) {
    global_counter++;
    printf("Global counter incremented to: %d\n", global_counter);
}

// Static global function - only accessible within this file
static void internal_helper(void) {
    printf("This function has internal linkage\n");
}

void demonstrate_local_scope(void) {
    // Local variables - only accessible within this function
    int local_var = 10;
    printf("Local variable: %d\n", local_var);
    
    // Block scope
    {
        int block_var = 20;
        int local_var = 30;  // Shadows the outer local_var
        printf("Block scope - local_var: %d, block_var: %d\n", 
               local_var, block_var);
    }
    
    // block_var is no longer accessible here
    printf("After block - local_var: %d\n", local_var);
    
    // Local variable shadows global
    int global_counter = 100;  // Shadows global global_counter
    printf("Local global_counter: %d\n", global_counter);
}

void demonstrate_scope_rules(void) {
    printf("\n=== Scope Rules Demo ===\n");
    
    // Access global variables
    printf("Program: %s\n", program_name);
    printf("Global counter: %d\n", global_counter);
    
    // Call functions with different scope
    demonstrate_local_scope();
    increment_global_counter();
    internal_helper();  // Can call static function within same file
    
    // Loop variable scope (C99 and later)
    for (int i = 0; i < 3; i++) {
        printf("Loop iteration: %d\n", i);
    }
    // i is not accessible here in C99+ mode
}

// Function parameters have function scope
int calculate_area(int width, int height) {
    // width and height are accessible throughout the function
    if (width <= 0 || height <= 0) {
        printf("Invalid dimensions\n");
        return -1;
    }
    
    int area = width * height;  // Local variable
    return area;
}

int main(void) {
    demonstrate_scope_rules();
    
    // Function parameter scope
    int w = 5, h = 10;
    int result = calculate_area(w, h);
    printf("Area calculation result: %d\n", result);
    
    return 0;
}
```

#### Static Variables and Functions

```c
#include <stdio.h>

// Static global variable - internal linkage (file scope only)
static int file_local_counter = 0;

// Regular function counter using static local variable
int get_next_id(void) {
    static int id_counter = 1000;  // Initialized only once
    return ++id_counter;
}

// Function call counter
void function_with_static(void) {
    static int call_count = 0;  // Retains value between calls
    int local_count = 0;        // Reset every call
    
    call_count++;
    local_count++;
    
    printf("Call #%d: static_count = %d, local_count = %d\n",
           call_count, call_count, local_count);
}

// Static function - internal linkage
static void helper_function(void) {
    printf("This static function is only accessible within this file\n");
    file_local_counter++;
}

// Demonstrate static array initialization
void static_array_demo(void) {
    static int numbers[5] = {1, 2, 3, 4, 5};  // Initialized once
    static int initialized = 0;
    
    if (!initialized) {
        printf("Static array initialized\n");
        initialized = 1;
    }
    
    printf("Static array contents: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
        numbers[i] *= 2;  // Modify for next call
    }
    printf("\n");
}

// Real-world example: Simple cache implementation
typedef struct {
    int key;
    int value;
    int valid;
} CacheEntry;

int cached_expensive_calculation(int input) {
    static CacheEntry cache[10] = {0};  // Static cache array
    static int cache_size = 0;
    
    // Check if result is cached
    for (int i = 0; i < cache_size; i++) {
        if (cache[i].valid && cache[i].key == input) {
            printf("Cache hit for input %d\n", input);
            return cache[i].value;
        }
    }
    
    // Simulate expensive calculation
    printf("Performing expensive calculation for input %d\n", input);
    int result = input * input + 2 * input + 1;  // Some computation
    
    // Store in cache if there's room
    if (cache_size < 10) {
        cache[cache_size].key = input;
        cache[cache_size].value = result;
        cache[cache_size].valid = 1;
        cache_size++;
        printf("Result cached (cache size: %d)\n", cache_size);
    }
    
    return result;
}

// Configuration system using static variables
typedef struct {
    int debug_level;
    int max_connections;
    char log_file[256];
} Config;

Config* get_config(void) {
    static Config config = {
        .debug_level = 1,
        .max_connections = 100,
        .log_file = "application.log"
    };
    
    static int initialized = 0;
    if (!initialized) {
        printf("Configuration initialized with defaults\n");
        initialized = 1;
    }
    
    return &config;
}

void set_debug_level(int level) {
    Config* config = get_config();
    config->debug_level = level;
    printf("Debug level set to: %d\n", level);
}

int get_debug_level(void) {
    return get_config()->debug_level;
}

int main(void) {
    printf("=== Static Variables Demo ===\n");
    
    // Static local variables
    printf("\nStatic local variable demo:\n");
    for (int i = 0; i < 5; i++) {
        function_with_static();
    }
    
    // ID generation with static
    printf("\nID generation:\n");
    for (int i = 0; i < 5; i++) {
        printf("Generated ID: %d\n", get_next_id());
    }
    
    // Static array demo
    printf("\nStatic array demo:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d: ", i + 1);
        static_array_demo();
    }
    
    // Static function demo
    printf("\nStatic function demo:\n");
    helper_function();
    printf("File local counter: %d\n", file_local_counter);
    
    // Cache demo
    printf("\nCache implementation demo:\n");
    int test_inputs[] = {5, 3, 5, 7, 3, 9, 5};
    for (int i = 0; i < 7; i++) {
        int result = cached_expensive_calculation(test_inputs[i]);
        printf("Input: %d, Result: %d\n", test_inputs[i], result);
    }
    
    // Configuration system demo
    printf("\nConfiguration system demo:\n");
    Config* config = get_config();
    printf("Initial debug level: %d\n", get_debug_level());
    
    set_debug_level(3);
    printf("Updated debug level: %d\n", get_debug_level());
    printf("Max connections: %d\n", config->max_connections);
    
    return 0;
}
```

#### External and Internal Linkage

Understanding linkage is crucial for multi-file programs.

**File 1: main.c**
```c
/* main.c - Demonstrates external and internal linkage */
#include <stdio.h>

// External declarations (defined in other files)
extern int shared_counter;           // Defined in utils.c
extern void increment_shared(void);  // Defined in utils.c
extern void print_shared(void);     // Defined in utils.c

// External function declaration
void demonstrate_linkage(void);     // Defined below

// Global variable with external linkage (available to other files)
int main_global = 100;

// Static global variable with internal linkage (file scope only)
static int main_local = 200;

// Static function with internal linkage
static void internal_function(void) {
    printf("This function is only accessible within main.c\n");
    printf("main_local = %d\n", main_local);
}

// Function with external linkage (default for functions)
void demonstrate_linkage(void) {
    printf("=== Linkage Demonstration ===\n");
    
    printf("main_global (external): %d\n", main_global);
    printf("main_local (static): %d\n", main_local);
    
    internal_function();
    
    printf("shared_counter (external): %d\n", shared_counter);
    increment_shared();
    print_shared();
}

int main(void) {
    demonstrate_linkage();
    
    // Call external functions
    printf("\nCalling external functions:\n");
    increment_shared();
    increment_shared();
    print_shared();
    
    return 0;
}
```

**File 2: utils.c**
```c
/* utils.c - Utility functions and variables */
#include <stdio.h>

// External variable accessible from other files
int shared_counter = 0;

// Static variable - internal linkage (only accessible in this file)
static int internal_counter = 1000;

// External function - accessible from other files
void increment_shared(void) {
    shared_counter++;
    internal_counter++;
    printf("Incremented: shared=%d, internal=%d\n", 
           shared_counter, internal_counter);
}

// External function
void print_shared(void) {
    printf("Current shared_counter: %d\n", shared_counter);
}

// Static function - internal linkage only
static void internal_utility(void) {
    printf("Internal utility function called\n");
}

// Function that uses internal static function
void call_internal(void) {
    internal_utility();
}

// Access external variable from main.c
extern int main_global;

void access_main_global(void) {
    printf("Accessing main_global from utils.c: %d\n", main_global);
    main_global += 50;
    printf("Modified main_global: %d\n", main_global);
}
```

**Complete Linkage Example:**
```c
/* complete_linkage_demo.c - Self-contained linkage demonstration */
#include <stdio.h>

// === Global Variables with Different Linkage ===

// External linkage - accessible from other translation units
int global_external = 10;

// Internal linkage - only accessible within this file
static int global_internal = 20;

// === Function Declarations ===

// External linkage function (default)
void external_function(void);

// Internal linkage function
static void internal_function(void);

// === Function Definitions ===

void external_function(void) {
    printf("External function called\n");
    printf("Can access global_external: %d\n", global_external);
    printf("Can access global_internal: %d\n", global_internal);
    
    // Can call internal function from same file
    internal_function();
}

static void internal_function(void) {
    static int call_count = 0;  // Static local variable
    call_count++;
    
    printf("Internal function called (call #%d)\n", call_count);
    printf("Modifying global_internal: %d -> ", global_internal);
    global_internal += 5;
    printf("%d\n", global_internal);
}

// Function to demonstrate const linkage
const int const_global = 42;  // External linkage
static const int const_internal = 84;  // Internal linkage

void demonstrate_const_linkage(void) {
    printf("const_global (external): %d\n", const_global);
    printf("const_internal (internal): %d\n", const_internal);
}

// === Storage Class Summary ===
void storage_class_summary(void) {
    // auto storage class (default for local variables)
    auto int auto_var = 1;
    
    // register storage class (hint to compiler)
    register int reg_var = 2;
    
    // static storage class (retains value, internal linkage)
    static int static_var = 3;
    
    // No extern needed here since we're not declaring, just using
    printf("\nStorage Class Summary:\n");
    printf("auto variable: %d\n", auto_var);
    printf("register variable: %d\n", reg_var);
    printf("static variable: %d\n", static_var);
    
    static_var++;  // Will retain this change
}

int main(void) {
    printf("=== Complete Linkage Demonstration ===\n");
    
    // Access global variables
    printf("global_external: %d\n", global_external);
    printf("global_internal: %d\n", global_internal);
    
    // Call functions
    external_function();
    
    // Note: Cannot call internal_function directly from outside
    // internal_function();  // This would cause a compilation error
    
    // Demonstrate const linkage
    printf("\n");
    demonstrate_const_linkage();
    
    // Storage class demonstration
    printf("\nCalling storage_class_summary multiple times:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d:\n", i + 1);
        storage_class_summary();
    }
    
    // Show final state
    printf("\nFinal global values:\n");
    printf("global_external: %d\n", global_external);
    printf("global_internal: %d\n", global_internal);
    
    return 0;
}
```

#### Storage Duration

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Static storage duration - global variables
int global_static_duration = 100;
static int file_static_duration = 200;

// Function to demonstrate automatic storage duration
void automatic_storage_demo(void) {
    // Automatic storage duration - local variables
    int local_auto = 10;        // Destroyed when function exits
    char local_array[100];      // Also automatic storage
    
    printf("Automatic storage - local_auto: %d\n", local_auto);
    
    // Modify local variables
    local_auto += 5;
    strcpy(local_array, "Hello from automatic storage");
    printf("Modified local_auto: %d\n", local_auto);
    printf("Local array: %s\n", local_array);
    
    // These variables will be destroyed when function returns
}

// Function to demonstrate static storage duration (local static)
void static_local_demo(void) {
    static int persistent_counter = 0;  // Static storage duration
    int temporary_counter = 0;          // Automatic storage duration
    
    persistent_counter++;
    temporary_counter++;
    
    printf("Static local: %d, Automatic local: %d\n", 
           persistent_counter, temporary_counter);
    
    // persistent_counter retains its value between calls
    // temporary_counter is reset to 0 each call
}

// Dynamic storage duration examples
void dynamic_storage_demo(void) {
    printf("\n=== Dynamic Storage Duration ===\n");
    
    // Allocate dynamic memory
    int *dynamic_array = malloc(5 * sizeof(int));
    if (dynamic_array == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Initialize dynamic memory
    for (int i = 0; i < 5; i++) {
        dynamic_array[i] = i * 10;
    }
    
    printf("Dynamic array contents: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", dynamic_array[i]);
    }
    printf("\n");
    
    // Dynamic memory persists until explicitly freed
    // (Even after this function returns, if we don't free it)
    
    // Allocate and initialize a string
    char *dynamic_string = malloc(50);
    if (dynamic_string != NULL) {
        strcpy(dynamic_string, "Dynamic string");
        printf("Dynamic string: %s\n", dynamic_string);
        
        // Must free dynamic memory
        free(dynamic_string);
        dynamic_string = NULL;  // Good practice
    }
    
    // Free the array
    free(dynamic_array);
    dynamic_array = NULL;
    
    printf("Dynamic memory freed\n");
}

// Thread-local storage duration (C11 feature)
// Note: This requires C11 compiler support
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 201112L
#include <threads.h>
_Thread_local int thread_local_var = 0;

void thread_local_demo(void) {
    printf("Thread-local variable: %d\n", thread_local_var);
    thread_local_var++;
}
#endif
#endif

// Real-world example: Memory pool for frequent allocations
typedef struct MemoryBlock {
    void *data;
    size_t size;
    int in_use;
    struct MemoryBlock *next;
} MemoryBlock;

typedef struct {
    MemoryBlock *blocks;
    size_t block_size;
    int total_blocks;
    int used_blocks;
} MemoryPool;

static MemoryPool global_pool = {NULL, 0, 0, 0};  // Static storage duration

void initialize_memory_pool(size_t block_size, int num_blocks) {
    global_pool.block_size = block_size;
    global_pool.total_blocks = num_blocks;
    global_pool.used_blocks = 0;
    
    // Allocate blocks (dynamic storage duration)
    for (int i = 0; i < num_blocks; i++) {
        MemoryBlock *block = malloc(sizeof(MemoryBlock));
        if (block == NULL) break;
        
        block->data = malloc(block_size);
        if (block->data == NULL) {
            free(block);
            break;
        }
        
        block->size = block_size;
        block->in_use = 0;
        block->next = global_pool.blocks;
        global_pool.blocks = block;
    }
    
    printf("Memory pool initialized: %d blocks of %zu bytes each\n", 
           num_blocks, block_size);
}

void* pool_allocate(void) {
    MemoryBlock *current = global_pool.blocks;
    
    while (current != NULL) {
        if (!current->in_use) {
            current->in_use = 1;
            global_pool.used_blocks++;
            printf("Allocated block from pool (used: %d/%d)\n", 
                   global_pool.used_blocks, global_pool.total_blocks);
            return current->data;
        }
        current = current->next;
    }
    
    printf("No available blocks in pool\n");
    return NULL;
}

void pool_free(void *ptr) {
    MemoryBlock *current = global_pool.blocks;
    
    while (current != NULL) {
        if (current->data == ptr && current->in_use) {
            current->in_use = 0;
            global_pool.used_blocks--;
            printf("Block returned to pool (used: %d/%d)\n", 
                   global_pool.used_blocks, global_pool.total_blocks);
            return;
        }
        current = current->next;
    }
    
    printf("Block not found in pool\n");
}

void cleanup_memory_pool(void) {
    MemoryBlock *current = global_pool.blocks;
    int freed_count = 0;
    
    while (current != NULL) {
        MemoryBlock *next = current->next;
        free(current->data);
        free(current);
        current = next;
        freed_count++;
    }
    
    global_pool.blocks = NULL;
    global_pool.used_blocks = 0;
    printf("Memory pool cleaned up: %d blocks freed\n", freed_count);
}

int main(void) {
    printf("=== Storage Duration Demonstration ===\n");
    
    // Static storage duration
    printf("Global static storage:\n");
    printf("global_static_duration: %d\n", global_static_duration);
    printf("file_static_duration: %d\n", file_static_duration);
    
    // Automatic storage duration
    printf("\nAutomatic storage duration:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d: ", i + 1);
        automatic_storage_demo();
    }
    
    // Static local storage duration
    printf("\nStatic local storage duration:\n");
    for (int i = 0; i < 5; i++) {
        printf("Call %d: ", i + 1);
        static_local_demo();
    }
    
    // Dynamic storage duration
    dynamic_storage_demo();
    
    // Thread-local storage (if supported)
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 201112L
    printf("\nThread-local storage (C11):\n");
    for (int i = 0; i < 3; i++) {
        thread_local_demo();
    }
#endif
#endif
    
    // Memory pool demonstration
    printf("\nMemory Pool Demonstration:\n");
    initialize_memory_pool(256, 5);
    
    // Allocate some blocks
    void *ptr1 = pool_allocate();
    void *ptr2 = pool_allocate();
    void *ptr3 = pool_allocate();
    
    // Use the memory
    if (ptr1) strcpy((char*)ptr1, "Block 1 data");
    if (ptr2) strcpy((char*)ptr2, "Block 2 data");
    
    // Free some blocks
    pool_free(ptr2);
    
    // Allocate again (should reuse freed block)
    void *ptr4 = pool_allocate();
    if (ptr4) strcpy((char*)ptr4, "Block 4 data (reused)");
    
    // Display memory contents
    if (ptr1) printf("ptr1 contents: %s\n", (char*)ptr1);
    if (ptr3) printf("ptr3 contents: %s\n", (char*)ptr3);
    if (ptr4) printf("ptr4 contents: %s\n", (char*)ptr4);
    
    // Clean up
    pool_free(ptr1);
    pool_free(ptr3);
    pool_free(ptr4);
    cleanup_memory_pool();
    
    return 0;
}
```

### 9. Basic Input/Output Operations {#basic-io}

Input/output operations are fundamental to interactive C programs. C provides both formatted and unformatted I/O functions.

#### Formatted Input/Output: printf and scanf

**printf Family Functions:**
```c
#include <stdio.h>
#include <stdarg.h>

// Custom printf-like function demonstration
void debug_printf(const char *format, ...) {
    printf("[DEBUG] ");
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int main(void) {
    // === Basic printf Usage ===
    printf("=== printf Format Specifiers ===\n");
    
    // Integer formats
    int num = 42;
    printf("Decimal: %d\n", num);
    printf("Octal: %o\n", num);
    printf("Hexadecimal: %x (lowercase), %X (uppercase)\n", num, num);
    printf("With field width: %5d\n", num);
    printf("With leading zeros: %05d\n", num);
    printf("Left-justified: %-5d|\n", num);
    
    // Floating-point formats
    double pi = 3.14159265359;
    printf("\nFloating-point formats:\n");
    printf("Default: %f\n", pi);
    printf("Scientific: %e\n", pi);
    printf("Scientific (uppercase): %E\n", pi);
    printf("Shorter of f/e: %g\n", pi);
    printf("Precision control: %.3f\n", pi);
    printf("Field width and precision: %10.4f\n", pi);
    
    // Character and string formats
    char ch = 'A';
    char name[] = "Alice";
    printf("\nCharacter and string formats:\n");
    printf("Character: %c (ASCII: %d)\n", ch, ch);
    printf("String: %s\n", name);
    printf("String with width: %10s|\n", name);
    printf("String left-justified: %-10s|\n", name);
    printf("String with precision: %.3s\n", name);
    
    // Pointer format
    int *ptr = &num;
    printf("\nPointer format:\n");
    printf("Pointer address: %p\n", (void*)ptr);
    printf("Pointer value: %d\n", *ptr);
    
    // Size and count formats
    size_t size = sizeof(int);
    printf("\nSize format:\n");
    printf("Size of int: %zu bytes\n", size);
    
    // Advanced formatting
    printf("\n=== Advanced printf Features ===\n");
    
    // Dynamic field width and precision
    int width = 10, precision = 3;
    printf("Dynamic formatting: %*.*f\n", width, precision, pi);
    
    // Positional parameters (not standard C, but GNU extension)
    // printf("Reorder: %2$s is %1$d years old\n", 25, "Bob");
    
    // Using sprintf for string formatting
    char buffer[100];
    int written = sprintf(buffer, "Formatted: %d %.2f %s", num, pi, name);
    printf("sprintf result: %s (wrote %d chars)\n", buffer, written);
    
    // Using snprintf for safe string formatting
    char safe_buffer[20];
    int would_write = snprintf(safe_buffer, sizeof(safe_buffer), 
                              "Very long string: %d %.6f %s", num, pi, name);
    printf("snprintf result: %s\n", safe_buffer);
    printf("Would write %d chars (buffer size: %zu)\n", would_write, sizeof(safe_buffer));
    
    // Custom debug function
    debug_printf("Custom printf: value=%d, pi=%.2f\n", num, pi);
    
    return 0;
}
```

**scanf Family Functions and Input Validation:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Safe integer input function
int safe_get_int(const char *prompt, int min, int max) {
    char buffer[100];
    int value;
    char *endptr;
    
    while (1) {
        printf("%s", prompt);
        
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            printf("Error reading input\n");
            continue;
        }
        
        // Remove newline
        buffer[strcspn(buffer, "\n")] = '\0';
        
        // Convert to integer
        errno = 0;
        value = strtol(buffer, &endptr, 10);
        
        // Check for conversion errors
        if (errno == ERANGE) {
            printf("Number out of range. Please try again.\n");
            continue;
        }
        
        if (endptr == buffer || *endptr != '\0') {
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        
        if (value < min || value > max) {
            printf("Value must be between %d and %d. Please try again.\n", min, max);
            continue;
        }
        
        return value;
    }
}

// Safe string input function
void safe_get_string(const char *prompt, char *buffer, size_t buffer_size) {
    while (1) {
        printf("%s", prompt);
        
        if (fgets(buffer, buffer_size, stdin) != NULL) {
            // Remove trailing newline
            buffer[strcspn(buffer, "\n")] = '\0';
            
            if (strlen(buffer) > 0) {
                return; // Valid non-empty string
            }
        }
        
        printf("Please enter a valid string.\n");
    }
}

// Demonstrate scanf variations
void scanf_demonstration(void) {
    printf("\n=== scanf Demonstration ===\n");
    printf("Note: This demo uses scanf for educational purposes.\n");
    printf("In real applications, prefer safer alternatives.\n");
    
    // Basic scanf usage (commented out for safety)
    /*
    int age;
    printf("Enter your age: ");
    if (scanf("%d", &age) == 1) {
        printf("You entered: %d\n", age);
    } else {
        printf("Invalid input\n");
    }
    
    // Clear input buffer after scanf
    while (getchar() != '\n');
    
    // Multiple inputs
    int day, month, year;
    printf("Enter date (dd mm yyyy): ");
    if (scanf("%d %d %d", &day, &month, &year) == 3) {
        printf("Date: %02d/%02d/%04d\n", day, month, year);
    }
    
    // String input with scanf (dangerous without width limit)
    char name[50];
    printf("Enter name (max 49 chars): ");
    scanf("%49s", name);  // Limit input to prevent buffer overflow
    printf("Hello, %s!\n", name);
    */
    
    printf("Skipping interactive scanf demo for safety.\n");
}

// Real-world input validation example
typedef struct {
    char name[50];
    int age;
    double salary;
    char email[100];
} Employee;

Employee input_employee_data(void) {
    Employee emp = {0};
    
    printf("\n=== Employee Data Entry ===\n");
    
    // Get name
    safe_get_string("Enter employee name: ", emp.name, sizeof(emp.name));
    
    // Get age with validation
    emp.age = safe_get_int("Enter age (18-100): ", 18, 100);
    
    // Get salary
    char buffer[100];
    while (1) {
        printf("Enter salary: $");
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            char *endptr;
            emp.salary = strtod(buffer, &endptr);
            
            if (endptr != buffer && (*endptr == '\n' || *endptr == '\0')) {
                if (emp.salary >= 0) {
                    break;
                }
            }
        }
        printf("Please enter a valid positive number.\n");
    }
    
    // Get email
    safe_get_string("Enter email: ", emp.email, sizeof(emp.email));
    
    return emp;
}

void print_employee(const Employee *emp) {
    printf("\n=== Employee Information ===\n");
    printf("Name: %s\n", emp->name);
    printf("Age: %d\n", emp->age);
    printf("Salary: $%.2f\n", emp->salary);
    printf("Email: %s\n", emp->email);
}

// Menu-driven input example
int display_menu(void) {
    printf("\n=== Main Menu ===\n");
    printf("1. Add employee\n");
    printf("2. Display employee\n");
    printf("3. Calculate statistics\n");
    printf("0. Exit\n");
    
    return safe_get_int("Select option (0-3): ", 0, 3);
}

int main(void) {
    // printf demonstrations
    printf("=== Input/Output Demonstrations ===\n");
    
    // Show scanf concepts (but don't actually use it)
    scanf_demonstration();
    
    // Safe input methods
    printf("\n=== Safe Input Methods ===\n");
    
    // Interactive employee data entry (commented for demo)
    /*
    Employee emp = input_employee_data();
    print_employee(&emp);
    
    // Menu system example
    int choice;
    do {
        choice = display_menu();
        
        switch (choice) {
            case 1:
                printf("Adding employee...\n");
                // emp = input_employee_data();
                break;
            case 2:
                printf("Displaying employee...\n");
                // print_employee(&emp);
                break;
            case 3:
                printf("Calculating statistics...\n");
                break;
            case 0:
                printf("Goodbye!\n");
                break;
        }
    } while (choice != 0);
    */
    
    // Instead, demonstrate with preset data
    Employee sample_emp = {
        .name = "John Doe",
        .age = 30,
        .salary = 75000.50,
        .email = "john.doe@company.com"
    };
    
    printf("Sample employee data:\n");
    print_employee(&sample_emp);
    
    // Show different output formatting
    printf("\n=== Alternative Formatting ===\n");
    printf("Compact: %s (%d) - $%.0f\n", 
           sample_emp.name, sample_emp.age, sample_emp.salary);
    printf("Detailed: %-20s | Age: %2d | Salary: $%8.2f\n", 
           sample_emp.name, sample_emp.age, sample_emp.salary);
    
    return 0;
}
```

#### Character Input/Output

```c
#include <stdio.h>
#include <ctype.h>
#include <string.h>

// Character processing utilities
void analyze_character(int ch) {
    printf("Character: ");
    if (isprint(ch)) {
        printf("'%c' ", ch);
    } else {
        printf("(non-printable) ");
    }
    
    printf("ASCII: %d", ch);
    
    if (isalpha(ch)) printf(" [Letter]");
    if (isdigit(ch)) printf(" [Digit]");
    if (isspace(ch)) printf(" [Whitespace]");
    if (ispunct(ch)) printf(" [Punctuation]");
    if (isupper(ch)) printf(" [Uppercase]");
    if (islower(ch)) printf(" [Lowercase]");
    
    printf("\n");
}

// Read and process characters one by one
void character_input_demo(void) {
    printf("=== Character Input Demo ===\n");
    printf("Type some characters (Ctrl+D or Ctrl+Z to end):\n");
    
    int ch;
    int char_count = 0, line_count = 0, word_count = 0;
    int in_word = 0;
    
    while ((ch = getchar()) != EOF) {
        char_count++;
        
        if (ch == '\n') {
            line_count++;
            in_word = 0;
        } else if (isspace(ch)) {
            in_word = 0;
        } else if (!in_word) {
            word_count++;
            in_word = 1;
        }
        
        analyze_character(ch);
    }
    
    printf("\nStatistics:\n");
    printf("Characters: %d\n", char_count);
    printf("Lines: %d\n", line_count);
    printf("Words: %d\n", word_count);
}

// Text filter examples
void uppercase_filter(void) {
    printf("\n=== Uppercase Filter ===\n");
    printf("Enter text (empty line to end):\n");
    
    int ch;
    while ((ch = getchar()) != EOF && ch != '\n') {
        putchar(toupper(ch));
    }
    putchar('\n');
}

void character_replacement_filter(void) {
    printf("\n=== Character Replacement Filter ===\n");
    printf("Enter text (replaces vowels with '*'):\n");
    
    int ch;
    while ((ch = getchar()) != EOF && ch != '\n') {
        char lower_ch = tolower(ch);
        if (lower_ch == 'a' || lower_ch == 'e' || lower_ch == 'i' || 
            lower_ch == 'o' || lower_ch == 'u') {
            putchar('*');
        } else {
            putchar(ch);
        }
    }
    putchar('\n');
}

// Password input (hiding characters)
void get_password(char *password, size_t max_len) {
    printf("Enter password: ");
    
    size_t i = 0;
    int ch;
    
    // Note: This is a simplified example. Real password input
    // requires platform-specific code to disable echo.
    while (i < max_len - 1 && (ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 8 || ch == 127) { // Backspace or DEL
            if (i > 0) {
                i--;
                printf("\b \b"); // Move back, print space, move back
            }
        } else {
            password[i++] = ch;
            putchar('*'); // Print asterisk instead of character
        }
    }
    
    password[i] = '\0';
    putchar('\n');
}

// Line-oriented input processing
void process_lines(void) {
    printf("\n=== Line Processing Demo ===\n");
    printf("Enter lines of text ('quit' to stop):\n");
    
    char line[256];
    int line_number = 1;
    
    while (fgets(line, sizeof(line), stdin) != NULL) {
        // Remove trailing newline
        line[strcspn(line, "\n")] = '\0';
        
        if (strcmp(line, "quit") == 0) {
            break;
        }
        
        // Process the line
        printf("Line %d (%zu chars): %s\n", 
               line_number++, strlen(line), line);
        
        // Reverse the line
        printf("Reversed: ");
        for (int i = strlen(line) - 1; i >= 0; i--) {
            putchar(line[i]);
        }
        putchar('\n');
        
        // Count words in line
        int words = 0;
        int in_word = 0;
        for (size_t i = 0; i < strlen(line); i++) {
            if (isspace(line[i])) {
                in_word = 0;
            } else if (!in_word) {
                words++;
                in_word = 1;
            }
        }
        printf("Words: %d\n", words);
        printf("---\n");
    }
}

// Binary character operations
void hex_dump(const char *data, size_t length) {
    printf("\n=== Hex Dump ===\n");
    
    for (size_t i = 0; i < length; i += 16) {
        // Print address
        printf("%08zx: ", i);
        
        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", (unsigned char)data[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        // Print ASCII representation
        for (size_t j = 0; j < 16 && i + j < length; j++) {
            char ch = data[i + j];
            putchar(isprint(ch) ? ch : '.');
        }
        
        printf("|\n");
    }
}

int main(void) {
    printf("=== Character Input/Output Operations ===\n");
    
    // Demonstrate character analysis
    printf("Character Analysis Examples:\n");
    char test_chars[] = {'A', 'a', '5', ' ', '\n', '\t', '!', '@'};
    for (size_t i = 0; i < sizeof(test_chars); i++) {
        analyze_character(test_chars[i]);
    }
    
    // Demo data for other functions (to avoid interactive input in demo)
    printf("\n=== Filter Demonstrations ===\n");
    
    // Simulate uppercase filter
    char sample_text[] = "Hello, World! This is a test.";
    printf("Original: %s\n", sample_text);
    printf("Uppercase: ");
    for (size_t i = 0; i < strlen(sample_text); i++) {
        putchar(toupper(sample_text[i]));
    }
    putchar('\n');
    
    // Simulate vowel replacement
    printf("Vowel replacement: ");
    for (size_t i = 0; i < strlen(sample_text); i++) {
        char ch = tolower(sample_text[i]);
        if (ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u') {
            putchar('*');
        } else {
            putchar(sample_text[i]);
        }
    }
    putchar('\n');
    
    // Hex dump demonstration
    hex_dump(sample_text, strlen(sample_text));
    
    // Interactive demos (commented out for this demonstration)
    /*
    character_input_demo();
    uppercase_filter();
    character_replacement_filter();
    
    char password[100];
    get_password(password, sizeof(password));
    printf("Password length: %zu\n", strlen(password));
    
    process_lines();
    */
    
    return 0;
}
```

#### Buffered vs Unbuffered I/O

```c
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

// Demonstrate different buffering modes
void demonstrate_buffering(void) {
    printf("=== I/O Buffering Demonstration ===\n");
    
    // Full buffering (default for files)
    printf("Full buffering test: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        // Output may not appear immediately
        sleep(1);
    }
    printf("\n");
    
    // Forced flush
    printf("With fflush(): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        fflush(stdout);  // Force output
        sleep(1);
    }
    printf("\n");
    
    // Line buffering demonstration
    printf("Line buffering (terminal default):\n");
    printf("This appears immediately because it ends with newline\n");
    printf("This might not appear immediately...");
    fflush(stdout);
    printf(" until now!\n");
    
    // No buffering
    setbuf(stdout, NULL);  // Disable buffering
    printf("Unbuffered output: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        sleep(1);  // Each character should appear immediately
    }
    printf("\n");
    
    // Restore default buffering
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
}

// Custom buffering example
void custom_buffering_demo(void) {
    printf("\n=== Custom Buffering ===\n");
    
    FILE *file = fopen("buffer_test.txt", "w");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }
    
    // Set custom buffer size
    char custom_buffer[1024];
    setvbuf(file, custom_buffer, _IOFBF, sizeof(custom_buffer));
    
    // Write data (will be buffered)
    fprintf(file, "Line 1: This is buffered output\n");
    fprintf(file, "Line 2: Still in buffer\n");
    fprintf(file, "Line 3: Buffer might be full soon\n");
    
    printf("Data written to file (but may be in buffer)\n");
    
    // Force flush
    fflush(file);
    printf("Buffer flushed to file\n");
    
    fclose(file);
    
    // Read back the file
    file = fopen("buffer_test.txt", "r");
    if (file != NULL) {
        char line[256];
        printf("File contents:\n");
        while (fgets(line, sizeof(line), file) != NULL) {
            printf("  %s", line);
        }
        fclose(file);
    }
    
    // Clean up
    remove("buffer_test.txt");
}

// Performance comparison: buffered vs unbuffered
void performance_comparison(void) {
    printf("\n=== Performance Comparison ===\n");
    
    const int num_writes = 10000;
    clock_t start, end;
    
    // Test 1: Buffered output
    FILE *buffered = fopen("buffered_test.txt", "w");
    if (buffered == NULL) {
        perror("Cannot create buffered test file");
        return;
    }
    
    start = clock();
    for (int i = 0; i < num_writes; i++) {
        fprintf(buffered, "Line %d: Some test data here\n", i);
    }
    fclose(buffered);
    end = clock();
    
    double buffered_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Buffered writes (%d lines): %.4f seconds\n", num_writes, buffered_time);
    
    // Test 2: Unbuffered output
    FILE *unbuffered = fopen("unbuffered_test.txt", "w");
    if (unbuffered == NULL) {
        perror("Cannot create unbuffered test file");
        return;
    }
    
    setbuf(unbuffered, NULL);  // Disable buffering
    
    start = clock();
    for (int i = 0; i < num_writes; i++) {
        fprintf(unbuffered, "Line %d: Some test data here\n", i);
    }
    fclose(unbuffered);
    end = clock();
    
    double unbuffered_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Unbuffered writes (%d lines): %.4f seconds\n", num_writes, unbuffered_time);
    
    printf("Performance difference: %.2fx\n", unbuffered_time / buffered_time);
    
    // Clean up
    remove("buffered_test.txt");
    remove("unbuffered_test.txt");
}

// Buffer overflow protection example
void safe_input_with_buffer_control(void) {
    printf("\n=== Safe Input with Buffer Control ===\n");
    
    char buffer[10];  // Small buffer to demonstrate overflow protection
    
    printf("Enter text (max 9 chars): ");
    fflush(stdout);
    
    // Simulate safe input (without actual user input for demo)
    const char *simulated_input = "This is a very long input string";
    printf("Simulated input: \"%s\"\n", simulated_input);
    
    // Safe copy with size limit
    strncpy(buffer, simulated_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    
    printf("Buffer contents (safely truncated): \"%s\"\n", buffer);
    printf("Buffer size: %zu, String length: %zu\n", 
           sizeof(buffer), strlen(buffer));
    
    // Show what happens without protection
    char unsafe_buffer[10];
    // DON'T DO THIS: strcpy(unsafe_buffer, simulated_input);  // Buffer overflow!
    
    printf("Safe programming prevented buffer overflow!\n");
}

// Stream state management
void stream_state_demo(void) {
    printf("\n=== Stream State Management ===\n");
    
    FILE *file = fopen("stream_test.txt", "w+");
    if (file == NULL) {
        perror("Cannot create test file");
        return;
    }
    
    // Write some data
    fprintf(file, "Hello, World!\n");
    fprintf(file, "Line 2\n");
    fprintf(file, "Line 3\n");
    
    // Check stream state
    if (ferror(file)) {
        printf("Error occurred during write\n");
    } else {
        printf("Write operations successful\n");
    }
    
    // Flush to ensure data is written
    fflush(file);
    
    // Try to read without rewinding (will fail)
    char buffer[100];
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        if (feof(file)) {
            printf("End of file reached (expected)\n");
        } else if (ferror(file)) {
            printf("Error occurred during read\n");
        }
    }
    
    // Clear error state and rewind
    clearerr(file);
    rewind(file);
    
    printf("Stream state cleared, reading from beginning:\n");
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("  %s", buffer);
    }
    
    fclose(file);
    remove("stream_test.txt");
}

int main(void) {
    printf("=== Buffered vs Unbuffered I/O ===\n");
    
    // Note: Some demonstrations may not show differences on all systems
    // as modern systems optimize I/O operations
    
    demonstrate_buffering();
    custom_buffering_demo();
    performance_comparison();
    safe_input_with_buffer_control();
    stream_state_demo();
    
    printf("\nBuffer types summary:\n");
    printf("_IOFBF: Full buffering (default for files)\n");
    printf("_IOLBF: Line buffering (default for terminals)\n");
    printf("_IONBF: No buffering (unbuffered I/O)\n");
    
    return 0;
}
```

---

## Part II: Intermediate Level - Advanced Concepts

### 10. Pointers and Memory Management {#pointers-memory}

Pointers are one of the most powerful and fundamental features of C, enabling direct memory access and efficient data manipulation.

#### Pointer Fundamentals

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pointer_basics(void) {
    printf("=== Pointer Fundamentals ===\n");
    
    // Basic pointer declaration and initialization
    int value = 42;
    int *ptr = &value;  // ptr points to the address of value
    
    printf("value = %d\n", value);
    printf("Address of value: %p\n", (void*)&value);
    printf("ptr = %p\n", (void*)ptr);
    printf("*ptr = %d\n", *ptr);  // Dereference ptr to get value
    
    // Modify value through pointer
    *ptr = 100;
    printf("After *ptr = 100:\n");
    printf("value = %d\n", value);
    printf("*ptr = %d\n", *ptr);
    
    // Pointer to pointer
    int **double_ptr = &ptr;
    printf("\nPointer to pointer:\n");
    printf("ptr = %p\n", (void*)ptr);
    printf("&ptr = %p\n", (void*)&ptr);
    printf("double_ptr = %p\n", (void*)double_ptr);
    printf("*double_ptr = %p\n", (void*)*double_ptr);
    printf("**double_ptr = %d\n", **double_ptr);
    
    // NULL pointer
    int *null_ptr = NULL;
    printf("\nNULL pointer:\n");
    printf("null_ptr = %p\n", (void*)null_ptr);
    
    if (null_ptr == NULL) {
        printf("null_ptr is NULL\n");
    }
    
    // Don't dereference NULL pointer!
    // printf("*null_ptr = %d\n", *null_ptr);  // This would crash
}

// Different data types and their pointers
void pointer_types_demo(void) {
    printf("\n=== Pointer Types ===\n");
    
    // Integer pointer
    int i = 10;
    int *int_ptr = &i;
    printf("int: value=%d, size=%zu, ptr=%p\n", 
           *int_ptr, sizeof(int), (void*)int_ptr);
    
    // Character pointer
    char c = 'A';
    char *char_ptr = &c;
    printf("char: value='%c', size=%zu, ptr=%p\n", 
           *char_ptr, sizeof(char), (void*)char_ptr);
    
    // Double pointer
    double d = 3.14159;
    double *double_ptr = &d;
    printf("double: value=%.5f, size=%zu, ptr=%p\n", 
           *double_ptr, sizeof(double), (void*)double_ptr);
    
    // Pointer arithmetic
    printf("\nPointer arithmetic:\n");
    printf("int_ptr = %p\n", (void*)int_ptr);
    printf("int_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(int_ptr + 1), (char*)(int_ptr + 1) - (char*)int_ptr);
    
    printf("char_ptr = %p\n", (void*)char_ptr);
    printf("char_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(char_ptr + 1), (char*)(char_ptr + 1) - (char*)char_ptr);
    
    printf("double_ptr = %p\n", (void*)double_ptr);
    printf("double_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(double_ptr + 1), (char*)(double_ptr + 1) - (char*)double_ptr);
}

// Function pointers revisited
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }

void function_pointers_advanced(void) {
    printf("\n=== Advanced Function Pointers ===\n");
    
    // Function pointer declaration
    int (*operation)(int, int);
    
    // Assign function to pointer
    operation = add;
    printf("add(5, 3) = %d\n", operation(5, 3));
    
    operation = multiply;
    printf("multiply(5, 3) = %d\n", operation(5, 3));
    
    // Array of function pointers
    int (*operations[])(int, int) = {add, multiply};
    const char *names[] = {"add", "multiply"};
    
    for (size_t i = 0; i < 2; i++) {
        printf("%s(7, 4) = %d\n", names[i], operations[i](7, 4));
    }
    
    // Function pointer as parameter
    void apply_operation(int x, int y, int (*op)(int, int), const char *name) {
        printf("%s(%d, %d) = %d\n", name, x, y, op(x, y));
    }
    
    apply_operation(8, 2, add, "add");
    apply_operation(8, 2, multiply, "multiply");
}

// Const pointers and pointer to const
void const_pointers_demo(void) {
    printf("\n=== Const Pointers ===\n");
    
    int value1 = 10, value2 = 20;
    
    // Regular pointer - can change both pointer and value
    int *ptr1 = &value1;
    printf("Regular pointer: *ptr1 = %d\n", *ptr1);
    *ptr1 = 15;  // OK: change value
    ptr1 = &value2;  // OK: change pointer
    printf("After changes: *ptr1 = %d\n", *ptr1);
    
    // Pointer to const - can change pointer, cannot change value
    const int *ptr2 = &value1;
    printf("Pointer to const: *ptr2 = %d\n", *ptr2);
    // *ptr2 = 25;  // ERROR: cannot change value
    ptr2 = &value2;  // OK: can change pointer
    printf("After pointer change: *ptr2 = %d\n", *ptr2);
    
    // Const pointer - cannot change pointer, can change value
    int *const ptr3 = &value1;
    printf("Const pointer: *ptr3 = %d\n", *ptr3);
    *ptr3 = 30;  // OK: can change value
    // ptr3 = &value2;  // ERROR: cannot change pointer
    printf("After value change: *ptr3 = %d\n", *ptr3);
    
    // Const pointer to const - cannot change either
    const int *const ptr4 = &value1;
    printf("Const pointer to const: *ptr4 = %d\n", *ptr4);
    // *ptr4 = 35;  // ERROR: cannot change value
    // ptr4 = &value2;  // ERROR: cannot change pointer
}

// Real-world example: Generic swap function
void swap_ints(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void swap_generic(void *a, void *b, size_t size) {
    unsigned char *pa = (unsigned char*)a;
    unsigned char *pb = (unsigned char*)b;
    
    for (size_t i = 0; i < size; i++) {
        unsigned char temp = pa[i];
        pa[i] = pb[i];
        pb[i] = temp;
    }
}

void swap_demo(void) {
    printf("\n=== Swap Functions Demo ===\n");
    
    // Integer swap
    int x = 10, y = 20;
    printf("Before swap: x=%d, y=%d\n", x, y);
    swap_ints(&x, &y);
    printf("After int swap: x=%d, y=%d\n", x, y);
    
    // Generic swap with doubles
    double a = 3.14, b = 2.71;
    printf("Before swap: a=%.2f, b=%.2f\n", a, b);
    swap_generic(&a, &b, sizeof(double));
    printf("After generic swap: a=%.2f, b=%.2f\n", a, b);
    
    // Generic swap with strings (array of characters)
    char str1[] = "Hello";
    char str2[] = "World";
    printf("Before swap: str1='%s', str2='%s'\n", str1, str2);
    
    // Swap individual characters
    for (size_t i = 0; i < 5; i++) {
        swap_generic(&str1[i], &str2[i], sizeof(char));
    }
    printf("After character swap: str1='%s', str2='%s'\n", str1, str2);
}

int main(void) {
    pointer_basics();
    pointer_types_demo();
    function_pointers_advanced();
    const_pointers_demo();
    swap_demo();
    
    printf("\n=== Pointer Best Practices ===\n");
    printf("1. Always initialize pointers (or set to NULL)\n");
    printf("2. Check for NULL before dereferencing\n");
    printf("3. Set pointer to NULL after freeing memory\n");
    printf("4. Use const appropriately for read-only data\n");
    printf("5. Be careful with pointer arithmetic\n");
    printf("6. Don't return pointers to local variables\n");
    
    return 0;
}
```

#### Pointer Arithmetic and Arrays

```c
#include <stdio.h>
#include <string.h>

void array_pointer_relationship(void) {
    printf("=== Array-Pointer Relationship ===\n");
    
    int numbers[] = {10, 20, 30, 40, 50};
    int *ptr = numbers;  // Same as &numbers[0]
    
    printf("Array elements using array notation:\n");
    for (size_t i = 0; i < 5; i++) {
        printf("numbers[%zu] = %d (address: %p)\n", 
               i, numbers[i], (void*)&numbers[i]);
    }
    
    printf("\nSame elements using pointer notation:\n");
    for (size_t i = 0; i < 5; i++) {
        printf("*(ptr + %zu) = %d (address: %p)\n", 
               i, *(ptr + i), (void*)(ptr + i));
    }
    
    printf("\nEquivalent expressions:\n");
    printf("numbers[2] = %d\n", numbers[2]);
    printf("*(numbers + 2) = %d\n", *(numbers + 2));
    printf("*(ptr + 2) = %d\n", *(ptr + 2));
    printf("ptr[2] = %d\n", ptr[2]);
    
    // Array name is a constant pointer
    printf("\nArray name as pointer:\n");
    printf("numbers = %p\n", (void*)numbers);
    printf("&numbers[0] = %p\n", (void*)&numbers[0]);
    printf("ptr = %p\n", (void*)ptr);
}

void pointer_arithmetic_demo(void) {
    printf("\n=== Pointer Arithmetic ===\n");
    
    int data[] = {100, 200, 300, 400, 500};
    int *start = data;
    int *end = data + 5;  // Points one past the last element
    
    printf("Array traversal using pointer arithmetic:\n");
    for (int *current = start; current < end; current++) {
        printf("Address: %p, Value: %d, Index: %ld\n", 
               (void*)current, *current, current - start);
    }
    
    // Pointer subtraction
    printf("\nPointer subtraction:\n");
    printf("end - start = %ld elements\n", end - start);
    printf("Distance in bytes: %ld\n", (char*)end - (char*)start);
    
    // Reverse traversal
    printf("\nReverse traversal:\n");
    for (int *current = end - 1; current >= start; current--) {
        printf("Value: %d, Position from start: %ld\n", 
               *current, current - start);
    }
}

// String manipulation using pointers
void string_pointer_operations(void) {
    printf("\n=== String Pointer Operations ===\n");
    
    char message[] = "Hello, World!";
    char *ptr = message;
    
    printf("Original string: '%s'\n", message);
    
    // Count characters using pointers
    int length = 0;
    char *temp = ptr;
    while (*temp != '\0') {
        length++;
        temp++;
    }
    printf("Length calculated with pointers: %d\n", length);
    
    // Find first occurrence of character
    char target = 'o';
    char *found = ptr;
    while (*found != '\0' && *found != target) {
        found++;
    }
    
    if (*found == target) {
        printf("Found '%c' at position %ld\n", target, found - ptr);
    } else {
        printf("Character '%c' not found\n", target);
    }
    
    // Reverse string in place using two pointers
    char copy[] = "Hello, World!";
    char *left = copy;
    char *right = copy + strlen(copy) - 1;
    
    while (left < right) {
        char temp = *left;
        *left = *right;
        *right = temp;
        left++;
        right--;
    }
    
    printf("Reversed string: '%s'\n", copy);
}

// Multi-dimensional arrays and pointers
void multidimensional_array_pointers(void) {
    printf("\n=== Multi-dimensional Arrays and Pointers ===\n");
    
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    // Different ways to access elements
    printf("Different access methods:\n");
    printf("matrix[1][2] = %d\n", matrix[1][2]);
    printf("*(*(matrix + 1) + 2) = %d\n", *(*(matrix + 1) + 2));
    printf("*((int*)matrix + 1*4 + 2) = %d\n", *((int*)matrix + 1*4 + 2));
    
    // Pointer to array vs array of pointers
    int (*ptr_to_array)[4] = matrix;  // Pointer to array of 4 ints
    printf("\nUsing pointer to array:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%d ", ptr_to_array[i][j]);
        }
        printf("\n");
    }
    
    // Array of pointers
    int row0[] = {1, 2, 3, 4};
    int row1[] = {5, 6, 7, 8};
    int row2[] = {9, 10, 11, 12};
    int *array_of_ptrs[] = {row0, row1, row2};
    
    printf("\nUsing array of pointers:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%d ", array_of_ptrs[i][j]);
        }
        printf("\n");
    }
}

// Pointer-based data structures
typedef struct Node {
    int data;
    struct Node *next;
} Node;

Node* create_node(int value) {
    Node *node = malloc(sizeof(Node));
    if (node != NULL) {
        node->data = value;
        node->next = NULL;
    }
    return node;
}

void linked_list_demo(void) {
    printf("\n=== Linked List with Pointers ===\n");
    
    // Create nodes
    Node *head = create_node(10);
    head->next = create_node(20);
    head->next->next = create_node(30);
    head->next->next->next = create_node(40);
    
    // Traverse using pointers
    printf("Linked list contents: ");
    Node *current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
    
    // Count nodes
    int count = 0;
    current = head;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    printf("Number of nodes: %d\n", count);
    
    // Free memory
    current = head;
    while (current != NULL) {
        Node *next = current->next;
        free(current);
        current = next;
    }
    printf("Memory freed\n");
}

// Advanced pointer patterns
void pointer_patterns(void) {
    printf("\n=== Advanced Pointer Patterns ===\n");
    
    // Function returning pointer
    int values[] = {1, 2, 3, 4, 5};
    
    int* find_max(int arr[], size_t size) {
        if (size == 0) return NULL;
        
        int *max_ptr = &arr[0];
        for (size_t i = 1; i < size; i++) {
            if (arr[i] > *max_ptr) {
                max_ptr = &arr[i];
            }
        }
        return max_ptr;
    }
    
    int *max_value = find_max(values, 5);
    if (max_value != NULL) {
        printf("Maximum value: %d at index %ld\n", 
               *max_value, max_value - values);
    }
    
    // Pointer to function returning pointer
    int* (*func_ptr)(int[], size_t) = find_max;
    int *result = func_ptr(values, 5);
    printf("Using function pointer: max = %d\n", *result);
    
    // Array of pointers to functions
    int sum_func(int a, int b) { return a + b; }
    int diff_func(int a, int b) { return a - b; }
    
    int (*math_funcs[])(int, int) = {sum_func, diff_func};
    const char *func_names[] = {"sum", "difference"};
    
    for (size_t i = 0; i < 2; i++) {
        printf("%s(10, 3) = %d\n", func_names[i], math_funcs[i](10, 3));
    }
}

int main(void) {
    array_pointer_relationship();
    pointer_arithmetic_demo();
    string_pointer_operations();
    multidimensional_array_pointers();
    linked_list_demo();
    pointer_patterns();
    
    printf("\n=== Pointer Arithmetic Rules ===\n");
    printf("1. ptr + n: Move n elements forward\n");
    printf("2. ptr - n: Move n elements backward\n");
    printf("3. ptr1 - ptr2: Number of elements between pointers\n");
    printf("4. Comparison operators work with pointers to same array\n");
    printf("5. Only addition/subtraction of integers allowed\n");
    printf("6. No multiplication or division of pointers\n");
    
    return 0;
}
```

### 11. Arrays and Multidimensional Data {#arrays}

Arrays are fundamental data structures in C, providing efficient storage and access to collections of elements.

#### Array Declaration and Initialization

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void array_basics(void) {
    printf("=== Array Declaration and Initialization ===\n");
    
    // Different ways to declare and initialize arrays
    int numbers1[5];  // Uninitialized array
    int numbers2[5] = {1, 2, 3, 4, 5};  // Full initialization
    int numbers3[5] = {1, 2};  // Partial initialization (rest are 0)
    int numbers4[] = {1, 2, 3, 4, 5, 6};  // Size inferred from initializer
    int numbers5[5] = {0};  // All elements initialized to 0
    
    printf("numbers1 (uninitialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers1[i]);  // May contain garbage values
    }
    printf("\n");
    
    printf("numbers2 (full init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers2[i]);
    }
    printf("\n");
    
    printf("numbers3 (partial init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers3[i]);
    }
    printf("\n");
    
    printf("numbers4 (inferred size): ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", numbers4[i]);
    }
    printf("\n");
    
    printf("numbers5 (zero init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers5[i]);
    }
    printf("\n");
    
    // Character arrays (strings)
    char string1[] = "Hello";  // Size is 6 (including '\0')
    char string2[10] = "World";  // Remaining chars are '\0'
    char string3[] = {'H', 'e', 'l', 'l', 'o', '\0'};  // Explicit
    
    printf("string1: '%s' (length: %zu, size: %zu)\n", 
           string1, strlen(string1), sizeof(string1));
    printf("string2: '%s' (length: %zu, size: %zu)\n", 
           string2, strlen(string2), sizeof(string2));
    printf("string3: '%s' (length: %zu, size: %zu)\n", 
           string3, strlen(string3), sizeof(string3));
    
    // Designated initializers (C99)
    int sparse[10] = {[0] = 1, [4] = 5, [9] = 10};
    printf("sparse array: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", sparse[i]);
    }
    printf("\n");
}

// Array operations and utilities
void array_operations(void) {
    printf("\n=== Array Operations ===\n");
    
    int numbers[] = {64, 34, 25, 12, 22, 11, 90, 88, 76, 50, 42};
    size_t size = sizeof(numbers) / sizeof(numbers[0]);
    
    printf("Original array: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Find minimum and maximum
    int min = numbers[0], max = numbers[0];
    size_t min_idx = 0, max_idx = 0;
    
    for (size_t i = 1; i < size; i++) {
        if (numbers[i] < min) {
            min = numbers[i];
            min_idx = i;
        }
        if (numbers[i] > max) {
            max = numbers[i];
            max_idx = i;
        }
    }
    
    printf("Minimum: %d at index %zu\n", min, min_idx);
    printf("Maximum: %d at index %zu\n", max, max_idx);
    
    // Calculate sum and average
    long sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += numbers[i];
    }
    
    double average = (double)sum / size;
    printf("Sum: %ld, Average: %.2f\n", sum, average);
    
    // Search for element (linear search)
    int target = 22;
    int found_idx = -1;
    
    for (size_t i = 0; i < size; i++) {
        if (numbers[i] == target) {
            found_idx = i;
            break;
        }
    }
    
    if (found_idx != -1) {
        printf("Found %d at index %d\n", target, found_idx);
    } else {
        printf("%d not found in array\n", target);
    }
    
    // Reverse array
    int reversed[size];
    for (size_t i = 0; i < size; i++) {
        reversed[i] = numbers[size - 1 - i];
    }
    
    printf("Reversed array: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", reversed[i]);
    }
    printf("\n");
}

// Array copying and comparison
void array_copy_compare(void) {
    printf("\n=== Array Copying and Comparison ===\n");
    
    int source[] = {1, 2, 3, 4, 5};
    int destination[5];
    size_t size = sizeof(source) / sizeof(source[0]);
    
    // Copy array manually
    printf("Manual copy:\n");
    for (size_t i = 0; i < size; i++) {
        destination[i] = source[i];
    }
    
    printf("Source: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", source[i]);
    }
    printf("\n");
    
    printf("Destination: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", destination[i]);
    }
    printf("\n");
    
    // Copy using memcpy
    int dest_memcpy[5];
    memcpy(dest_memcpy, source, sizeof(source));
    
    printf("Copied with memcpy: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", dest_memcpy[i]);
    }
    printf("\n");
    
    // Array comparison
    int array1[] = {1, 2, 3, 4, 5};
    int array2[] = {1, 2, 3, 4, 5};
    int array3[] = {1, 2, 3, 4, 6};
    
    // Manual comparison
    int arrays_equal = 1;
    for (size_t i = 0; i < size; i++) {
        if (array1[i] != array2[i]) {
            arrays_equal = 0;
            break;
        }
    }
    
    printf("array1 == array2: %s\n", arrays_equal ? "true" : "false");
    
    // Using memcmp
    int cmp_result = memcmp(array1, array3, sizeof(array1));
    printf("memcmp(array1, array3): %d\n", cmp_result);
    printf("array1 %s array3\n", 
           cmp_result == 0 ? "equals" : (cmp_result < 0 ? "is less than" : "is greater than"));
}

// String arrays and manipulation
void string_arrays(void) {
    printf("\n=== String Arrays ===\n");
    
    // Array of strings (array of pointers)
    const char *fruits[] = {
        "apple", "banana", "cherry", "date", "elderberry"
    };
    
    size_t num_fruits = sizeof(fruits) / sizeof(fruits[0]);
    
    printf("Fruits array:\n");
    for (size_t i = 0; i < num_fruits; i++) {
        printf("%zu: %s\n", i, fruits[i]);
    }
    
    // 2D character array
    char colors[][10] = {"red", "green", "blue", "yellow", "purple"};
    size_t num_colors = sizeof(colors) / sizeof(colors[0]);
    
    printf("\nColors array:\n");
    for (size_t i = 0; i < num_colors; i++) {
        printf("%zu: %s (length: %zu)\n", i, colors[i], strlen(colors[i]));
    }
    
    // String manipulation in array
    char sentences[][50] = {
        "The quick brown fox",
        "jumps over the lazy dog",
        "Pack my box with",
        "five dozen liquor jugs"
    };
    
    printf("\nOriginal sentences:\n");
    for (size_t i = 0; i < 4; i++) {
        printf("%s\n", sentences[i]);
    }
    
    // Convert to uppercase
    printf("\nConverted to uppercase:\n");
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; sentences[i][j] != '\0'; j++) {
            sentences[i][j] = toupper(sentences[i][j]);
        }
        printf("%s\n", sentences[i]);
    }
}

// Multidimensional arrays
void multidimensional_arrays(void) {
    printf("\n=== Multidimensional Arrays ===\n");
    
    // 2D array (matrix)
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    printf("3x4 Matrix:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // Matrix operations
    printf("\nMatrix transpose (4x3):\n");
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 3; i++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // 3D array
    int cube[2][3][4];
    int value = 1;
    
    // Initialize 3D array
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                cube[i][j][k] = value++;
            }
        }
    }
    
    printf("\n3D Array (2x3x4):\n");
    for (int i = 0; i < 2; i++) {
        printf("Layer %d:\n", i);
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                printf("%3d ", cube[i][j][k]);
            }
            printf("\n");
        }
        printf("\n");
    }
}

// Dynamic arrays (variable length arrays - C99)
void variable_length_arrays(void) {
    printf("\n=== Variable Length Arrays (C99) ===\n");
    
    int rows = 3, cols = 4;
    
    // VLA declaration
    int vla_matrix[rows][cols];
    
    // Initialize VLA
    int counter = 1;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            vla_matrix[i][j] = counter++;
        }
    }
    
    printf("Variable Length Array (%dx%d):\n", rows, cols);
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%3d ", vla_matrix[i][j]);
        }
        printf("\n");
    }
    
    // Function with VLA parameter
    void print_matrix(int r, int c, int mat[r][c]) {
        printf("Matrix printed by function:\n");
        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                printf("%3d ", mat[i][j]);
            }
            printf("\n");
        }
    }
    
    print_matrix(rows, cols, vla_matrix);
}

// Real-world example: Grade management system
typedef struct {
    char name[50];
    float grades[5];  // 5 subjects
    float average;
} Student;

void grade_management_demo(void) {
    printf("\n=== Grade Management System ===\n");
    
    const char *subjects[] = {"Math", "English", "Science", "History", "Art"};
    const int num_subjects = 5;
    
    Student students[] = {
        {"Alice Johnson", {85.5, 92.0, 88.5, 90.0, 87.5}, 0},
        {"Bob Smith", {78.0, 85.5, 82.0, 79.5, 88.0}, 0},
        {"Carol Davis", {95.0, 91.5, 96.0, 93.5, 89.0}, 0},
        {"David Wilson", {82.5, 78.0, 85.0, 87.5, 84.0}, 0}
    };
    
    int num_students = sizeof(students) / sizeof(students[0]);
    
    // Calculate averages
    for (int i = 0; i < num_students; i++) {
        float sum = 0;
        for (int j = 0; j < num_subjects; j++) {
            sum += students[i].grades[j];
        }
        students[i].average = sum / num_subjects;
    }
    
    // Display student grades
    printf("Student Grade Report:\n");
    printf("%-15s", "Name");
    for (int j = 0; j < num_subjects; j++) {
        printf("%-10s", subjects[j]);
    }
    printf("%-10s\n", "Average");
    
    printf("%-15s", "---------------");
    for (int j = 0; j < num_subjects; j++) {
        printf("%-10s", "--------");
    }
    printf("%-10s\n", "--------");
    
    for (int i = 0; i < num_students; i++) {
        printf("%-15s", students[i].name);
        for (int j = 0; j < num_subjects; j++) {
            printf("%-10.1f", students[i].grades[j]);
        }
        printf("%-10.1f\n", students[i].average);
    }
    
    // Calculate subject averages
    printf("\nSubject Averages:\n");
    for (int j = 0; j < num_subjects; j++) {
        float subject_sum = 0;
        for (int i = 0; i < num_students; i++) {
            subject_sum += students[i].grades[j];
        }
        printf("%-10s: %.1f\n", subjects[j], subject_sum / num_students);
    }
    
    // Find best student
    int best_student_idx = 0;
    for (int i = 1; i < num_students; i++) {
        if (students[i].average > students[best_student_idx].average) {
            best_student_idx = i;
        }
    }
    
    printf("\nBest performing student: %s (Average: %.1f)\n",
           students[best_student_idx].name, students[best_student_idx].average);
}

// Array sorting algorithms
void bubble_sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

void selection_sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        int min_idx = i;
        for (int j = i + 1; j < n; j++) {
            if (arr[j] < arr[min_idx]) {
                min_idx = j;
            }
        }
        if (min_idx != i) {
            int temp = arr[i];
            arr[i] = arr[min_idx];
            arr[min_idx] = temp;
        }
    }
}

void insertion_sort(int arr[], int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j = i - 1;
        
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j = j - 1;
        }
        arr[j + 1] = key;
    }
}

void sorting_algorithms_demo(void) {
    printf("\n=== Array Sorting Algorithms ===\n");
    
    int original[] = {64, 34, 25, 12, 22, 11, 90, 88, 76, 50, 42};
    int size = sizeof(original) / sizeof(original[0]);
    
    printf("Original array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", original[i]);
    }
    printf("\n");
    
    // Test different sorting algorithms
    int bubble_array[size], selection_array[size], insertion_array[size];
    
    // Copy original array for each sorting method
    memcpy(bubble_array, original, sizeof(original));
    memcpy(selection_array, original, sizeof(original));
    memcpy(insertion_array, original, sizeof(original));
    
    // Bubble sort
    bubble_sort(bubble_array, size);
    printf("Bubble sort:    ");
    for (int i = 0; i < size; i++) {
        printf("%d ", bubble_array[i]);
    }
    printf("\n");
    
    // Selection sort
    selection_sort(selection_array, size);
    printf("Selection sort: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", selection_array[i]);
    }
    printf("\n");
    
    // Insertion sort
    insertion_sort(insertion_array, size);
    printf("Insertion sort: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", insertion_array[i]);
    }
    printf("\n");
}

// Binary search (requires sorted array)
int binary_search(int arr[], int size, int target) {
    int left = 0, right = size - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (arr[mid] == target) {
            return mid;
        } else if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    return -1;  // Not found
}

void search_algorithms_demo(void) {
    printf("\n=== Array Search Algorithms ===\n");
    
    int sorted_array[] = {2, 5, 8, 12, 16, 23, 38, 45, 56, 67, 78};
    int size = sizeof(sorted_array) / sizeof(sorted_array[0]);
    
    printf("Sorted array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", sorted_array[i]);
    }
    printf("\n");
    
    int targets[] = {23, 67, 15, 2, 100};
    int num_targets = sizeof(targets) / sizeof(targets[0]);
    
    for (int i = 0; i < num_targets; i++) {
        int result = binary_search(sorted_array, size, targets[i]);
        if (result != -1) {
            printf("Found %d at index %d\n", targets[i], result);
        } else {
            printf("%d not found in array\n", targets[i]);
        }
    }
}

int main(void) {
    array_basics();
    array_operations();
    array_copy_compare();
    string_arrays();
    multidimensional_arrays();
    
    // VLA demo (C99 feature)
#if __STDC_VERSION__ >= 199901L
    variable_length_arrays();
#else
    printf("\nVariable Length Arrays require C99 or later\n");
#endif
    
    grade_management_demo();
    sorting_algorithms_demo();
    search_algorithms_demo();
    
    printf("\n=== Array Best Practices ===\n");
    printf("1. Always initialize arrays before use\n");
    printf("2. Use sizeof() to calculate array size\n");
    printf("3. Be careful with array bounds (no automatic checking)\n");
    printf("4. Consider using const for read-only arrays\n");
    printf("5. Use meaningful names for array indices\n");
    printf("6. Prefer standard library functions (memcpy, memcmp) when possible\n");
    printf("7. Consider using VLAs for runtime-sized arrays (C99+)\n");
    
    return 0;
}
```

### 12. Dynamic Memory Allocation {#dynamic-memory}

Dynamic memory allocation allows programs to request memory at runtime, enabling flexible data structures and efficient memory usage.

#### malloc, calloc, realloc, and free

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void basic_malloc_demo(void) {
    printf("=== Basic malloc() Demo ===\n");
    
    // Allocate memory for 5 integers
    int *numbers = malloc(5 * sizeof(int));
    
    if (numbers == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    printf("Memory allocated successfully\n");
    
    // Initialize the allocated memory
    for (int i = 0; i < 5; i++) {
        numbers[i] = (i + 1) * 10;
    }
    
    printf("Allocated array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Always free allocated memory
    free(numbers);
    numbers = NULL;  // Good practice to avoid dangling pointer
    printf("Memory freed\n");
}

void calloc_vs_malloc_demo(void) {
    printf("\n=== calloc() vs malloc() Demo ===\n");
    
    // malloc - memory contains garbage values
    int *malloc_array = malloc(5 * sizeof(int));
    if (malloc_array == NULL) {
        printf("malloc failed\n");
        return;
    }
    
    printf("malloc array (uninitialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", malloc_array[i]);
    }
    printf("\n");
    
    // calloc - memory is zero-initialized
    int *calloc_array = calloc(5, sizeof(int));
    if (calloc_array == NULL) {
        printf("calloc failed\n");
        free(malloc_array);
        return;
    }
    
    printf("calloc array (zero-initialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", calloc_array[i]);
    }
    printf("\n");
    
    // Performance comparison
    printf("\nPerformance note: calloc is slightly slower due to initialization\n");
    printf("Use malloc when you'll immediately initialize all elements\n");
    printf("Use calloc when you want zero-initialized memory\n");
    
    free(malloc_array);
    free(calloc_array);
}

void realloc_demo(void) {
    printf("\n=== realloc() Demo ===\n");
    
    // Start with small array
    int *array = malloc(3 * sizeof(int));
    if (array == NULL) {
        printf("Initial allocation failed\n");
        return;
    }
    
    // Initialize
    for (int i = 0; i < 3; i++) {
        array[i] = i + 1;
    }
    
    printf("Initial array (size 3): ");
    for (int i = 0; i < 3; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // Expand the array
    int *temp = realloc(array, 6 * sizeof(int));
    if (temp == NULL) {
        printf("Reallocation failed\n");
        free(array);
        return;
    }
    
    array = temp;  // Update pointer
    
    // Initialize new elements
    for (int i = 3; i < 6; i++) {
        array[i] = i + 1;
    }
    
    printf("Expanded array (size 6): ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // Shrink the array
    temp = realloc(array, 4 * sizeof(int));
    if (temp == NULL) {
        printf("Reallocation failed\n");
        free(array);
        return;
    }
    
    array = temp;
    
    printf("Shrunk array (size 4): ");
    for (int i = 0; i < 4; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // realloc with size 0 is equivalent to free
    array = realloc(array, 0);  // array becomes NULL
    printf("Array freed using realloc(ptr, 0)\n");
}

// Dynamic string handling
void dynamic_string_demo(void) {
    printf("\n=== Dynamic String Handling ===\n");
    
    // Allocate memory for a string
    char *message = malloc(20);
    if (message == NULL) {
        printf("String allocation failed\n");
        return;
    }
    
    strcpy(message, "Hello");
    printf("Initial string: '%s'\n", message);
    
    // Expand to accommodate more text
    message = realloc(message, 50);
    if (message == NULL) {
        printf("String reallocation failed\n");
        return;
    }
    
    strcat(message, ", World!");
    printf("Expanded string: '%s'\n", message);
    
    // Create a copy
    size_t len = strlen(message);
    char *copy = malloc(len + 1);
    if (copy != NULL) {
        strcpy(copy, message);
        printf("Copy: '%s'\n", copy);
        free(copy);
    }
    
    free(message);
}

// Error handling in memory allocation
void allocation_error_handling(void) {
    printf("\n=== Memory Allocation Error Handling ===\n");
    
    // Try to allocate a very large amount of memory
    size_t huge_size = SIZE_MAX;
    void *huge_ptr = malloc(huge_size);
    
    if (huge_ptr == NULL) {
        printf("Large allocation failed (as expected)\n");
        printf("errno: %d (%s)\n", errno, strerror(errno));
    } else {
        printf("Unexpected: Large allocation succeeded\n");
        free(huge_ptr);
    }
    
    // Proper error handling pattern
    int *safe_array = malloc(100 * sizeof(int));
    if (safe_array == NULL) {
        fprintf(stderr, "Error: Cannot allocate memory for array\n");
        return;
    }
    
    printf("Safe allocation succeeded\n");
    
    // Use the memory
    for (int i = 0; i < 100; i++) {
        safe_array[i] = i * i;
    }
    
    printf("First 10 squares: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", safe_array[i]);
    }
    printf("\n");
    
    free(safe_array);
}

// Real-world example: Dynamic array with growth
typedef struct {
    int *data;
    size_t size;
    size_t capacity;
} DynamicArray;

DynamicArray* create_array(void) {
    DynamicArray *arr = malloc(sizeof(DynamicArray));
    if (arr == NULL) return NULL;
    
    arr->data = malloc(4 * sizeof(int));  // Initial capacity of 4
    if (arr->data == NULL) {
        free(arr);
        return NULL;
    }
    
    arr->size = 0;
    arr->capacity = 4;
    return arr;
}

int append_array(DynamicArray *arr, int value) {
    if (arr == NULL) return 0;
    
    // Check if we need to grow the array
    if (arr->size >= arr->capacity) {
        size_t new_capacity = arr->capacity * 2;
        int *new_data = realloc(arr->data, new_capacity * sizeof(int));
        if (new_data == NULL) {
            return 0;  // Allocation failed
        }
        
        arr->data = new_data;
        arr->capacity = new_capacity;
        printf("Array grown to capacity %zu\n", new_capacity);
    }
    
    arr->data[arr->size++] = value;
    return 1;  // Success
}

void print_array(const DynamicArray *arr) {
    if (arr == NULL) return;
    
    printf("Array (size: %zu, capacity: %zu): ", arr->size, arr->capacity);
    for (size_t i = 0; i < arr->size; i++) {
        printf("%d ", arr->data[i]);
    }
    printf("\n");
}

void destroy_array(DynamicArray *arr) {
    if (arr != NULL) {
        free(arr->data);
        free(arr);
    }
}

void dynamic_array_demo(void) {
    printf("\n=== Dynamic Array Demo ===\n");
    
    DynamicArray *arr = create_array();
    if (arr == NULL) {
        printf("Failed to create dynamic array\n");
        return;
    }
    
    printf("Created dynamic array\n");
    print_array(arr);
    
    // Add elements to trigger growth
    for (int i = 1; i <= 10; i++) {
        if (append_array(arr, i * 10)) {
            printf("Added %d\n", i * 10);
            print_array(arr);
        } else {
            printf("Failed to add %d\n", i * 10);
            break;
        }
    }
    
    destroy_array(arr);
    printf("Dynamic array destroyed\n");
}

// Memory leak detection and prevention
void demonstrate_memory_leaks(void) {
    printf("\n=== Memory Leak Prevention ===\n");
    
    // Example of potential memory leak
    void memory_leak_example(void) {
        int *ptr = malloc(100 * sizeof(int));
        if (ptr == NULL) return;
        
        // ... use ptr ...
        
        // Oops! Forgot to call free(ptr) - MEMORY LEAK!
        return;  // Memory is lost
    }
    
    // Correct version
    void correct_memory_usage(void) {
        int *ptr = malloc(100 * sizeof(int));
        if (ptr == NULL) return;
        
        // ... use ptr ...
        
        free(ptr);  // Always free allocated memory
        ptr = NULL; // Prevent accidental reuse
    }
    
    printf("Always pair malloc/calloc with free\n");
    printf("Set pointers to NULL after freeing\n");
    printf("Use tools like Valgrind to detect leaks\n");
    
    // Example with proper cleanup
    char *buffer1 = malloc(256);
    char *buffer2 = malloc(512);
    
    if (buffer1 == NULL || buffer2 == NULL) {
        printf("Allocation failed\n");
        free(buffer1);  // Safe to call on NULL
        free(buffer2);
        return;
    }
    
    // Use buffers
    strcpy(buffer1, "Buffer 1 content");
    strcpy(buffer2, "Buffer 2 has more content than buffer 1");
    
    printf("Buffer 1: %s\n", buffer1);
    printf("Buffer 2: %s\n", buffer2);
    
    // Cleanup
    free(buffer1);
    free(buffer2);
    buffer1 = buffer2 = NULL;
    
    printf("Buffers properly freed\n");
}

// Advanced: Memory pools for frequent allocations
typedef struct MemoryBlock {
    void *data;
    size_t size;
    int in_use;
    struct MemoryBlock *next;
} MemoryBlock;

typedef struct {
    MemoryBlock *blocks;
    size_t block_size;
    size_t num_blocks;
    size_t blocks_in_use;
} MemoryPool;

MemoryPool* create_memory_pool(size_t block_size, size_t num_blocks) {
    MemoryPool *pool = malloc(sizeof(MemoryPool));
    if (pool == NULL) return NULL;
    
    pool->block_size = block_size;
    pool->num_blocks = num_blocks;
    pool->blocks_in_use = 0;
    pool->blocks = NULL;
    
    // Create linked list of blocks
    for (size_t i = 0; i < num_blocks; i++) {
        MemoryBlock *block = malloc(sizeof(MemoryBlock));
        if (block == NULL) {
            // Cleanup on failure
            // ... cleanup code ...
            return NULL;
        }
        
        block->data = malloc(block_size);
        if (block->data == NULL) {
            free(block);
            // ... cleanup code ...
            return NULL;
        }
        
        block->size = block_size;
        block->in_use = 0;
        block->next = pool->blocks;
        pool->blocks = block;
    }
    
    return pool;
}

void* pool_allocate(MemoryPool *pool) {
    if (pool == NULL) return NULL;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (!current->in_use) {
            current->in_use = 1;
            pool->blocks_in_use++;
            return current->data;
        }
        current = current->next;
    }
    
    return NULL;  // No available blocks
}

void pool_deallocate(MemoryPool *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) return;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (current->data == ptr && current->in_use) {
            current->in_use = 0;
            pool->blocks_in_use--;
            return;
        }
        current = current->next;
    }
}

void destroy_memory_pool(MemoryPool *pool) {
    if (pool == NULL) return;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        MemoryBlock *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
    
    free(pool);
}

void memory_pool_demo(void) {
    printf("\n=== Memory Pool Demo ===\n");
    
    MemoryPool *pool = create_memory_pool(256, 5);
    if (pool == NULL) {
        printf("Failed to create memory pool\n");
        return;
    }
    
    printf("Created memory pool: 5 blocks of 256 bytes each\n");
    
    // Allocate some blocks
    void *ptr1 = pool_allocate(pool);
    void *ptr2 = pool_allocate(pool);
    void *ptr3 = pool_allocate(pool);
    
    if (ptr1 && ptr2 && ptr3) {
        printf("Allocated 3 blocks from pool (in use: %zu/%zu)\n", 
               pool->blocks_in_use, pool->num_blocks);
        
        // Use the memory
        strcpy((char*)ptr1, "Block 1 data");
        strcpy((char*)ptr2, "Block 2 data");
        strcpy((char*)ptr3, "Block 3 data");
        
        printf("Block contents: '%s', '%s', '%s'\n", 
               (char*)ptr1, (char*)ptr2, (char*)ptr3);
    }
    
    // Deallocate middle block
    pool_deallocate(pool, ptr2);
    printf("Deallocated block 2 (in use: %zu/%zu)\n", 
           pool->blocks_in_use, pool->num_blocks);
    
    // Allocate again (should reuse the freed block)
    void *ptr4 = pool_allocate(pool);
    if (ptr4) {
        strcpy((char*)ptr4, "Block 4 data (reused)");
        printf("Allocated new block: '%s' (in use: %zu/%zu)\n", 
               (char*)ptr4, pool->blocks_in_use, pool->num_blocks);
    }
    
    destroy_memory_pool(pool);
    printf("Memory pool destroyed\n");
}

int main(void) {
    basic_malloc_demo();
    calloc_vs_malloc_demo();
    realloc_demo();
    dynamic_string_demo();
    allocation_error_handling();
    dynamic_array_demo();
    demonstrate_memory_leaks();
    memory_pool_demo();
    
    printf("\n=== Dynamic Memory Best Practices ===\n");
    printf("1. Always check for NULL return from malloc/calloc/realloc\n");
    printf("2. Free every allocated block exactly once\n");
    printf("3. Set pointers to NULL after freeing\n");
    printf("4. Use calloc when you need zero-initialized memory\n");
    printf("5. Be careful when using realloc (it may move memory)\n");
    printf("6. Consider memory pools for frequent allocations\n");
    printf("7. Use static analysis tools to detect memory issues\n");
    printf("8. Match every malloc with exactly one free\n");
    
    return 0;
}
```

### 13. Structures, Unions, and Enumerations {#structures-unions}

These user-defined data types allow you to create complex data structures and organize related data efficiently.

#### Structure Definition and Usage

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Basic structure definition
struct Point {
    double x;
    double y;
};

// Structure with different data types
struct Person {
    char name[50];
    int age;
    double height;
    char gender;
};

// Typedef for convenience
typedef struct {
    int day;
    int month;
    int year;
} Date;

// Self-referencing structure (for linked lists, trees, etc.)
typedef struct Employee {
    int id;
    char name[100];
    double salary;
    Date hire_date;
    struct Employee *manager;  // Self-reference
} Employee;

void basic_structures_demo(void) {
    printf("=== Basic Structures Demo ===\n");
    
    // Structure initialization methods
    struct Point p1 = {3.0, 4.0};              // Positional initialization
    struct Point p2 = {.x = 1.0, .y = 2.0};    // Designated initialization (C99)
    struct Point p3;                            // Uninitialized
    
    // Initialize p3
    p3.x = 5.0;
    p3.y = 12.0;
    
    printf("Point p1: (%.1f, %.1f)\n", p1.x, p1.y);
    printf("Point p2: (%.1f, %.1f)\n", p2.x, p2.y);
    printf("Point p3: (%.1f, %.1f)\n", p3.x, p3.y);
    
    // Calculate distance between points
    double distance = sqrt((p3.x - p1.x) * (p3.x - p1.x) + 
                          (p3.y - p1.y) * (p3.y - p1.y));
    printf("Distance between p1 and p3: %.2f\n", distance);
    
    // Person structure example
    struct Person person1 = {
        .name = "John Doe",
        .age = 30,
        .height = 5.9,
        .gender = 'M'
    };
    
    printf("\nPerson Information:\n");
    printf("Name: %s\n", person1.name);
    printf("Age: %d\n", person1.age);
    printf("Height: %.1f feet\n", person1.height);
    printf("Gender: %c\n", person1.gender);
    
    // Date structure with typedef
    Date today = {1, 9, 2025};  // September 1, 2025
    printf("\nToday's date: %02d/%02d/%04d\n", 
           today.day, today.month, today.year);
}

// Structure operations and functions
double calculate_distance(struct Point p1, struct Point p2) {
    double dx = p2.x - p1.x;
    double dy = p2.y - p1.y;
    return sqrt(dx * dx + dy * dy);
}

struct Point midpoint(struct Point p1, struct Point p2) {
    struct Point mid;
    mid.x = (p1.x + p2.x) / 2.0;
    mid.y = (p1.y + p2.y) / 2.0;
    return mid;
}

void print_point(const struct Point *p) {
    printf("Point: (%.2f, %.2f)\n", p->x, p->y);
}

void move_point(struct Point *p, double dx, double dy) {
    p->x += dx;
    p->y += dy;
}

void structure_functions_demo(void) {
    printf("\n=== Structure Functions Demo ===\n");
    
    struct Point a = {0.0, 0.0};
    struct Point b = {3.0, 4.0};
    
    printf("Initial points:\n");
    print_point(&a);
    print_point(&b);
    
    double dist = calculate_distance(a, b);
    printf("Distance: %.2f\n", dist);
    
    struct Point mid = midpoint(a, b);
    printf("Midpoint: ");
    print_point(&mid);
    
    // Modify point using pointer
    move_point(&a, 1.0, 1.0);
    printf("After moving point a by (1,1): ");
    print_point(&a);
}

// Nested structures
typedef struct {
    char street[100];
    char city[50];
    char state[20];
    char zip_code[10];
} Address;

typedef struct {
    char first_name[50];
    char last_name[50];
    int age;
    Address address;        // Nested structure
    char phone[15];
    char email[100];
} Contact;

void nested_structures_demo(void) {
    printf("\n=== Nested Structures Demo ===\n");
    
    Contact person = {
        .first_name = "Alice",
        .last_name = "Johnson",
        .age = 28,
        .address = {
            .street = "123 Main St",
            .city = "Springfield",
            .state = "IL",
            .zip_code = "62701"
        },
        .phone = "555-1234",
        .email = "alice.johnson@email.com"
    };
    
    printf("Contact Information:\n");
    printf("Name: %s %s\n", person.first_name, person.last_name);
    printf("Age: %d\n", person.age);
    printf("Address: %s\n", person.address.street);
    printf("         %s, %s %s\n", 
           person.address.city, person.address.state, person.address.zip_code);
    printf("Phone: %s\n", person.phone);
    printf("Email: %s\n", person.email);
}

// Arrays of structures
void structure_arrays_demo(void) {
    printf("\n=== Structure Arrays Demo ===\n");
    
    Employee employees[] = {
        {1, "John Smith", 75000.0, {15, 3, 2020}, NULL},
        {2, "Jane Doe", 82000.0, {22, 7, 2019}, NULL},
        {3, "Bob Wilson", 68000.0, {10, 11, 2021}, NULL},
        {4, "Carol Davis", 95000.0, {5, 1, 2018}, NULL},
        {5, "David Brown", 71000.0, {18, 9, 2020}, NULL}
    };
    
    int num_employees = sizeof(employees) / sizeof(employees[0]);
    
    // Set manager relationships
    employees[1].manager = &employees[3];  // Jane reports to Carol
    employees[2].manager = &employees[3];  // Bob reports to Carol
    employees[4].manager = &employees[1];  // David reports to Jane
    
    printf("Employee Database:\n");
    printf("%-3s %-15s %-10s %-12s %-15s\n", 
           "ID", "Name", "Salary", "Hire Date", "Manager");
    printf("%-3s %-15s %-10s %-12s %-15s\n", 
           "---", "---------------", "----------", "------------", "---------------");
    
    for (int i = 0; i < num_employees; i++) {
        printf("%-3d %-15s $%-9.0f %02d/%02d/%04d   %-15s\n",
               employees[i].id,
               employees[i].name,
               employees[i].salary,
               employees[i].hire_date.day,
               employees[i].hire_date.month,
               employees[i].hire_date.year,
               employees[i].manager ? employees[i].manager->name : "None");
    }
    
    // Calculate average salary
    double total_salary = 0;
    for (int i = 0; i < num_employees; i++) {
        total_salary += employees[i].salary;
    }
    
    printf("\nAverage salary: $%.2f\n", total_salary / num_employees);
    
    // Find highest paid employee
    Employee *highest_paid = &employees[0];
    for (int i = 1; i < num_employees; i++) {
        if (employees[i].salary > highest_paid->salary) {
            highest_paid = &employees[i];
        }
    }
    
    printf("Highest paid: %s ($%.0f)\n", 
           highest_paid->name, highest_paid->salary);
}

// Dynamic structures
typedef struct Node {
    int data;
    struct Node *next;
} Node;

typedef struct {
    Node *head;
    Node *tail;
    size_t size;
} LinkedList;

LinkedList* create_list(void) {
    LinkedList *list = malloc(sizeof(LinkedList));
    if (list != NULL) {
        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
    }
    return list;
}

void append_to_list(LinkedList *list, int value) {
    if (list == NULL) return;
    
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) return;
    
    new_node->data = value;
    new_node->next = NULL;
    
    if (list->head == NULL) {
        list->head = new_node;
        list->tail = new_node;
    } else {
        list->tail->next = new_node;
        list->tail = new_node;
    }
    
    list->size++;
}

void print_list(const LinkedList *list) {
    if (list == NULL || list->head == NULL) {
        printf("Empty list\n");
        return;
    }
    
    printf("List (size %zu): ", list->size);
    Node *current = list->head;
    while (current != NULL) {
        printf("%d", current->data);
        if (current->next != NULL) printf(" -> ");
        current = current->next;
    }
    printf(" -> NULL\n");
}

void destroy_list(LinkedList *list) {
    if (list == NULL) return;
    
    Node *current = list->head;
    while (current != NULL) {
        Node *next = current->next;
        free(current);
        current = next;
    }
    
    free(list);
}

void dynamic_structures_demo(void) {
    printf("\n=== Dynamic Structures Demo ===\n");
    
    LinkedList *list = create_list();
    if (list == NULL) {
        printf("Failed to create list\n");
        return;
    }
    
    printf("Created empty linked list\n");
    print_list(list);
    
    // Add elements
    for (int i = 1; i <= 5; i++) {
        append_to_list(list, i * 10);
        printf("Added %d: ", i * 10);
        print_list(list);
    }
    
    destroy_list(list);
    printf("List destroyed\n");
}

// Structure padding and alignment
void structure_memory_layout(void) {
    printf("\n=== Structure Memory Layout ===\n");
    
    typedef struct {
        char a;      // 1 byte
        int b;       // 4 bytes
        char c;      // 1 byte
        double d;    // 8 bytes
    } UnalignedStruct;
    
    typedef struct {
        double d;    // 8 bytes
        int b;       // 4 bytes
        char a;      // 1 byte
        char c;      // 1 byte
    } AlignedStruct;
    
    printf("Unaligned structure:\n");
    printf("  sizeof(UnalignedStruct): %zu bytes\n", sizeof(UnalignedStruct));
    printf("  Expected without padding: %zu bytes\n", 
           sizeof(char) + sizeof(int) + sizeof(char) + sizeof(double));
    
    printf("\nAligned structure:\n");
    printf("  sizeof(AlignedStruct): %zu bytes\n", sizeof(AlignedStruct));
    
    // Show member offsets
    UnalignedStruct unaligned;
    printf("\nUnaligned structure member offsets:\n");
    printf("  a: %zu\n", (char*)&unaligned.a - (char*)&unaligned);
    printf("  b: %zu\n", (char*)&unaligned.b - (char*)&unaligned);
    printf("  c: %zu\n", (char*)&unaligned.c - (char*)&unaligned);
    printf("  d: %zu\n", (char*)&unaligned.d - (char*)&unaligned);
    
    // Packed structure (compiler-specific)
    #ifdef __GNUC__
    typedef struct __attribute__((packed)) {
        char a;
        int b;
        char c;
        double d;
    } PackedStruct;
    
    printf("\nPacked structure (GCC):\n");
    printf("  sizeof(PackedStruct): %zu bytes\n", sizeof(PackedStruct));
    #endif
}

// Unions demonstration
union Data {
    int i;
    float f;
    char c[4];
};

void unions_demo(void) {
    printf("\n=== Unions Demo ===\n");
    
    union Data data;
    
    printf("sizeof(union Data): %zu bytes\n", sizeof(union Data));
    printf("All members share the same memory location\n\n");
    
    // Store integer
    data.i = 0x12345678;
    printf("Stored integer: 0x%X (%d)\n", data.i, data.i);
    printf("As float: %f\n", data.f);
    printf("As char array: [0x%02X, 0x%02X, 0x%02X, 0x%02X]\n",
           (unsigned char)data.c[0], (unsigned char)data.c[1], 
           (unsigned char)data.c[2], (unsigned char)data.c[3]);
    
    // Store float
    data.f = 3.14159f;
    printf("\nStored float: %f\n", data.f);
    printf("As integer: %d (0x%X)\n", data.i, data.i);
    printf("As char array: [0x%02X, 0x%02X, 0x%02X, 0x%02X]\n",
           (unsigned char)data.c[0], (unsigned char)data.c[1], 
           (unsigned char)data.c[2], (unsigned char)data.c[3]);
    
    // Tagged unions (discriminated unions)
    typedef enum {
        TYPE_INT,
        TYPE_FLOAT,
        TYPE_STRING
    } DataType;
    
    typedef struct {
        DataType type;
        union {
            int i;
            float f;
            char s[20];
        } value;
    } TaggedData;
    
    printf("\n=== Tagged Union Demo ===\n");
    
    TaggedData items[] = {
        {TYPE_INT, .value.i = 42},
        {TYPE_FLOAT, .value.f = 3.14159f},
        {TYPE_STRING, .value.s = "Hello"}
    };
    
    for (int i = 0; i < 3; i++) {
        switch (items[i].type) {
            case TYPE_INT:
                printf("Integer: %d\n", items[i].value.i);
                break;
            case TYPE_FLOAT:
                printf("Float: %.5f\n", items[i].value.f);
                break;
            case TYPE_STRING:
                printf("String: %s\n", items[i].value.s);
                break;
        }
    }
}

// Enumerations
enum Status {
    STATUS_PENDING = 1,    // Explicit value
    STATUS_PROCESSING,     // 2 (auto-increment)
    STATUS_COMPLETED,      // 3
    STATUS_FAILED = -1,    // Explicit negative value
    STATUS_CANCELLED = 100 // Explicit large value
};

typedef enum {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARNING,
    LEVEL_ERROR,
    LEVEL_CRITICAL
} LogLevel;

const char* status_to_string(enum Status status) {
    switch (status) {
        case STATUS_PENDING: return "Pending";
        case STATUS_PROCESSING: return "Processing";
        case STATUS_COMPLETED: return "Completed";
        case STATUS_FAILED: return "Failed";
        case STATUS_CANCELLED: return "Cancelled";
        default: return "Unknown";
    }
}

const char* level_to_string(LogLevel level) {
    static const char* level_names[] = {
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
    };
    
    if (level >= 0 && level <= LEVEL_CRITICAL) {
        return level_names[level];
    }
    return "UNKNOWN";
}

void enumerations_demo(void) {
    printf("\n=== Enumerations Demo ===\n");
    
    // Show enum values
    printf("Status enum values:\n");
    printf("  STATUS_PENDING: %d\n", STATUS_PENDING);
    printf("  STATUS_PROCESSING: %d\n", STATUS_PROCESSING);
    printf("  STATUS_COMPLETED: %d\n", STATUS_COMPLETED);
    printf("  STATUS_FAILED: %d\n", STATUS_FAILED);
    printf("  STATUS_CANCELLED: %d\n", STATUS_CANCELLED);
    
    // Using enums in practice
    enum Status task_status = STATUS_PENDING;
    printf("\nTask status: %s (%d)\n", 
           status_to_string(task_status), task_status);
    
    task_status = STATUS_PROCESSING;
    printf("Updated status: %s (%d)\n", 
           status_to_string(task_status), task_status);
    
    // Log level example
    printf("\nLog levels:\n");
    for (LogLevel level = LEVEL_DEBUG; level <= LEVEL_CRITICAL; level++) {
        printf("  %s: %d\n", level_to_string(level), level);
    }
    
    // Enum in switch statement
    LogLevel current_level = LEVEL_WARNING;
    printf("\nProcessing log level %s:\n", level_to_string(current_level));
    
    switch (current_level) {
        case LEVEL_DEBUG:
        case LEVEL_INFO:
            printf("  Information message\n");
            break;
        case LEVEL_WARNING:
            printf("  Warning: Something might be wrong\n");
            break;
        case LEVEL_ERROR:
        case LEVEL_CRITICAL:
            printf("  Error: Action required!\n");
            break;
    }
}

// Bit fields in structures
struct PackedData {
    unsigned int flag1 : 1;     // 1 bit
    unsigned int flag2 : 1;     // 1 bit
    unsigned int counter : 6;   // 6 bits (0-63)
    unsigned int type : 4;      // 4 bits (0-15)
    unsigned int reserved : 4;  // 4 bits unused
    // Total: 16 bits = 2 bytes
};

void bit_fields_demo(void) {
    printf("\n=== Bit Fields Demo ===\n");
    
    struct PackedData data = {0};
    printf("sizeof(struct PackedData): %zu bytes\n", sizeof(struct PackedData));
    
    // Set bit fields
    data.flag1 = 1;
    data.flag2 = 0;
    data.counter = 42;
    data.type = 7;
    
    printf("flag1: %u\n", data.flag1);
    printf("flag2: %u\n", data.flag2);
    printf("counter: %u\n", data.counter);
    printf("type: %u\n", data.type);
    printf("reserved: %u\n", data.reserved);
    
    // Show raw bytes
    unsigned char *bytes = (unsigned char*)&data;
    printf("Raw bytes: ");
    for (size_t i = 0; i < sizeof(data); i++) {
        printf("0x%02X ", bytes[i]);
    }
    printf("\n");
    
    // Bit field overflow (be careful!)
    data.counter = 70;  // Exceeds 6-bit range (0-63)
    printf("counter after overflow (70 -> %u): %u\n", 70, data.counter);
}

int main(void) {
    basic_structures_demo();
    structure_functions_demo();
    nested_structures_demo();
    structure_arrays_demo();
    dynamic_structures_demo();
    structure_memory_layout();
    unions_demo();
    enumerations_demo();
    bit_fields_demo();
    
    printf("\n=== Structures, Unions, Enums Best Practices ===\n");
    printf("Structures:\n");
    printf("1. Use meaningful names for structure members\n");
    printf("2. Consider memory alignment for performance\n");
    printf("3. Use const for read-only structure parameters\n");
    printf("4. Initialize structures to avoid garbage values\n");
    
    printf("\nUnions:\n");
    printf("1. Use tagged unions to track which member is active\n");
    printf("2. Be careful about endianness when interpreting bytes\n");
    printf("3. Understand that all members share the same memory\n");
    
    printf("\nEnumerations:\n");
    printf("1. Use enums for named constants and state machines\n");
    printf("2. Provide string conversion functions for debugging\n");
    printf("3. Consider using typedef for cleaner code\n");
    printf("4. Handle unknown values in switch statements\n");
    
    return 0;
}
```
FormatStyle: file
```

**clang-format Configuration (.clang-format):**

```yaml
---
Language: Cpp
BasedOnStyle: LLVM

# Indentation
IndentWidth: 4
TabWidth: 4
UseTab: Never
IndentCaseLabels: true

# Line length
ColumnLimit: 100

# Braces
BreakBeforeBraces: Linux
Cpp11BracedListStyle: true

# Spacing
SpaceAfterCStyleCast: true
SpaceBeforeParens: ControlStatements
SpaceInEmptyParentheses: false

# Alignment
AlignConsecutiveAssignments: false
AlignConsecutiveDeclarations: false
AlignOperands: true
AlignTrailingComments: true

# Line breaks
AllowShortBlocksOnASingleLine: false
AllowShortCaseLabelsOnASingleLine: false
AllowShortFunctionsOnASingleLine: None
AllowShortIfStatementsOnASingleLine: false

# Includes
SortIncludes: true
IncludeBlocks: Regroup
IncludeCategories:
  - Regex: '^<.*\.h>'     # System C headers
    Priority: 1
  - Regex: '^<.*>'        # System C++ headers  
    Priority: 2
  - Regex: '^".*"'        # Local headers
    Priority: 3

# Comments
ReflowComments: true
```

**Static Analysis with cppcheck:**

```bash
#!/bin/bash
# static_analysis.sh - Comprehensive static analysis

echo "🔍 Running Static Analysis..."

# Create reports directory
mkdir -p reports

# Run cppcheck with comprehensive checks⁵
echo "Running cppcheck..."
cppcheck \
    --enable=all \
    --std=c11 \
    --platform=unix64 \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --inline-suppr \
    --xml \
    --xml-version=2 \
    src/ include/ \
    2> reports/cppcheck.xml

# Generate HTML report
cppcheck-htmlreport \
    --source-dir=. \
    --title="Project Static Analysis" \
    --file=reports/cppcheck.xml \
    --report-dir=reports/cppcheck/

# Run clang-tidy on all source files
echo "Running clang-tidy..."
find src -name "*.c" | while read -r file; do
    echo "Analyzing: $file"
    clang-tidy "$file" -- -Iinclude > "reports/$(basename "$file").tidy" 2>&1
done

# Run clang static analyzer
echo "Running clang static analyzer..."
scan-build \
    -o reports/scan-build \
    --html-title="Static Analysis Report" \
    make clean all

echo "✅ Static analysis completed. Check reports/ directory."
```

#### Best Practices for Large C Projects

**Project Structure:**

```
my-large-c-project/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                 # CI pipeline
│   │   └── release.yml            # Release automation
│   └── ISSUE_TEMPLATE.md          # Issue templates
├── cmake/
│   ├── FindCustomLib.cmake        # Custom CMake modules
│   └── CompilerWarnings.cmake     # Compiler configurations
├── docs/
│   ├── api/                       # API documentation
│   ├── design/                    # Design documents
│   ├── examples/                  # Usage examples
│   └── Doxyfile                   # Doxygen configuration
├── include/
│   ├── myproject/                 # Public headers
│   │   ├── core.h
│   │   └── utils.h
│   └── myproject_version.h.in     # Version template
├── src/
│   ├── core/                      # Core functionality
│   │   ├── core.c
│   │   └── core_internal.h        # Private headers
│   ├── utils/
│   │   └── utils.c
│   └── main.c
├── tests/
│   ├── unit/                      # Unit tests
│   │   ├── test_core.c
│   │   └── test_utils.c
│   ├── integration/               # Integration tests
│   └── fixtures/                  # Test data
├── tools/
│   ├── scripts/                   # Build/utility scripts
│   └── generators/                # Code generators
├── third_party/                   # External dependencies
├── .clang-format                  # Code formatting rules
├── .clang-tidy                    # Static analysis rules
├── .gitignore                     # Git ignore rules
├── CMakeLists.txt                 # Build configuration
├── README.md                      # Project documentation
├── CHANGELOG.md                   # Change history
└── LICENSE                        # License information
```

**Documentation Standards with Doxygen:**

```c
/**
 * @file core.h
 * @brief Core functionality for the MyProject library
 * @details This file contains the main API functions for interacting
 *          with the MyProject library. It provides a clean interface
 *          for users while hiding internal implementation details.
 * 
 * @author John Developer
 * @date 2024-01-15
 * @version 1.2.0
 * @copyright Copyright (c) 2024 MyCompany. All rights reserved.
 * @license MIT License
 */

#ifndef MYPROJECT_CORE_H
#define MYPROJECT_CORE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Core Core Functions
 * @brief Core functionality of the MyProject library
 * @{
 */

/**
 * @brief Error codes returned by library functions
 * 
 * All library functions return one of these error codes to indicate
 * success or the type of failure that occurred.
 */
typedef enum {
    MYPROJECT_SUCCESS = 0,      /**< Operation completed successfully */
    MYPROJECT_ERROR_PARAM = -1, /**< Invalid parameter passed to function */
    MYPROJECT_ERROR_MEMORY = -2,/**< Memory allocation failed */
    MYPROJECT_ERROR_IO = -3,    /**< Input/output operation failed */
    MYPROJECT_ERROR_STATE = -4  /**< Invalid state for operation */
} MyProjectError;

/**
 * @brief Configuration structure for the library
 * 
 * This structure holds configuration parameters that control
 * the behavior of the library. Initialize with myproject_config_default()
 * and modify as needed before calling myproject_init().
 */
typedef struct {
    /** @brief Maximum number of concurrent operations */
    uint32_t max_operations;
    
    /** @brief Enable debug logging */
    bool debug_enabled;
    
    /** @brief Memory limit in bytes (0 = no limit) */
    size_t memory_limit;
    
    /** @brief Custom allocator function (NULL = use malloc) */
    void* (*custom_allocator)(size_t size);
    
    /** @brief Custom deallocator function (NULL = use free) */
    void (*custom_deallocator)(void* ptr);
} MyProjectConfig;

/**
 * @brief Initialize the library with given configuration
 * 
 * This function must be called before using any other library functions.
 * It sets up internal data structures and validates the configuration.
 * 
 * @param[in] config Configuration parameters (NULL for defaults)
 * 
 * @return MYPROJECT_SUCCESS on success
 * @retval MYPROJECT_ERROR_PARAM if config contains invalid values
 * @retval MYPROJECT_ERROR_MEMORY if initialization fails due to memory
 * 
 * @pre Library must not be already initialized
 * @post Library is ready for use if successful
 * 
 * @warning This function is not thread-safe. Call only from main thread.
 * 
 * @see myproject_cleanup()
 * @see myproject_config_default()
 * 
 * @par Example:
 * @code
 * MyProjectConfig config;
 * myproject_config_default(&config);
 * config.max_operations = 100;
 * 
 * if (myproject_init(&config) != MYPROJECT_SUCCESS) {
 *     fprintf(stderr, "Failed to initialize library\n");
 *     exit(1);
 * }
 * @endcode
 */
MyProjectError myproject_init(const MyProjectConfig* config);

/**
 * @brief Clean up library resources
 * 
 * This function releases all resources allocated by the library
 * and should be called before program termination.
 * 
 * @warning After calling this function, no other library functions
 *          should be called until myproject_init() is called again.
 * 
 * @see myproject_init()
 */
void myproject_cleanup(void);

/**
 * @brief Fill configuration structure with default values
 * 
 * @param[out] config Configuration structure to initialize
 * 
 * @pre config must not be NULL
 * @post config contains sensible default values
 */
void myproject_config_default(MyProjectConfig* config);

/** @} */ // end of Core group

#ifdef __cplusplus
}
#endif

#endif /* MYPROJECT_CORE_H */
```

**Coding Standards Document (CODING_STANDARDS.md):**

```markdown
# C Coding Standards

## Overview
This document defines the coding standards for our C projects to ensure
consistency, maintainability, and quality across the codebase.

## Naming Conventions

### Functions
- Use `snake_case` for function names
- Use descriptive names that indicate the action performed
- Prefix with module name for public APIs: `mymodule_function_name()`

```c
// ✅ Good
int user_authenticate(const char* username, const char* password);
void string_buffer_clear(StringBuffer* buffer);

// ❌ Bad  
int auth(const char* u, const char* p);
void clr(StringBuffer* buf);
```

### Variables
- Use `snake_case` for variable names
- Use descriptive names, avoid abbreviations
- Use `const` qualifier when appropriate

```c
// ✅ Good
const char* config_filename = "app.conf";
int connection_count = 0;
bool is_initialized = false;

// ❌ Bad
const char* cfg = "app.conf";
int cnt = 0;
bool init = false;
```

### Constants and Macros
- Use `SCREAMING_SNAKE_CASE` for macros and constants
- Include module prefix for public APIs

```c
// ✅ Good
#define MYPROJECT_MAX_CONNECTIONS 1000
#define BUFFER_SIZE 4096
const int DEFAULT_TIMEOUT = 30;

// ❌ Bad
#define maxConn 1000
#define buf_sz 4096
```

## Code Organization

### File Structure
1. Copyright/license header
2. File documentation comment
3. System includes (alphabetical)
4. Local includes (alphabetical)  
5. Forward declarations
6. Constants and macros
7. Type definitions
8. Static function declarations
9. Global variables (avoid if possible)
10. Function implementations

### Header Guards
Always use include guards in headers:

```c
#ifndef MYPROJECT_MODULE_H
#define MYPROJECT_MODULE_H

/* Header content */

#endif /* MYPROJECT_MODULE_H */
```

## Error Handling

### Return Codes
- Use consistent error code conventions
- Always check return values from functions that can fail
- Provide meaningful error messages

```c
typedef enum {
    RESULT_SUCCESS = 0,
    RESULT_ERROR_INVALID_PARAM = -1,
    RESULT_ERROR_OUT_OF_MEMORY = -2,
    RESULT_ERROR_IO = -3
} Result;

Result process_file(const char* filename) {
    if (!filename) {
        return RESULT_ERROR_INVALID_PARAM;
    }
    
    FILE* file = fopen(filename, "r");
    if (!file) {
        return RESULT_ERROR_IO;
    }
    
    // Process file...
    
    fclose(file);
    return RESULT_SUCCESS;
}
```

## Memory Management

### Allocation Guidelines
- Always check allocation return values
- Free all allocated memory
- Set pointers to NULL after freeing
- Use consistent allocation/deallocation patterns

```c
// ✅ Good
char* create_buffer(size_t size) {
    char* buffer = malloc(size);
    if (!buffer) {
        return NULL;
    }
    
    memset(buffer, 0, size);
    return buffer;
}

void destroy_buffer(char** buffer) {
    if (buffer && *buffer) {
        free(*buffer);
        *buffer = NULL;
    }
}

// Usage
char* buf = create_buffer(1024);
if (!buf) {
    // Handle error
    return ERROR_OUT_OF_MEMORY;
}

// Use buffer...

destroy_buffer(&buf);  // buf is now NULL
```

## Thread Safety

### Guidelines
- Document thread safety guarantees for each function
- Use appropriate synchronization primitives
- Avoid global mutable state when possible

```c
/**
 * @brief Thread-safe counter increment
 * @note This function is thread-safe
 */
void counter_increment(Counter* counter) {
    pthread_mutex_lock(&counter->mutex);
    counter->value++;
    pthread_mutex_unlock(&counter->mutex);
}
```
```

**Footnote 1**: *Good commit messages follow the format: brief summary (50 chars max), blank line, detailed explanation. This helps with code review and maintenance.*

**Footnote 2**: *Merge commits preserve the feature branch history, while rebase creates a linear history. Choose based on team preferences and project needs.*

**Footnote 3**: *Interactive rebase allows you to squash commits, reword messages, and reorder commits before merging. This creates cleaner history but should not be used on public#### Concepts ⚙
- Process creation with fork() and program replacement with exec()
- Inter-process communication mechanisms and their use cases
- Signal handling for asynchronous events
- Process synchronization and resource sharing

#### Errors ⚠
- Race conditions between parent and child processes
- Zombie processes from unreaped children
- Signal handling in multi-threaded environments
- Resource leaks in IPC mechanisms

#### Tips 🧠
- Always check return values from system calls
- Use waitpid() with WNOHANG to avoid blocking
- Implement proper signal handlers with sigaction
- Clean up IPC resources (shared memory, message queues, semaphores)

#### Tools 🔧
- **Process Monitoring**: ps, top, htop, pstree
- **IPC Analysis**: ipcs, ipcrm for System V IPC
- **Signal Debugging**: strace, ltrace
- **System Call Tracing**: strace -f for fork tracking

---

### 25. Advanced Concurrency & Parallelism {#advanced-concurrency}

**Figure Reference: [Threading Models Comparison Diagram]**

Modern C applications require efficient concurrency and parallelism to utilize multi-core systems effectively.

#### POSIX Threads (pthreads) Fundamentals

```c
/* pthreads_basics.c - POSIX threads fundamentals */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

// Thread function signature: void* (*start_routine)(void*)
void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    printf("Thread %d: Starting work (PID: %d, TID: %lu)\n", 
           thread_id, getpid(), pthread_self());
    
    // Simulate work
    for (int i = 0; i < 5; i++) {
        printf("Thread %d: Working... step %d\n", thread_id, i + 1);
        sleep(1);
    }
    
    // Return value (can be retrieved with pthread_join)
    int* result = malloc(sizeof(int));
    *result = thread_id * 100;
    
    printf("Thread %d: Completed work\n", thread_id);
    return result;
}

void basic_pthread_demo(void) {
    printf("=== Basic pthread Demo ===\n");
    
    const int num_threads = 3;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i + 1;
        
        int result = pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]);
        if (result != 0) {
            fprintf(stderr, "Error creating thread %d: %s\n", i, strerror(result));
            exit(1);
        }
        
        printf("Main: Created thread %d\n", i + 1);
    }
    
    // Wait for threads to complete and collect results
    for (int i = 0; i < num_threads; i++) {
        void* thread_result;
        int result = pthread_join(threads[i], &thread_result);
        
        if (result != 0) {
            fprintf(stderr, "Error joining thread %d: %s\n", i, strerror(result));
        } else {
            int* value = (int*)thread_result;
            printf("Main: Thread %d returned: %d\n", i + 1, *value);
            free(value);  // Clean up allocated result
        }
    }
    
    printf("Main: All threads completed\n");
}

// Thread attributes demonstration
void thread_attributes_demo(void) {
    printf("\n=== Thread Attributes Demo ===\n");
    
    pthread_t thread;
    pthread_attr_t attr;
    
    // Initialize thread attributes
    pthread_attr_init(&attr);
    
    // Set thread as detached¹
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    // Set stack size (default is usually 8MB on Linux)
    size_t stack_size = 1024 * 1024;  // 1MB
    pthread_attr_setstacksize(&attr, stack_size);
    
    // Get and display attributes
    int detach_state;
    size_t actual_stack_size;
    
    pthread_attr_getdetachstate(&attr, &detach_state);
    pthread_attr_getstacksize(&attr, &actual_stack_size);
    
    printf("Thread attributes:\n");
    printf("  Detach state: %s\n", 
           detach_state == PTHREAD_CREATE_DETACHED ? "Detached" : "Joinable");
    printf("  Stack size: %zu bytes\n", actual_stack_size);
    
    int thread_id = 99;
    int result = pthread_create(&thread, &attr, worker_thread, &thread_id);
    
    if (result == 0) {
        printf("Detached thread created successfully\n");
        // Note: Cannot join detached threads
        sleep(6);  // Give thread time to complete
    }
    
    // Clean up attributes
    pthread_attr_destroy(&attr);
}
```

**Footnote 1**: *Detached threads automatically clean up their resources when they terminate, but cannot be joined. This is useful for fire-and-forget tasks.*

#### Synchronization Primitives

```c
/* pthread_synchronization.c - Threading synchronization primitives */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

// Shared data structure
typedef struct {
    int counter;
    pthread_mutex_t mutex;          // Protects counter
    pthread_cond_t condition;       // Signals counter changes
    pthread_rwlock_t rwlock;        // Reader-writer lock for data
    int data[100];
    int data_ready;
} SharedData;

SharedData shared_data = {
    .counter = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER,
    .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    .data_ready = 0
};

// Mutex demonstration
void* mutex_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 1000; i++) {
        // Critical section - must be protected by mutex²
        pthread_mutex_lock(&shared_data.mutex);
        
        int old_value = shared_data.counter;
        shared_data.counter = old_value + 1;  // Non-atomic operation
        
        pthread_mutex_unlock(&shared_data.mutex);
        
        // Simulate some work outside critical section
        if (i % 100 == 0) {
            printf("Thread %d: counter = %d (iteration %d)\n", 
                   thread_id, shared_data.counter, i);
        }
    }
    
    return NULL;
}

void mutex_demo(void) {
    printf("=== Mutex Demo ===\n");
    
    const int num_threads = 4;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];
    
    printf("Starting %d threads, each incrementing counter 1000 times\n", num_threads);
    printf("Expected final counter value: %d\n", num_threads * 1000);
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i + 1;
        pthread_create(&threads[i], NULL, mutex_worker, &thread_ids[i]);
    }
    
    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Final counter value: %d\n", shared_data.counter);
    printf("Mutex prevented race conditions: %s\n", 
           shared_data.counter == num_threads * 1000 ? "YES" : "NO");
}

// Condition variable demonstration
void* producer_thread(void* arg) {
    printf("Producer: Generating data...\n");
    
    // Generate data
    pthread_rwlock_wrlock(&shared_data.rwlock);  // Write lock
    
    for (int i = 0; i < 100; i++) {
        shared_data.data[i] = i * i;  // Simple data: squares
    }
    
    pthread_rwlock_unlock(&shared_data.rwlock);
    
    // Signal that data is ready
    pthread_mutex_lock(&shared_data.mutex);
    shared_data.data_ready = 1;
    pthread_cond_broadcast(&shared_data.condition);  // Wake all waiters
    pthread_mutex_unlock(&shared_data.mutex);
    
    printf("Producer: Data ready, consumers notified\n");
    return NULL;
}

void* consumer_thread(void* arg) {
    int consumer_id = *(int*)arg;
    
    printf("Consumer %d: Waiting for data...\n", consumer_id);
    
    // Wait for data to be ready³
    pthread_mutex_lock(&shared_data.mutex);
    while (!shared_data.data_ready) {
        pthread_cond_wait(&shared_data.condition, &shared_data.mutex);
    }
    pthread_mutex_unlock(&shared_data.mutex);
    
    printf("Consumer %d: Data available, processing...\n", consumer_id);
    
    // Read data (multiple readers can read simultaneously)
    pthread_rwlock_rdlock(&shared_data.rwlock);  // Read lock
    
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += shared_data.data[i];
    }
    
    pthread_rwlock_unlock(&shared_data.rwlock);
    
    printf("Consumer %d: Sum of data = %d\n", consumer_id, sum);
    return NULL;
}

void condition_variable_demo(void) {
    printf("\n=== Condition Variable & RWLock Demo ===\n");
    
    pthread_t producer;
    pthread_t consumers[3];
    int consumer_ids[] = {1, 2, 3};
    
    // Reset data_ready flag
    shared_data.data_ready = 0;
    
    // Create consumer threads first
    for (int i = 0; i < 3; i++) {
        pthread_create(&consumers[i], NULL, consumer_thread, &consumer_ids[i]);
    }
    
    sleep(1);  // Let consumers start waiting
    
    // Create producer thread
    pthread_create(&producer, NULL, producer_thread, NULL);
    
    // Wait for all threads
    pthread_join(producer, NULL);
    for (int i = 0; i < 3; i++) {
        pthread_join(consumers[i], NULL);
    }
}
```

**Footnote 2**: *The mutex ensures atomicity of the increment operation. Without it, multiple threads could read the same value, increment it, and write back the same result, causing lost updates.*

**Footnote 3**: *pthread_cond_wait() atomically unlocks the mutex and waits for the condition. When signaled, it re-acquires the mutex before returning. This prevents race conditions in the wait-signal pattern.*

#### Thread Barriers and Advanced Synchronization

```c
/* advanced_sync.c - Advanced synchronization primitives */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

// Barrier demonstration⁴
pthread_barrier_t sync_barrier;
int barrier_thread_count = 4;

void* barrier_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    printf("Thread %d: Starting phase 1\n", thread_id);
    sleep(thread_id);  // Different work times
    printf("Thread %d: Completed phase 1\n", thread_id);
    
    // Wait for all threads to complete phase 1
    printf("Thread %d: Waiting at barrier\n", thread_id);
    int result = pthread_barrier_wait(&sync_barrier);
    
    if (result == PTHREAD_BARRIER_SERIAL_THREAD) {
        printf("Thread %d: Last thread to reach barrier\n", thread_id);
    }
    
    printf("Thread %d: Starting phase 2\n", thread_id);
    sleep(1);
    printf("Thread %d: Completed phase 2\n", thread_id);
    
    return NULL;
}

void barrier_demo(void) {
    printf("\n=== Barrier Demo ===\n");
    
    // Initialize barrier for 4 threads
    pthread_barrier_init(&sync_barrier, NULL, barrier_thread_count);
    
    pthread_t threads[4];
    int thread_ids[] = {1, 2, 3, 4};
    
    printf("Creating %d threads with different work times\n", barrier_thread_count);
    
    for (int i = 0; i < barrier_thread_count; i++) {
        pthread_create(&threads[i], NULL, barrier_worker, &thread_ids[i]);
    }
    
    for (int i = 0; i < barrier_thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    pthread_barrier_destroy(&sync_barrier);
    printf("All threads synchronized and completed\n");
}

// Spinlock demonstration (busy-waiting)
pthread_spinlock_t spinlock;
volatile int spin_counter = 0;

void* spinlock_worker(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 100000; i++) {
        pthread_spin_lock(&spinlock);
        spin_counter++;
        pthread_spin_unlock(&spinlock);
    }
    
    return NULL;
}

void spinlock_demo(void) {
    printf("\n=== Spinlock Demo ===\n");
    
    pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
    
    const int num_threads = 2;
    pthread_t threads[num_threads];
    int thread_ids[] = {1, 2};
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, spinlock_worker, &thread_ids[i]);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    gettimeofday(&end, NULL);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Spinlock result: counter = %d (expected: %d)\n", 
           spin_counter, num_threads * 100000);
    printf("Elapsed time: %.4f seconds\n", elapsed);
    
    pthread_spin_destroy(&spinlock);
}
```

**Footnote 4**: *Barriers synchronize multiple threads at a specific point. All threads must reach the barrier before any can proceed. This is useful for parallel algorithms with distinct phases.*

#### Thread Pool Implementation

```c
/* thread_pool.c - Professional thread pool implementation */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

// Task structure
typedef struct Task {
    void (*function)(void* arg);  // Task function
    void* argument;               // Task argument  
    struct Task* next;           // Next task in queue
} Task;

// Thread pool structure
typedef struct {
    pthread_t* threads;          // Array of worker threads
    Task* task_queue_head;       // Head of task queue
    Task* task_queue_tail;       // Tail of task queue
    pthread_mutex_t queue_mutex; // Protects task queue
    pthread_cond_t queue_cond;   // Signals new tasks
    pthread_cond_t done_cond;    // Signals task completion
    int thread_count;            // Number of worker threads
    int active_tasks;            // Number of active tasks
    int total_tasks;             // Total tasks in queue
    bool shutdown;               // Shutdown flag
} ThreadPool;

// Worker thread function
void* thread_pool_worker(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;
    
    while (true) {
        pthread_mutex_lock(&pool->queue_mutex);
        
        // Wait for tasks or shutdown signal
        while (pool->task_queue_head == NULL && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex);
        }
        
        // Check for shutdown
        if (pool->shutdown && pool->task_queue_head == NULL) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }
        
        // Get next task from queue
        Task* task = pool->task_queue_head;
        if (task != NULL) {
            pool->task_queue_head = task->next;
            if (pool->task_queue_head == NULL) {
                pool->task_queue_tail = NULL;
            }
            pool->total_tasks--;
            pool->active_tasks++;
        }
        
        pthread_mutex_unlock(&pool->queue_mutex);
        
        // Execute task
        if (task != NULL) {
            task->function(task->argument);
            free(task);
            
            // Mark task as completed
            pthread_mutex_lock(&pool->queue_mutex);
            pool->active_tasks--;
            if (pool->active_tasks == 0 && pool->total_tasks == 0) {
                pthread_cond_signal(&pool->done_cond);
            }
            pthread_mutex_unlock(&pool->queue_mutex);
        }
    }
    
    return NULL;
}

// Create thread pool
ThreadPool* thread_pool_create(int thread_count) {
    if (thread_count <= 0) return NULL;
    
    ThreadPool* pool = malloc(sizeof(ThreadPool));
    if (!pool) return NULL;
    
    // Initialize pool structure
    pool->threads = malloc(thread_count * sizeof(pthread_t));
    pool->task_queue_head = NULL;
    pool->task_queue_tail = NULL;
    pool->thread_count = thread_count;
    pool->active_tasks = 0;
    pool->total_tasks = 0;
    pool->shutdown = false;
    
    // Initialize synchronization primitives
    pthread_mutex_init(&pool->queue_mutex, NULL);
    pthread_cond_init(&pool->queue_cond, NULL);
    pthread_cond_init(&pool->done_cond, NULL);
    
    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool) != 0) {
            // Handle thread creation failure
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    
    return pool;
}

// Submit task to thread pool
int thread_pool_submit(ThreadPool* pool, void (*function)(void*), void* argument) {
    if (!pool || !function) return -1;
    
    Task* task = malloc(sizeof(Task));
    if (!task) return -1;
    
    task->function = function;
    task->argument = argument;
    task->next = NULL;
    
    pthread_mutex_lock(&pool->queue_mutex);
    
    if (pool->shutdown) {
        free(task);
        pthread_mutex_unlock(&pool->queue_mutex);
        return -1;
    }
    
    // Add task to queue
    if (pool->task_queue_tail == NULL) {
        pool->task_queue_head = pool->task_queue_tail = task;
    } else {
        pool->task_queue_tail->next = task;
        pool->task_queue_tail = task;
    }
    
    pool->total_tasks++;
    
    // Signal worker threads
    pthread_cond_signal(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return 0;
}

// Wait for all tasks to complete
void thread_pool_wait(ThreadPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    while (pool->active_tasks > 0 || pool->total_tasks > 0) {
        pthread_cond_wait(&pool->done_cond, &pool->queue_mutex);
    }
    pthread_mutex_unlock(&pool->queue_mutex);
}

// Destroy thread pool
void thread_pool_destroy(ThreadPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    // Wait for worker threads to finish
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    // Clean up remaining tasks
    Task* current = pool->task_queue_head;
    while (current != NULL) {
        Task* next = current->next;
        free(current);
        current = next;
    }
    
    // Clean up synchronization primitives
    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_cond);
    pthread_cond_destroy(&pool->done_cond);
    
    free(pool->threads);
    free(pool);
}

// Example task functions
void cpu_intensive_task(void* arg) {
    int task_id = *(int*)arg;
    printf("Task %d: Starting CPU-intensive work\n", task_id);
    
    // Simulate CPU work
    volatile long sum = 0;
    for (long i = 0; i < 1000000; i++) {
        sum += i;
    }
    
    printf("Task %d: Completed (sum = %ld)\n", task_id, sum);
}

void io_task(void* arg) {
    int task_id = *(int*)arg;
    printf("Task %d: Simulating I/O operation\n", task_id);
    
    // Simulate I/O delay
    sleep(1);
    
    printf("Task %d: I/O operation completed\n", task_id);
}

void thread_pool_demo(void) {
    printf("=== Thread Pool Demo ===\n");
    
    // Create thread pool with 4 worker threads
    ThreadPool* pool = thread_pool_create(4);
    if (!pool) {
        printf("Failed to create thread pool\n");
        return;
    }
    
    printf("Created thread pool with 4 worker threads\n");
    
    // Submit CPU-intensive tasks
    int cpu_task_ids[] = {1, 2, 3, 4, 5};
    for (int i = 0; i < 5; i++) {
        thread_pool_submit(pool, cpu_intensive_task, &cpu_task_ids[i]);
    }
    
    // Submit I/O tasks
    int io_task_ids[] = {10, 11, 12};
    for (int i = 0; i < 3; i++) {
        thread_pool_submit(pool, io_task, &io_task_ids[i]);
    }
    
    printf("Submitted 8 tasks total\n");
    
    // Wait for all tasks to complete
    thread_pool_wait(pool);
    printf("All tasks completed\n");
    
    // Clean up
    thread_pool_destroy(pool);
    printf("Thread pool destroyed\n");
}
```

#### Parallel Algorithms

```c
/* parallel_algorithms.c - Map-Reduce style parallel processing */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

// Parallel map operation⁵
typedef struct {
    double* input_array;
    double* output_array;
    int start_index;
    int end_index;
    double (*map_function)(double);
} MapTask;

// Example map functions
double square_function(double x) {
    return x * x;
}

double sqrt_function(double x) {
    return sqrt(x);
}

void* parallel_map_worker(void* arg) {
    MapTask* task = (MapTask*)arg;
    
    for (int i = task->start_index; i < task->end_index; i++) {
        task->output_array[i] = task->map_function(task->input_array[i]);
    }
    
    return NULL;
}

void parallel_map(double* input, double* output, int size, int num_threads, 
                 double (*map_func)(double)) {
    if (num_threads <= 0 || size <= 0) return;
    
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    MapTask* tasks = malloc(num_threads * sizeof(MapTask));
    
    int chunk_size = size / num_threads;
    int remainder = size % num_threads;
    
    // Create and start worker threads
    for (int i = 0; i < num_threads; i++) {
        tasks[i].input_array = input;
        tasks[i].output_array = output;
        tasks[i].map_function = map_func;
        tasks[i].start_index = i * chunk_size;
        tasks[i].end_index = (i + 1) * chunk_size;
        
        // Distribute remainder among first threads
        if (i < remainder) {
            tasks[i].end_index++;
        }
        if (i > 0 && i <= remainder) {
            tasks[i].start_index++;
            tasks[i].end_index++;
        }
        
        pthread_create(&threads[i], NULL, parallel_map_worker, &tasks[i]);
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    free(tasks);
}

// Parallel reduce operation
typedef struct {
    double* array;
    int start_index;
    int end_index;
    double result;
    double (*reduce_function)(double, double);
} ReduceTask;

double sum_function(double a, double b) {
    return a + b;
}

double max_function(double a, double b) {
    return a > b ? a : b;
}

void* parallel_reduce_worker(void* arg) {
    ReduceTask* task = (ReduceTask*)arg;
    
    if (task->start_index >= task->end_index) {
        task->result = 0.0;  // Identity for sum
        return NULL;
    }
    
    task->result = task->array[task->start_index];
    for (int i = task->start_index + 1; i < task->end_index; i++) {
        task->result = task->reduce_function(task->result, task->array[i]);
    }
    
    return NULL;
}

double parallel_reduce(double* array, int size, int num_threads,
                      double (*reduce_func)(double, double)) {
    if (num_threads <= 0 || size <= 0) return 0.0;
    
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    ReduceTask* tasks = malloc(num_threads * sizeof(ReduceTask));
    
    int chunk_size = size / num_threads;
    
    // Create and start worker threads
    for (int i = 0; i < num_threads; i++) {
        tasks[i].array = array;
        tasks[i].reduce_function = reduce_func;
        tasks[i].start_index = i * chunk_size;
        tasks[i].end_index = (i + 1) * chunk_size;
        
        // Last thread handles remainder
        if (i == num_threads - 1) {
            tasks[i].end_index = size;
        }
        
        pthread_create(&threads[i], NULL, parallel_reduce_worker, &tasks[i]);
    }
    
    // Wait for all threads and combine results
    double final_result = 0.0;
    bool first_result = true;
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        
        if (tasks[i].start_index < tasks[i].end_index) {  // Thread had work to do
            if (first_result) {
                final_result = tasks[i].result;
                first_result = false;
            } else {
                final_result = reduce_func(final_result, tasks[i].result);
            }
        }
    }
    
    free(threads);
    free(tasks);
    
    return final_result;
}

void parallel_algorithms_demo(void) {
    printf("=== Parallel Algorithms Demo ===\n");
    
    const int array_size = 1000000;
    const int num_threads = 4;
    
    // Create test data
    double* input_data = malloc(array_size * sizeof(double));
    double* output_data = malloc(array_size * sizeof(double));
    
    for (int i = 0; i < array_size; i++) {
        input_data[i] = (double)(i + 1);
    }
    
    printf("Processing array of %d elements with %d threads\n", 
           array_size, num_threads);
    
    // Parallel map: square all elements
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    parallel_map(input_data, output_data, array_size, num_threads, square_function);
    
    gettimeofday(&end, NULL);
    double map_time = (end.tv_sec - start.tv_sec) + 
                     (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Parallel map (square) completed in %.4f seconds\n", map_time);
    
    // Verify first few results
    printf("First 5 squared values: ");
    for (int i = 0; i < 5; i++) {
        printf("%.0f ", output_data[i]);
    }
    printf("\n");
    
    // Parallel reduce: sum all squared values
    gettimeofday(&start, NULL);
    
    double sum = parallel_reduce(output_data, array_size, num_threads, sum_function);
    
    gettimeofday(&end, NULL);
    double reduce_time = (end.tv_sec - start.tv_sec) + 
                        (end.tv_usec - start.tv_usec) / 1000000.0;
    
    printf("Parallel reduce (sum) completed in %.4f seconds\n", reduce_time);
    printf("Sum of squares: %.0f\n", sum);
    
    // Find maximum value
    double max_value = parallel_reduce(output_data, array_size, num_threads, max_function);
    printf("Maximum value: %.0f\n", max_value);
    
    free                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Echo back the message that came in
                    buffer[valread] = '\0';
                    printf("Received: %s", buffer);
                    send(sd, buffer, strlen(buffer), 0);
                }
            }
        }
    }
    
    close(server_fd);
}

// UDP Server implementation
void udp_server_demo(int port) {
    int server_fd;
    char buffer[1024];
    struct sockaddr_in servaddr, cliaddr;
    
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    
    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);
    
    // Bind the socket with the server address
    if (bind(server_fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    printf("UDP Server listening on port %d\n", port);
    
    socklen_t len = sizeof(cliaddr);
    
    while (1) {
        int n = recvfrom(server_fd, (char *)buffer, 1024,
                        MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';
        printf("Client: %s\n", buffer);
        
        // Echo back
        sendto(server_fd, buffer, strlen(buffer),
               MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
    }
    
    close(server_fd);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "tcp") == 0) {
        run_echo_server(8080);
    } else if (argc > 1 && strcmp(argv[1], "udp") == 0) {
        udp_server_demo(8081);
    } else {
        printf("Usage: %s [tcp|udp]\n", argv[0]);
    }
    
    return 0;
}
```

#### Concepts ⚙
- Socket programming fundamentals
- TCP vs UDP protocol differences
- Non-blocking I/O with select/poll/epoll
- Network byte order and endianness

#### Errors ⚠
- Not handling partial sends/receives
- Ignoring network byte order conversions
- Resource leaks with unclosed sockets
- Race conditions in multi-threaded servers

#### Tips 🧠
- Always use non-blocking I/O for scalable servers
- Implement proper error handling and retry logic
- Consider using higher-level libraries for complex protocols
- Test network code with various failure scenarios

#### Tools 🔧
- **Network Analysis**: Wireshark, tcpdump, netstat
- **Load Testing**: Apache Bench (ab), wrk, siege
- **Debugging**: strace, ltrace for system call tracing
- **Performance**: iperf, netperf for throughput testing

---

## Part IV: Special Sections

### 24. System Programming {#system-programming}

**Figure Reference: [Unix Process Hierarchy Diagram]**

System programming involves low-level interaction with the operating system, managing processes, and inter-process communication.

#### Process Management

```c
/* process_management.c - Process creation and management */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

void basic_fork_demo(void) {
    printf("=== Basic Fork Demo ===\n");
    printf("Before fork: PID = %d\n", getpid());
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process: PID = %d, Parent PID = %d\n", 
               getpid(), getppid());
        printf("Child: Doing some work...\n");
        sleep(2);
        printf("Child: Work completed\n");
        exit(42);  // Child exits with status 42
    } else {
        // Parent process
        printf("Parent process: PID = %d, Child PID = %d\n", 
               getpid(), pid);
        
        int status;
        pid_t child_pid = wait(&status);
        
        printf("Parent: Child %d terminated\n", child_pid);
        if (WIFEXITED(status)) {
            printf("Parent: Child exit status = %d\n", WEXITSTATUS(status));
        }
    }
}

// Process creation with exec family
void fork_exec_demo(void) {
    printf("\n=== Fork + Exec Demo ===\n");
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return;
    } else if (pid == 0) {
        // Child process - replace with new program
        printf("Child: About to exec 'ls -l'\n");
        
        // Replace process image with 'ls' command
        execlp("ls", "ls", "-l", ".", NULL);
        
        // This line should never be reached if exec succeeds
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        printf("Parent: Waiting for child to complete 'ls' command\n");
        
        int status;
        waitpid(pid, &status, 0);
        printf("Parent: Child completed\n");
    }
}

// Advanced process management
typedef struct {
    pid_t pid;
    char command[256];
    time_t start_time;
    int status;
    enum { PROC_RUNNING, PROC_FINISHED, PROC_FAILED } state;
} ProcessInfo;

#define MAX_PROCESSES 10
ProcessInfo processes[MAX_PROCESSES];
int process_count = 0;

int start_background_process(const char *command) {
    if (process_count >= MAX_PROCESSES) {
        printf("Process limit reached\n");
        return -1;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return -1;
    } else if (pid == 0) {
        // Child process - execute command
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process - record process info
        ProcessInfo *proc = &processes[process_count];
        proc->pid = pid;
        strncpy(proc->command, command, sizeof(proc->command) - 1);
        proc->command[sizeof(proc->command) - 1] = '\0';
        proc->start_time = time(NULL);
        proc->state = PROC_RUNNING;
        
        printf("Started process %d: %s\n", pid, command);
        return process_count++;
    }
}

void check_processes(void) {
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *proc = &processes[i];
        
        if (proc->state == PROC_RUNNING) {
            int status;
            pid_t result = waitpid(proc->pid, &status, WNOHANG);
            
            if (result == proc->pid) {
                // Process finished
                proc->status = status;
                proc->state = WIFEXITED(status) ? PROC_FINISHED : PROC_FAILED;
                
                printf("Process %d (%s) %s\n", 
                       proc->pid, proc->command,
                       proc->state == PROC_FINISHED ? "completed" : "failed");
            } else if (result == -1) {
                perror("waitpid");
                proc->state = PROC_FAILED;
            }
            // result == 0 means process is still running
        }
    }
}

void process_manager_demo(void) {
    printf("\n=== Process Manager Demo ===\n");
    
    // Start some background processes
    start_background_process("sleep 3 && echo 'Task 1 completed'");
    start_background_process("ls -la /tmp > /dev/null");
    start_background_process("echo 'Quick task' && sleep 1");
    
    // Monitor processes
    for (int i = 0; i < 10; i++) {
        check_processes();
        sleep(1);
        
        // Check if all processes are done
        int running_count = 0;
        for (int j = 0; j < process_count; j++) {
            if (processes[j].state == PROC_RUNNING) {
                running_count++;
            }
        }
        
        if (running_count == 0) {
            printf("All processes completed\n");
            break;
        }
    }
}
```

#### Inter-Process Communication (IPC)

**Pipes and Named Pipes:**

```c
/* ipc_pipes.c - Pipe-based inter-process communication */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

void anonymous_pipe_demo(void) {
    printf("=== Anonymous Pipe Demo ===\n");
    
    int pipefd[2];  // pipe file descriptors: [0] = read, [1] = write
    pid_t pid;
    char buffer[100];
    
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }
    
    pid = fork();
    
    if (pid == -1) {
        perror("fork");
        return;
    } else if (pid == 0) {
        // Child process - writer
        close(pipefd[0]);  // Close unused read end
        
        const char *message = "Hello from child process!";
        printf("Child: Sending message: %s\n", message);
        
        write(pipefd[1], message, strlen(message) + 1);
        close(pipefd[1]);
        exit(0);
    } else {
        // Parent process - reader
        close(pipefd[1]);  // Close unused write end
        
        printf("Parent: Waiting for message...\n");
        ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("Parent: Received: %s\n", buffer);
        }
        
        close(pipefd[0]);
        wait(NULL);  // Wait for child to finish
    }
}

void named_pipe_demo(void) {
    printf("\n=== Named Pipe (FIFO) Demo ===\n");
    
    const char *fifo_path = "/tmp/demo_fifo";
    
    // Create named pipe
    if (mkfifo(fifo_path, 0666) == -1) {
        perror("mkfifo");
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        unlink(fifo_path);
        return;
    } else if (pid == 0) {
        // Child process - writer
        sleep(1);  // Ensure parent is ready to read
        
        int fd = open(fifo_path, O_WRONLY);
        if (fd == -1) {
            perror("open fifo for writing");
            exit(1);
        }
        
        const char *message = "Message through named pipe";
        printf("Child: Writing to FIFO: %s\n", message);
        write(fd, message, strlen(message) + 1);
        close(fd);
        exit(0);
    } else {
        // Parent process - reader
        int fd = open(fifo_path, O_RDONLY);
        if (fd == -1) {
            perror("open fifo for reading");
            unlink(fifo_path);
            return;
        }
        
        char buffer[100];
        printf("Parent: Reading from FIFO...\n");
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("Parent: Received: %s\n", buffer);
        }
        
        close(fd);
        wait(NULL);
        unlink(fifo_path);  // Clean up
    }
}
```

**Shared Memory:**

```c
/* ipc_shared_memory.c - Shared memory IPC */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <string.h>

typedef struct {
    int counter;
    char message[100];
    int ready;
} SharedData;

void shared_memory_demo(void) {
    printf("=== Shared Memory Demo ===\n");
    
    // Create shared memory segment
    key_t key = ftok(".", 'A');  // Generate key
    int shmid = shmget(key, sizeof(SharedData), IPC_CREAT | 0666);
    
    if (shmid == -1) {
        perror("shmget");
        return;
    }
    
    // Attach shared memory
    SharedData *shared_data = (SharedData *)shmat(shmid, NULL, 0);
    if (shared_data == (SharedData *)-1) {
        perror("shmat");
        return;
    }
    
    // Initialize shared data
    shared_data->counter = 0;
    strcpy(shared_data->message, "Initial message");
    shared_data->ready = 0;
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        shmdt(shared_data);
        shmctl(shmid, IPC_RMID, NULL);
        return;
    } else if (pid == 0) {
        // Child process
        printf("Child: Modifying shared data...\n");
        
        shared_data->counter = 42;
        strcpy(shared_data->message, "Message from child process");
        shared_data->ready = 1;
        
        printf("Child: Data updated\n");
        
        // Detach shared memory
        shmdt(shared_data);
        exit(0);
    } else {
        // Parent process
        printf("Parent: Waiting for child to update data...\n");
        
        // Poll for data to be ready
        while (!shared_data->ready) {
            usleep(100000);  // Sleep 100ms
        }
        
        printf("Parent: Shared data received:\n");
        printf("  Counter: %d\n", shared_data->counter);
        printf("  Message: %s\n", shared_data->message);
        
        wait(NULL);
        
        // Detach and remove shared memory
        shmdt(shared_data);
        shmctl(shmid, IPC_RMID, NULL);
    }
}
```

**Message Queues and Semaphores:**

```c
/* ipc_msgqueue_semaphore.c - Message queues and semaphores */
#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

// Message structure
typedef struct {
    long mtype;  // Message type
    char mtext[100];  // Message data
} Message;

void message_queue_demo(void) {
    printf("=== Message Queue Demo ===\n");
    
    key_t key = ftok(".", 'B');
    int msgid = msgget(key, IPC_CREAT | 0666);
    
    if (msgid == -1) {
        perror("msgget");
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        msgctl(msgid, IPC_RMID, NULL);
        return;
    } else if (pid == 0) {
        // Child process - sender
        Message msg;
        msg.mtype = 1;  // Message type 1
        strcpy(msg.mtext, "Hello from child via message queue");
        
        printf("Child: Sending message...\n");
        if (msgsnd(msgid, &msg, strlen(msg.mtext) + 1, 0) == -1) {
            perror("msgsnd");
        } else {
            printf("Child: Message sent successfully\n");
        }
        
        exit(0);
    } else {
        // Parent process - receiver
        Message msg;
        
        printf("Parent: Waiting for message...\n");
        if (msgrcv(msgid, &msg, sizeof(msg.mtext), 1, 0) == -1) {
            perror("msgrcv");
        } else {
            printf("Parent: Received message: %s\n", msg.mtext);
        }
        
        wait(NULL);
        msgctl(msgid, IPC_RMID, NULL);  // Remove message queue
    }
}

// Semaphore operations
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

void semaphore_demo(void) {
    printf("\n=== Semaphore Demo ===\n");
    
    key_t key = ftok(".", 'C');
    int semid = semget(key, 1, IPC_CREAT | 0666);
    
    if (semid == -1) {
        perror("semget");
        return;
    }
    
    // Initialize semaphore to 1 (binary semaphore/mutex)
    union semun sem_union;
    sem_union.val = 1;
    if (semctl(semid, 0, SETVAL, sem_union) == -1) {
        perror("semctl");
        semctl(semid, 0, IPC_RMID);
        return;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        semctl(semid, 0, IPC_RMID);
        return;
    } else if (pid == 0) {
        // Child process
        struct sembuf sem_op;
        
        printf("Child: Acquiring semaphore...\n");
        sem_op.sem_num = 0;
        sem_op.sem_op = -1;  // P operation (acquire)
        sem_op.sem_flg = 0;
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
            exit(1);
        }
        
        printf("Child: Semaphore acquired, doing critical work...\n");
        sleep(3);  // Simulate work
        printf("Child: Critical work done\n");
        
        printf("Child: Releasing semaphore...\n");
        sem_op.sem_op = 1;  // V operation (release)
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
            exit(1);
        }
        
        printf("Child: Semaphore released\n");
        exit(0);
    } else {
        // Parent process
        sleep(1);  // Let child acquire first
        
        struct sembuf sem_op;
        
        printf("Parent: Trying to acquire semaphore...\n");
        sem_op.sem_num = 0;
        sem_op.sem_op = -1;  // P operation (acquire)
        sem_op.sem_flg = 0;
        
        if (semop(semid, &sem_op, 1) == -1) {
            perror("semop");
        } else {
            printf("Parent: Semaphore acquired after child released it\n");
            
            printf("Parent: Releasing semaphore...\n");
            sem_op.sem_op = 1;  // V operation (release)
            semop(semid, &sem_op, 1);
        }
        
        wait(NULL);
        semctl(semid, 0, IPC_RMID);  // Remove semaphore
    }
}
```

#### Advanced Signal Handling

```c
/* advanced_signals.c - Advanced signal handling */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

// Global flag for signal handling (sig_atomic_t is guaranteed atomic)
static volatile sig_atomic_t signal_received = 0;
static volatile sig_atomic_t child_count = 0;

// Simple signal handler
void simple_signal_handler(int sig) {
    signal_received = sig;
    // Note: Only async-signal-safe functions should be called here
    write(STDERR_FILENO, "Signal received\n", 16);
}

// Advanced signal handler with sigaction
void advanced_signal_handler(int sig, siginfo_t *info, void *context) {
    char msg[100];
    int len;
    
    switch (sig) {
        case SIGCHLD:
            // Child process terminated
            len = snprintf(msg, sizeof(msg), 
                          "Child process %d terminated\n", info->si_pid);
            write(STDERR_FILENO, msg, len);
            child_count--;
            break;
            
        case SIGINT:
            len = snprintf(msg, sizeof(msg), 
                          "SIGINT received from PID %d\n", info->si_pid);
            write(STDERR_FILENO, msg, len);
            signal_received = sig;
            break;
            
        case SIGUSR1:
            len = snprintf(msg, sizeof(msg), 
                          "SIGUSR1 received with value %d\n", info->si_value.sival_int);
            write(STDERR_FILENO, msg, len);
            break;
    }
}

void signal_handling_demo(void) {
    printf("=== Advanced Signal Handling Demo ===\n");
    
    // Set up advanced signal handling with sigaction
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_sigaction = advanced_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    
    // Install signal handlers
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    
    printf("Signal handlers installed\n");
    printf("PID: %d (send signals to this process)\n", getpid());
    
    // Create some child processes
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process
            printf("Child %d: PID %d, sleeping for %d seconds\n", 
                   i, getpid(), (i + 1) * 2);
            sleep((i + 1) * 2);
            printf("Child %d: Exiting\n", i);
            exit(i);
        } else if (pid > 0) {
            child_count++;
            printf("Created child %d with PID %d\n", i, pid);
        }
    }
    
    // Wait for signals
    printf("Parent: Waiting for signals... (Ctrl+C to interrupt)\n");
    
    while (child_count > 0 && signal_received != SIGINT) {
        pause();  // Wait for signals
        
        // Reap any zombie children
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            printf("Reaped child %d with status %d\n", pid, status);
        }
    }
    
    if (signal_received == SIGINT) {
        printf("\nInterrupted by SIGINT\n");
        // Kill any remaining children
        signal(SIGCHLD, SIG_IGN);  // Ignore SIGCHLD to avoid handlers
        kill(0, SIGTERM);  // Send SIGTERM to process group
    }
    
    printf("Signal handling demo completed\n");
}

// Signal-safe data structures and operations
typedef struct {
    volatile sig_atomic_t count;
    volatile sig_atomic_t max_count;
} SafeCounter;

SafeCounter safe_counter = {0, 100};

void counter_signal_handler(int sig) {
    if (sig == SIGUSR1) {
        if (safe_counter.count < safe_counter.max_count) {
            safe_counter.count++;
        }
    } else if (sig == SIGUSR2) {
        if (safe_counter.count > 0) {
            safe_counter.count--;
        }
    }
}

void signal_safe_demo(void) {
    printf("\n=== Signal-Safe Programming Demo ===\n");
    
    signal(SIGUSR1, counter_signal_handler);  // Increment counter
    signal(SIGUSR2, counter_signal_handler);  // Decrement counter
    
    printf("PID: %d\n", getpid());
    printf("Send SIGUSR1 to increment, SIGUSR2 to decrement\n");
    printf("Example: kill -USR1 %d\n", getpid());
    
    for (int i = 0; i < 20; i++) {
        printf("Counter: %d\n", safe_counter.count);
        sleep(1);
        
        // Self-test: send some signals
        if (i % 3 == 0) {
            kill(getpid(), SIGUSR1);
        } else if (i % 5 == 0) {
            kill(getpid(), SIGUSR2);
        }
    }
}
```

#### Real-World Example: Simple Shell

```c
/* simple_shell.c - Basic shell implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_COMMAND_LENGTH 1024
#define MAX_ARGS 64

// Built-in commands
int builtin_cd(char **args);
int builtin_exit(char **args);
int builtin_help(char **args);

// Built-in command names and functions
char *builtin_commands[] = {"cd", "exit", "help"};
int (*builtin_functions[])(char **) = {&builtin_cd, &builtin_exit, &builtin_help};

int builtin_count(void) {
    return sizeof(builtin_commands) / sizeof(char *);
}

int builtin_cd(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "cd: expected argument\n");
    } else {
        if (chdir(args[1]) != 0) {
            perror("cd");
        }
    }
    return 1;  // Continue shell
}

int builtin_exit(char **args) {
    return 0;  // Exit shell
}

int builtin_help(char **args) {
    printf("Simple Shell\n");
    printf("Built-in commands:\n");
    for (int i = 0; i < builtin_count(); i++) {
        printf("  %s\n", builtin_commands[i]);
    }
    printf("Use 'man' for information on other programs.\n");
    return 1;
}

// Parse command line into arguments
char **parse_line(char *line) {
    int position = 0;
    char **tokens = malloc(MAX_ARGS * sizeof(char *));
    char *token;
    
    if (!tokens) {
        fprintf(stderr, "allocation error\n");
        exit(EXIT_FAILURE);
    }
    
    token = strtok(line, " \t\r\n\a");
    while (token != NULL) {
        tokens[position] = token;
        position++;
        
        if (position >= MAX_ARGS) {
            fprintf(stderr, "too many arguments\n");
            break;
        }
        
        token = strtok(NULL, " \t\r\n\a");
    }
    tokens[position] = NULL;
    return tokens;
}

// Execute built-in or external command
int execute(char **args) {
    if (args[0] == NULL) {
        return 1;  // Empty command
    }
    
    // Check for built-in commands
    for (int i = 0; i < builtin_count(); i++) {
        if (strcmp(args[0], builtin_commands[i]) == 0) {
            return (*builtin_functions[i])(args);
        }
    }
    
    // Execute external command
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        if (execvp(args[0], args) == -1) {
            perror("shell");
        }
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        perror("shell");
    } else {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);
    }
    
    return 1;
}

// Main shell loop
void shell_loop(void) {
    char *line;
    char **args;
    int status = 1;
    
    do {
        printf("simple_shell> ");
        
        // Read command
        line = malloc(MAX_COMMAND_LENGTH);
        if (fgets(line, MAX_COMMAND_LENGTH, stdin) == NULL) {
            break;  // EOF
        }
        
        // Parse and execute
        args = parse_line(line);
        status = execute(args);
        
        free(line);
        free(args);
    } while (status);
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nUse 'exit' to quit the shell\n");
        printf("simple_shell> ");
        fflush(stdout);
    }
}

int main(void) {
    // Install signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    printf("Simple Shell Started (type 'help' for commands)\n");
    shell_loop();
    printf("Shell exited\n");
    
    return 0;
}
```

#### Concepts ⚙
- Process creation with fork() and program replacement with exec()
- Inter-process communication mechanisms and their use cases
- Signal handling for asynchronous events
- Process synchronization and resource sharing

#### Errors ⚠
- Race    printf("Loop optimization results:\n");
    printf("  Standard loop:     %.4f seconds (sum: %ld)\n", time1, sum1);
    printf("  Unrolled loop:     %.4f seconds (sum: %ld)\n", time2, sum2);
    printf("  Pointer-based:     %.4f seconds (sum: %ld)\n", time3, sum3);
    printf("  Unrolling speedup: %.2fx\n", time1 / time2);
    printf("  Pointer speedup:   %.2fx\n", time1 / time3);
    
    free(array);
}

// SIMD optimization example
#ifdef __SSE2__
#include <emmintrin.h>

void simd_vector_add(float *a, float *b, float *result, size_t size) {
    size_t i;
    
    // Process 4 floats at a time using SSE
    for (i = 0; i < size - 3; i += 4) {
        __m128 va = _mm_load_ps(&a[i]);
        __m128 vb = _mm_load_ps(&b[i]);
        __m128 vr = _mm_add_ps(va, vb);
        _mm_store_ps(&result[i], vr);
    }
    
    // Handle remaining elements
    for (; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}

void simd_demo(void) {
    printf("\n=== SIMD Optimization Demo ===\n");
    
    const size_t size = 1000000;
    
    // Allocate aligned memory for SIMD
    float *a = _mm_malloc(size * sizeof(float), 16);
    float *b = _mm_malloc(size * sizeof(float), 16);
    float *result1 = _mm_malloc(size * sizeof(float), 16);
    float *result2 = _mm_malloc(size * sizeof(float), 16);
    
    if (!a || !b || !result1 || !result2) {
        printf("Failed to allocate aligned memory\n");
        return;
    }
    
    // Initialize data
    for (size_t i = 0; i < size; i++) {
        a[i] = (float)i;
        b[i] = (float)i * 2.0f;
    }
    
    Timer timer;
    
    // Scalar version
    timer_start(&timer);
    for (size_t i = 0; i < size; i++) {
        result1[i] = a[i] + b[i];
    }
    double scalar_time = timer_stop(&timer);
    
    // SIMD version
    timer_start(&timer);
    simd_vector_add(a, b, result2, size);
    double simd_time = timer_stop(&timer);
    
    // Verify results match
    int results_match = 1;
    for (size_t i = 0; i < size && results_match; i++) {
        if (result1[i] != result2[i]) {
            results_match = 0;
        }
    }
    
    printf("Vector addition results:\n");
    printf("  Scalar: %.4f seconds\n", scalar_time);
    printf("  SIMD:   %.4f seconds\n", simd_time);
    printf("  Speedup: %.2fx\n", scalar_time / simd_time);
    printf("  Results match: %s\n", results_match ? "Yes" : "No");
    
    _mm_free(a);
    _mm_free(b);
    _mm_free(result1);
    _mm_free(result2);
}
#else
void simd_demo(void) {
    printf("\n=== SIMD Demo ===\n");
    printf("SSE2 not available on this platform\n");
}
#endif

int main(void) {
    compare_memory_layouts();
    loop_optimizations_demo();
    simd_demo();
    
    return 0;
}
```

---

### 22. Secure Coding Practices {#secure-coding}

**Figure Reference: [Common Security Vulnerabilities in C]**

Security is paramount in C programming due to the language's low-level nature and manual memory management.

#### Buffer Overflow Protection

```c
/* secure_coding.c - Secure coding practices */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

// UNSAFE: Buffer overflow vulnerability
void unsafe_string_copy(void) {
    char buffer[10];
    char *input = "This string is much longer than 10 characters";
    
    printf("=== UNSAFE String Copy ===\n");
    printf("Input: %s\n", input);
    
    // VULNERABILITY: No bounds checking
    strcpy(buffer, input);  // Buffer overflow!
    printf("Buffer: %s\n", buffer);  // Undefined behavior
}

// SAFE: Bounded string operations
void safe_string_copy(void) {
    char buffer[10];
    char *input = "This string is much longer than 10 characters";
    
    printf("\n=== SAFE String Copy ===\n");
    printf("Input: %s\n", input);
    
    // Safe copy with size limit
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    
    printf("Buffer: %s\n", buffer);
    printf("Truncated safely to %zu characters\n", strlen(buffer));
}

// Enhanced safe string operations
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} SafeString;

SafeString* safe_string_create(size_t capacity) {
    SafeString *str = malloc(sizeof(SafeString));
    if (!str) return NULL;
    
    str->data = malloc(capacity + 1);
    if (!str->data) {
        free(str);
        return NULL;
    }
    
    str->data[0] = '\0';
    str->size = 0;
    str->capacity = capacity;
    
    return str;
}

int safe_string_append(SafeString *str, const char *text) {
    if (!str || !text) return 0;
    
    size_t text_len = strlen(text);
    size_t available = str->capacity - str->size;
    
    if (text_len > available) {
        // Truncate to fit
        text_len = available;
    }
    
    if (text_len > 0) {
        memcpy(str->data + str->size, text, text_len);
        str->size += text_len;
        str->data[str->size] = '\0';
    }
    
    return text_len;
}

void safe_string_destroy(SafeString *str) {
    if (str) {
        free(str->data);
        free(str);
    }
}

void safe_string_demo(void) {
    printf("\n=== Safe String Implementation ===\n");
    
    SafeString *str = safe_string_create(20);
    if (!str) {
        printf("Failed to create safe string\n");
        return;
    }
    
    printf("Created safe string with capacity: %zu\n", str->capacity);
    
    int copied1 = safe_string_append(str, "Hello");
    int copied2 = safe_string_append(str, ", World!");
    int copied3 = safe_string_append(str, " This text will be truncated");
    
    printf("Append 1: copied %d chars, result: '%s'\n", copied1, str->data);
    printf("Append 2: copied %d chars, result: '%s'\n", copied2, str->data);
    printf("Append 3: copied %d chars, result: '%s'\n", copied3, str->data);
    printf("Final size: %zu/%zu\n", str->size, str->capacity);
    
    safe_string_destroy(str);
}

// Integer overflow protection
int safe_multiply(int a, int b, int *result) {
    if (!result) return 0;
    
    // Check for overflow
    if (a > 0 && b > 0 && a > INT_MAX / b) return 0;
    if (a < 0 && b < 0 && a < INT_MAX / b) return 0;
    if (a > 0 && b < 0 && b < INT_MIN / a) return 0;
    if (a < 0 && b > 0 && a < INT_MIN / b) return 0;
    
    *result = a * b;
    return 1;
}

size_t safe_array_size(size_t count, size_t element_size) {
    if (count == 0 || element_size == 0) return 0;
    
    // Check for overflow
    if (count > SIZE_MAX / element_size) {
        return 0;  // Overflow would occur
    }
    
    return count * element_size;
}

void integer_overflow_demo(void) {
    printf("\n=== Integer Overflow Protection ===\n");
    
    int result;
    
    // Safe operations
    if (safe_multiply(1000, 2000, &result)) {
        printf("1000 * 2000 = %d\n", result);
    } else {
        printf("1000 * 2000: overflow detected\n");
    }
    
    // Overflow detection
    if (safe_multiply(100000, 50000, &result)) {
        printf("100000 * 50000 = %d\n", result);
    } else {
        printf("100000 * 50000: overflow detected\n");
    }
    
    // Safe array allocation
    size_t count = 1000000;
    size_t element_size = sizeof(int);
    size_t total_size = safe_array_size(count, element_size);
    
    if (total_size > 0) {
        printf("Safe to allocate %zu bytes for %zu elements\n", total_size, count);
    } else {
        printf("Array size calculation would overflow\n");
    }
}
```

#### Format String Vulnerabilities

```c
// UNSAFE: Format string vulnerability
void unsafe_printf(const char *user_input) {
    printf("=== UNSAFE Printf ===\n");
    // VULNERABILITY: User input used directly as format string
    printf(user_input);  // Can lead to information disclosure or code execution
    printf("\n");
}

// SAFE: Proper format string usage
void safe_printf(const char *user_input) {
    printf("=== SAFE Printf ===\n");
    // Safe: User input treated as data, not format string
    printf("%s\n", user_input);
}

// Safe logging function with format validation
void safe_log(const char *level, const char *format, ...) {
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Safe: We control the format string
    printf("[%s] [%s] ", timestamp, level);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);  // Safe because we trust our format string
    va_end(args);
    
    printf("\n");
}

void format_string_demo(void) {
    printf("\n=== Format String Security Demo ===\n");
    
    // Simulated user input that could be malicious
    char *malicious_input = "User data with format specifiers: %x %x %x %n";
    char *normal_input = "Regular user message";
    
    printf("Testing with normal input:\n");
    safe_printf(normal_input);
    
    printf("\nTesting with potentially malicious input:\n");
    safe_printf(malicious_input);
    
    // Demonstrate safe logging
    safe_log("INFO", "Application started");
    safe_log("ERROR", "Failed to open file: %s", "nonexistent.txt");
    safe_log("DEBUG", "Processing %d items", 42);
}
```

#### Memory Safety and RAII-Style Programming

```c
// RAII-style resource management in C
typedef struct {
    FILE *file;
    char *buffer;
    int is_valid;
} FileResource;

FileResource* file_resource_create(const char *filename, size_t buffer_size) {
    FileResource *resource = malloc(sizeof(FileResource));
    if (!resource) return NULL;
    
    resource->file = fopen(filename, "r");
    resource->buffer = malloc(buffer_size);
    resource->is_valid = 0;
    
    if (!resource->file || !resource->buffer) {
        // Cleanup on failure
        if (resource->file) fclose(resource->file);
        if (resource->buffer) free(resource->buffer);
        free(resource);
        return NULL;
    }
    
    resource->is_valid = 1;
    return resource;
}

void file_resource_destroy(FileResource *resource) {
    if (resource) {
        if (resource->file) fclose(resource->file);
        if (resource->buffer) free(resource->buffer);
        resource->is_valid = 0;
        free(resource);
    }
}

// Automatic cleanup using GCC cleanup attribute
#ifdef __GNUC__
#define CLEANUP(func) __attribute__((cleanup(func)))

void cleanup_file(FILE **file) {
    if (file && *file) {
        fclose(*file);
        *file = NULL;
    }
}

void cleanup_free(void **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

void automatic_cleanup_demo(void) {
    printf("\n=== Automatic Cleanup Demo ===\n");
    
    // These will be automatically cleaned up when going out of scope
    FILE *file CLEANUP(cleanup_file) = fopen("test.txt", "w");
    char *buffer CLEANUP(cleanup_free) = malloc(1024);
    
    if (file && buffer) {
        fprintf(file, "Test data\n");
        strcpy(buffer, "Buffer data");
        printf("Resources created and used successfully\n");
    }
    
    printf("Resources will be automatically cleaned up\n");
    // No explicit cleanup needed - destructors called automatically
}
#else
void automatic_cleanup_demo(void) {
    printf("\n=== Automatic Cleanup Demo ===\n");
    printf("Automatic cleanup requires GCC extensions\n");
}
#endif
```

#### Input Validation and Sanitization

```c
// Comprehensive input validation
typedef enum {
    INPUT_VALID,
    INPUT_TOO_SHORT,
    INPUT_TOO_LONG,
    INPUT_INVALID_CHARS,
    INPUT_NULL
} InputValidationResult;

InputValidationResult validate_username(const char *username) {
    if (!username) return INPUT_NULL;
    
    size_t len = strlen(username);
    
    if (len < 3) return INPUT_TOO_SHORT;
    if (len > 32) return INPUT_TOO_LONG;
    
    // Check for valid characters (alphanumeric + underscore)
    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if (!isalnum(c) && c != '_') {
            return INPUT_INVALID_CHARS;
        }
    }
    
    return INPUT_VALID;
}

const char* validation_result_string(InputValidationResult result) {
    switch (result) {
        case INPUT_VALID: return "Valid";
        case INPUT_TOO_SHORT: return "Too short (minimum 3 characters)";
        case INPUT_TOO_LONG: return "Too long (maximum 32 characters)";
        case INPUT_INVALID_CHARS: return "Invalid characters (use only letters, numbers, underscore)";
        case INPUT_NULL: return "NULL input";
        default: return "Unknown error";
    }
}

// SQL injection prevention example
char* escape_sql_string(const char *input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char *escaped = malloc(len * 2 + 1);  // Worst case: every char needs escaping
    if (!escaped) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (c == '\'' || c == '"' || c == '\\') {
            escaped[j++] = '\\';  // Escape character
        }
        escaped[j++] = c;
    }
    escaped[j] = '\0';
    
    return escaped;
}

void input_validation_demo(void) {
    printf("\n=== Input Validation Demo ===\n");
    
    const char *test_usernames[] = {
        "john",
        "ab",  // Too short
        "this_username_is_way_too_long_to_be_valid",  // Too long
        "user@domain.com",  // Invalid chars
        "valid_user123",
        NULL
    };
    
    for (int i = 0; test_usernames[i]; i++) {
        InputValidationResult result = validate_username(test_usernames[i]);
        printf("Username '%s': %s\n", test_usernames[i], validation_result_string(result));
    }
    
    // SQL injection prevention demo
    const char *malicious_input = "'; DROP TABLE users; --";
    char *escaped = escape_sql_string(malicious_input);
    
    printf("\nSQL Injection Prevention:\n");
    printf("Original: %s\n", malicious_input);
    printf("Escaped:  %s\n", escaped);
    
    free(escaped);
}
```

#### Fuzzing and Security Testing

```c
/* fuzz_target.c - Example fuzzing target */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function to be fuzzed - intentionally has bugs for demonstration
int parse_packet(const uint8_t *data, size_t size) {
    if (size < 4) {
        return -1;  // Too small
    }
    
    // Parse header
    uint16_t packet_type = *(uint16_t*)data;
    uint16_t payload_size = *(uint16_t*)(data + 2);
    
    // BUG: No validation of payload_size
    if (size < 4 + payload_size) {
        return -2;  // Inconsistent size
    }
    
    // BUG: Buffer overflow if payload_size is large
    char buffer[256];
    if (payload_size > 0) {
        memcpy(buffer, data + 4, payload_size);  // Potential overflow
    }
    
    // Process packet based on type
    switch (packet_type) {
        case 1:
            printf("Login packet\n");
            break;
        case 2:
            printf("Data packet\n");
            break;
        default:
            return -3;  // Unknown type
    }
    
    return 0;
}

// LibFuzzer target function
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_packet(data, size);
    return 0;  // Always return 0 for libFuzzer
}
#endif

// Manual fuzzing for demonstration
void manual_fuzz_test(void) {
    printf("\n=== Manual Fuzzing Demo ===\n");
    
    // Test cases that might reveal bugs
    struct {
        const char *name;
        uint8_t data[512];
        size_t size;
    } test_cases[] = {
        {"Empty packet", {0}, 0},
        {"Too small", {1, 0, 5, 0}, 3},
        {"Normal login", {1, 0, 4, 0, 'u', 's', 'e', 'r'}, 8},
        {"Oversized payload", {2, 0, 255, 255, 'A'}, 5},  // payload_size = 65535
        {"Unknown type", {99, 0, 0, 0}, 4},
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        printf("Testing: %s\n", test_cases[i].name);
        
        int result = parse_packet(test_cases[i].data, test_cases[i].size);
        printf("  Result: %d\n", result);
        
        // In a real fuzzer, crashes would be detected automatically
    }
}
```

**Fuzzing Build Commands:**

```bash
# Build for AFL fuzzing
afl-gcc -o fuzz_target fuzz_target.c
echo "test input" | afl-fuzz -i input_dir -o output_dir ./fuzz_target

# Build for libFuzzer
clang -fsanitize=fuzzer,address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION fuzz_target.c -o fuzz_target
./fuzz_target

# Build with AddressSanitizer for better crash detection
gcc -fsanitize=address -g -O0 fuzz_target.c -o fuzz_target
```

#### Hardened Builds and Compiler Flags

**Security-focused compilation:**

```bash
# Security hardening flags
SECURITY_FLAGS="-D_FORTIFY_SOURCE=2 \
                -fstack-protector-strong \
                -fPIE \
                -Wformat \
                -Wformat-security \
                -Werror=format-security"

# Link-time security
SECURITY_LDFLAGS="-pie \
                  -Wl,-z,relro \
                  -Wl,-z,now \
                  -Wl,-z,noexecstack"

# Control Flow Integrity (CFI)
CFI_FLAGS="-fsanitize=cfi \
           -flto \
           -fvisibility=hidden"

# Complete secure build
gcc $SECURITY_FLAGS $SECURITY_LDFLAGS -O2 -g secure_program.c -o secure_program
```

```c
/* secure_build_demo.c - Demonstrating hardened build features */
#include <stdio.h>
#include <string.h>

// Function with potential stack buffer overflow
void vulnerable_function(const char *input) {
    char buffer[64];
    
    // Stack protector will detect overflow here
    strcpy(buffer, input);  // Dangerous!
    
    printf("Buffer: %s\n", buffer);
}

// Function demonstrating format string protection
void format_function(const char *user_input) {
    // _FORTIFY_SOURCE will catch this at compile time
    // printf(user_input);  // Compile error with -D_FORTIFY_SOURCE=2
    
    printf("%s\n", user_input);  // Safe version
}

int main(void) {
    printf("=== Secure Build Features Demo ===\n");
    
    // These would trigger security features in a hardened build:
    
    // 1. Stack protector test (would abort in hardened build)
    printf("Testing with normal input:\n");
    vulnerable_function("Normal input");
    
    // 2. Format string protection (prevented at compile time)
    format_function("User input string");
    
    printf("Program completed normally\n");
    return 0;
}
```

#### Concepts ⚙
- Buffer overflow prevention techniques
- Format string vulnerability mitigation
- Integer overflow detection and prevention
- Input validation and sanitization strategies

#### Errors ⚠
- Using unsafe string functions (strcpy, sprintf, gets)
- Trusting user input without validation
- Ignoring compiler security warnings
- Not enabling security hardening features

#### Tips 🧠
- Always use bounded string operations
- Validate all inputs at program boundaries
- Enable compiler security features in production builds
- Use static analysis tools to detect vulnerabilities

#### Tools 🔧
- **Static Analysis**: Clang Static Analyzer, Cppcheck, PVS-Studio
- **Dynamic Analysis**: AddressSanitizer, Valgrind, Dr. Memory
- **Fuzzing**: AFL, libFuzzer, Honggfuzz
- **Security Scanners**: Coverity, SonarQube, Checkmarx

---

### 23. Networking in C {#networking}

**Figure Reference: [TCP/IP Network Stack Diagram]**

Network programming in C provides direct access to sockets and network protocols.

#### TCP/UDP Socket Programming

```c
/* networking.c - Network programming examples */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>

#ifdef __linux__
#include <sys/epoll.h>
#endif

// TCP Server implementation
int create_tcp_server(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }
    
    // Configure address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }
    
    printf("TCP Server listening on port %d\n", port);
    return server_fd;
}

// TCP Client implementation
int create_tcp_client(const char *host, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return -1;
    }
    
    printf("Connected to %s:%d\n", host, port);
    return sock;
}

// Simple echo server using select()
void run_echo_server(int port) {
    int server_fd, client_socket, activity, max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Maximum clients
    #define MAX_CLIENTS 30
    int client_sockets[MAX_CLIENTS];
    char buffer[1025];
    fd_set readfds;
    
    // Initialize client sockets
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
    }
    
    server_fd = create_tcp_server(port);
    if (server_fd < 0) {
        return;
    }
    
    printf("Echo server started on port %d\n", port);
    
    while (1) {
        // Clear the socket set
        FD_ZERO(&readfds);
        
        // Add master socket to set
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;
        
        // Add child sockets to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            
            if (sd > max_sd) {
                max_sd = sd;
            }
        }
        
        // Wait for an activity on one of the sockets
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        
        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        }
        
        // If something happened on the master socket, it's an incoming connection
        if (FD_ISSET(server_fd, &readfds)) {
            if ((client_socket = accept(server_fd,
                                      (struct sockaddr *)&address,
                                      (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            
            printf("New connection: socket fd is %d, ip is: %s, port: %d\n",
                   client_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            
            // Send welcome message
            char *message = "Welcome to the echo server\r\n";
            if (send(client_socket, message, strlen(message), 0) != strlen(message)) {
                perror("send");
            }
            
            // Add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = client_socket;
                    printf("Adding to list of sockets as %d\n", i);
                    break;
                }
            }
        }
        
        // Handle IO operation on some other socket
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (FD_ISSET(sd, &readfds)) {
                int valread;
                
                // Check if it was for closing, and also read the incoming message
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    // Somebody disconnected
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    printf("Host disconnected: ip %s, port %d\n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    
                    close(sd);
                    client_sockets[    fclose(file);
    return ERR_SUCCESS;
}

void error_handling_demo(void) {
    printf("=== Error Handling Demo ===\n");
    
    // Test safe mathematical operations
    double result;
    ErrorCode err;
    
    err = safe_divide(10.0, 2.0, &result);
    if (err == ERR_SUCCESS) {
        printf("10.0 / 2.0 = %.2f\n", result);
    } else {
        print_last_error();
    }
    
    err = safe_divide(10.0, 0.0, &result);
    if (err != ERR_SUCCESS) {
        printf("Division by zero handled:\n");
        print_last_error();
    }
    
    err = safe_sqrt(-1.0, &result);
    if (err != ERR_SUCCESS) {
        printf("\nSquare root of negative number handled:\n");
        print_last_error();
    }
    
    // Test safe buffer operations
    SafeBuffer *buffer;
    err = safe_buffer_create(&buffer, 16);
    if (err == ERR_SUCCESS) {
        printf("\nBuffer created successfully\n");
        
        const char *data1 = "Hello, ";
        const char *data2 = "World!";
        
        err = safe_buffer_append(buffer, data1, strlen(data1));
        if (err == ERR_SUCCESS) {
            err = safe_buffer_append(buffer, data2, strlen(data2));
        }
        
        if (err == ERR_SUCCESS) {
            printf("Buffer content: %.*s\n", (int)buffer->size, (char*)buffer->data);
            printf("Buffer size: %zu, capacity: %zu\n", buffer->size, buffer->capacity);
        }
        
        safe_buffer_destroy(buffer);
    }
    
    // Test file operations
    char *content;
    size_t file_size;
    
    // Try to read a non-existent file
    err = safe_file_read("nonexistent.txt", &content, &file_size);
    if (err != ERR_SUCCESS) {
        printf("\nFile read error handled:\n");
        print_last_error();
    }
    
    // Create a test file and read it
    FILE *test_file = fopen("test.txt", "w");
    if (test_file) {
        fprintf(test_file, "This is a test file for error handling demo.\n");
        fclose(test_file);
        
        err = safe_file_read("test.txt", &content, &file_size);
        if (err == ERR_SUCCESS) {
            printf("\nFile read successfully:\n");
            printf("Size: %zu bytes\n", file_size);
            printf("Content: %s", content);
            free(content);
        }
        
        remove("test.txt");  // Cleanup
    }
}

// Exception-like error handling using setjmp/longjmp
static jmp_buf error_jmp_buf;
static ErrorInfo exception_error;

#define TRY if (setjmp(error_jmp_buf) == 0) {
#define CATCH } else {
#define THROW(code, msg) \
    do { \
        set_exception_error((code), (msg), __FILE__, __LINE__, __func__); \
        longjmp(error_jmp_buf, 1); \
    } while(0)
#define END_TRY }

void set_exception_error(ErrorCode code, const char *message,
                        const char *file, int line, const char *function) {
    exception_error.code = code;
    snprintf(exception_error.message, sizeof(exception_error.message), "%s", message);
    snprintf(exception_error.file, sizeof(exception_error.file), "%s",
             strrchr(file, '/') ? strrchr(file, '/') + 1 : file);
    exception_error.line = line;
    snprintf(exception_error.function, sizeof(exception_error.function), "%s", function);
}

void risky_operation(int value) {
    if (value < 0) {
        THROW(ERR_INVALID_ARGUMENT, "Value cannot be negative");
    }
    
    if (value == 0) {
        THROW(ERR_INVALID_ARGUMENT, "Value cannot be zero");
    }
    
    printf("Processing value: %d\n", value);
    
    if (value > 100) {
        THROW(ERR_INVALID_ARGUMENT, "Value too large");
    }
    
    printf("Value processed successfully\n");
}

void exception_handling_demo(void) {
    printf("\n=== Exception-style Error Handling Demo ===\n");
    
    int test_values[] = {50, -1, 0, 150};
    int num_values = sizeof(test_values) / sizeof(test_values[0]);
    
    for (int i = 0; i < num_values; i++) {
        printf("\nTesting value: %d\n", test_values[i]);
        
        TRY {
            risky_operation(test_values[i]);
        }
        CATCH {
            printf("Exception caught:\n");
            printf("  Code: %d\n", exception_error.code);
            printf("  Message: %s\n", exception_error.message);
            printf("  Location: %s:%d in %s()\n",
                   exception_error.file, exception_error.line, exception_error.function);
        }
        END_TRY;
    }
}

// Signal handling for crash recovery
static volatile sig_atomic_t signal_received = 0;
static int signal_number = 0;

void signal_handler(int sig) {
    signal_received = 1;
    signal_number = sig;
}

void install_signal_handlers(void) {
    signal(SIGSEGV, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGABRT, signal_handler);
    #ifdef SIGBUS
    signal(SIGBUS, signal_handler);
    #endif
}

void signal_handling_demo(void) {
    printf("\n=== Signal Handling Demo ===\n");
    
    install_signal_handlers();
    
    printf("Signal handlers installed\n");
    printf("Testing controlled scenarios...\n");
    
    // Test division by zero (may generate SIGFPE on some systems)
    signal_received = 0;
    
    // Note: Modern systems may not generate SIGFPE for floating point division by zero
    printf("Testing division by zero handling...\n");
    volatile double a = 1.0;
    volatile double b = 0.0;
    volatile double result = a / b;  // May or may not generate signal
    
    if (signal_received) {
        printf("Signal %d caught during division by zero\n", signal_number);
    } else {
        printf("No signal generated (result: %f)\n", result);
    }
    
    printf("Signal handling test completed\n");
}

// Debug logging system
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4,
    LOG_LEVEL_FATAL = 5
} LogLevel;

static LogLevel current_log_level = LOG_LEVEL_INFO;
static FILE *log_file = NULL;

const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_TRACE: return "TRACE";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

void log_init(const char *filename, LogLevel level) {
    current_log_level = level;
    
    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", filename);
            log_file = stderr;
        }
    } else {
        log_file = stderr;
    }
}

void log_cleanup(void) {
    if (log_file && log_file != stderr && log_file != stdout) {
        fclose(log_file);
    }
    log_file = NULL;
}

void log_message(LogLevel level, const char *file, int line, const char *function,
                const char *format, ...) {
    if (level < current_log_level || !log_file) {
        return;
    }
    
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    // Print timestamp and level
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
            log_level_to_string(level));
    
    // Print location info for debug levels
    if (level <= LOG_LEVEL_DEBUG) {
        const char *basename = strrchr(file, '/');
        if (!basename) basename = strrchr(file, '\\');
        if (!basename) basename = file - 1;
        fprintf(log_file, "[%s:%d:%s] ", basename + 1, line, function);
    }
    
    // Print message
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}

// Logging macros
#define LOG_TRACE(fmt, ...) log_message(LOG_LEVEL_TRACE, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) log_message(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

void logging_demo(void) {
    printf("\n=== Logging System Demo ===\n");
    
    log_init("debug.log", LOG_LEVEL_TRACE);
    
    LOG_TRACE("This is a trace message");
    LOG_DEBUG("Debug message with value: %d", 42);
    LOG_INFO("Application started successfully");
    LOG_WARN("This is a warning message");
    LOG_ERROR("An error occurred: %s", "example error");
    LOG_FATAL("Fatal error - application terminating");
    
    printf("Log messages written to debug.log\n");
    
    // Change log level
    current_log_level = LOG_LEVEL_WARN;
    printf("Changed log level to WARN\n");
    
    LOG_DEBUG("This debug message won't appear");
    LOG_INFO("This info message won't appear");
    LOG_WARN("This warning will appear");
    LOG_ERROR("This error will appear");
    
    log_cleanup();
}

// Memory debugging helpers
#ifdef DEBUG_MEMORY
static size_t total_allocated = 0;
static size_t allocation_count = 0;

void* debug_malloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size + sizeof(size_t));
    if (ptr) {
        *(size_t*)ptr = size;
        total_allocated += size;
        allocation_count++;
        printf("MALLOC: %zu bytes at %p (%s:%d) [Total: %zu, Count: %zu]\n",
               size, (char*)ptr + sizeof(size_t), file, line,
               total_allocated, allocation_count);
        return (char*)ptr + sizeof(size_t);
    }
    return NULL;
}

void debug_free(void *ptr, const char *file, int line) {
    if (ptr) {
        void *real_ptr = (char*)ptr - sizeof(size_t);
        size_t size = *(size_t*)real_ptr;
        total_allocated -= size;
        allocation_count--;
        printf("FREE: %zu bytes at %p (%s:%d) [Total: %zu, Count: %zu]\n",
               size, ptr, file, line, total_allocated, allocation_count);
        free(real_ptr);
    }
}

#define malloc(size) debug_malloc(size, __FILE__, __LINE__)
#define free(ptr) debug_free(ptr, __FILE__, __LINE__)
#endif

void memory_debugging_demo(void) {
    printf("\n=== Memory Debugging Demo ===\n");
    
#ifdef DEBUG_MEMORY
    printf("Memory debugging enabled\n");
    
    char *buffer1 = malloc(100);
    char *buffer2 = malloc(200);
    char *buffer3 = malloc(50);
    
    free(buffer2);
    buffer2 = malloc(150);
    
    free(buffer1);
    free(buffer2);
    free(buffer3);
    
    printf("Final allocation count: %zu, total: %zu\n", 
           allocation_count, total_allocated);
#else
    printf("Memory debugging not enabled (compile with -DDEBUG_MEMORY)\n");
    
    // Regular allocation for demo
    char *buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Test data");
        printf("Allocated and used buffer: %s\n", buffer);
        free(buffer);
    }
#endif
}

// Assertion macros with enhanced information
#ifdef DEBUG
#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ASSERTION FAILED: %s\n", #condition); \
            fprintf(stderr, "  File: %s:%d\n", __FILE__, __LINE__); \
            fprintf(stderr, "  Function: %s\n", __func__); \
            abort(); \
        } \
    } while(0)

#define ASSERT_MSG(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ASSERTION FAILED: %s\n", #condition); \
            fprintf(stderr, "  Message: %s\n", message); \
            fprintf(stderr, "  File: %s:%d\n", __FILE__, __LINE__); \
            fprintf(stderr, "  Function: %s\n", __func__); \
            abort(); \
        } \
    } while(0)
#else
#define ASSERT(condition) ((void)0)
#define ASSERT_MSG(condition, message) ((void)0)
#endif

void assertion_demo(void) {
    printf("\n=== Assertion Demo ===\n");
    
#ifdef DEBUG
    printf("Debug assertions enabled\n");
    
    int x = 10;
    ASSERT(x > 0);
    ASSERT_MSG(x < 100, "x should be less than 100");
    
    printf("All assertions passed\n");
    
    // This would abort the program:
    // ASSERT(x < 0);
#else
    printf("Debug assertions disabled (compile with -DDEBUG)\n");
#endif
}

int main(void) {
    error_handling_demo();
    exception_handling_demo();
    signal_handling_demo();
    logging_demo();
    memory_debugging_demo();
    assertion_demo();
    
    return 0;
}
```

#### Debugging Workflows and Tools

**GDB Debugging Session Example:**

```bash
# Compile with debugging symbols
gcc -g -O0 -DDEBUG -DDEBUG_MEMORY error_handling.c -o debug_program

# Start GDB session
gdb ./debug_program

# Common GDB commands:
(gdb) break main                    # Set breakpoint at main
(gdb) break error_handling.c:123   # Set breakpoint at line 123
(gdb) run                          # Start program execution
(gdb) continue                     # Continue execution
(gdb) step                         # Step into function calls
(gdb) next                         # Step over function calls
(gdb) print variable_name          # Print variable value
(gdb) backtrace                    # Show call stack
(gdb) frame 2                      # Switch to stack frame 2
(gdb) info locals                  # Show local variables
(gdb) watch global_var             # Set watchpoint on variable
(gdb) disassemble                  # Show assembly code
```

**AddressSanitizer (ASan) Usage:**

```c
/* asan_example.c - AddressSanitizer demonstration */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function with intentional bugs for ASan to catch
void demonstrate_memory_bugs(void) {
    printf("=== AddressSanitizer Demo ===\n");
    
    // 1. Heap buffer overflow
    char *buffer = malloc(10);
    strcpy(buffer, "This string is too long!");  // Buffer overflow
    printf("Buffer: %s\n", buffer);
    free(buffer);
    
    // 2. Use after free
    char *ptr = malloc(20);
    free(ptr);
    strcpy(ptr, "Use after free!");  // Use after free
    
    // 3. Double free
    char *another_ptr = malloc(30);
    free(another_ptr);
    free(another_ptr);  // Double free
    
    // 4. Memory leak (not freed)
    char *leaked = malloc(100);
    strcpy(leaked, "This memory will leak");
    // Missing free(leaked);
}
```

**Compilation and execution with sanitizers:**

```bash
# Compile with AddressSanitizer
gcc -fsanitize=address -g -O0 asan_example.c -o asan_program

# Compile with UndefinedBehaviorSanitizer
gcc -fsanitize=undefined -g -O0 program.c -o ubsan_program

# Compile with ThreadSanitizer
gcc -fsanitize=thread -g -O0 threaded_program.c -o tsan_program

# Run with sanitizer options
ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 ./asan_program
```

**Valgrind Memory Analysis:**

```bash
# Memory leak detection
valgrind --tool=memcheck --leak-check=full ./program

# Cache profiling
valgrind --tool=cachegrind ./program

# Heap profiling  
valgrind --tool=massif ./program

# Thread error detection
valgrind --tool=helgrind ./threaded_program
```

#### Testing and Coverage

**Simple Unit Testing Framework:**

```c
/* test_framework.c - Simple unit testing framework */
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

static int tests_run = 0;
static int tests_passed = 0;
static jmp_buf test_env;

#define TEST(name) \
    void test_##name(void); \
    void run_test_##name(void) { \
        printf("Running test: %s ... ", #name); \
        tests_run++; \
        if (setjmp(test_env) == 0) { \
            test_##name(); \
            tests_passed++; \
            printf("PASSED\n"); \
        } else { \
            printf("FAILED\n"); \
        } \
    } \
    void test_##name(void)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("\n  Assertion failed: expected %d, got %d\n", (expected), (actual)); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("\n  Assertion failed: expected '%s', got '%s'\n", (expected), (actual)); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("\n  Assertion failed: %s is false\n", #condition); \
            longjmp(test_env, 1); \
        } \
    } while(0)

#define RUN_TEST(name) run_test_##name()

// Example tests for our error handling functions
TEST(safe_divide_success) {
    double result;
    ErrorCode err = safe_divide(10.0, 2.0, &result);
    ASSERT_EQ(ERR_SUCCESS, err);
    ASSERT_TRUE(result == 5.0);
}

TEST(safe_divide_by_zero) {
    double result;
    ErrorCode err = safe_divide(10.0, 0.0, &result);
    ASSERT_EQ(ERR_INVALID_ARGUMENT, err);
}

TEST(safe_sqrt_positive) {
    double result;
    ErrorCode err = safe_sqrt(16.0, &result);
    ASSERT_EQ(ERR_SUCCESS, err);
    ASSERT_TRUE(result == 4.0);
}

TEST(safe_sqrt_negative) {
    double result;
    ErrorCode err = safe_sqrt(-1.0, &result);
    ASSERT_EQ(ERR_INVALID_ARGUMENT, err);
}

void run_all_tests(void) {
    printf("=== Running Unit Tests ===\n");
    
    RUN_TEST(safe_divide_success);
    RUN_TEST(safe_divide_by_zero);
    RUN_TEST(safe_sqrt_positive);
    RUN_TEST(safe_sqrt_negative);
    
    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("Success rate: %.1f%%\n", 
           tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0);
}
```

**Coverage Analysis:**

```bash
# Compile with coverage flags
gcc --coverage -g -O0 program.c -o program

# Run program to generate coverage data
./program

# Generate coverage report
gcov program.c

# Generate HTML coverage report with lcov
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html

# View coverage report
open coverage_html/index.html
```

#### Concepts ⚙
- Error propagation strategies and error codes
- Exception-like handling with setjmp/longjmp
- Signal handling for crash recovery
- Memory debugging and leak detection

#### Errors ⚠
- Inconsistent error handling patterns
- Resource leaks in error paths
- Signal handler safety violations
- Race conditions in error reporting

#### Tips 🧠
- Use consistent error codes throughout your application
- Always check return values from system calls
- Implement proper cleanup in error paths
- Use static analysis tools to catch bugs early

#### Tools 🔧
- **GDB/LLDB**: Interactive debuggers
- **AddressSanitizer**: Memory error detection
- **Valgrind**: Memory analysis and profiling
- **Static analyzers**: Clang Static Analyzer, Cppcheck
- **Coverage tools**: gcov, lcov, llvm-cov

---

### 21. Performance Optimization {#performance}

Performance optimization in C requires understanding of hardware characteristics, compiler behavior, and algorithmic complexity.

#### Profiling and Performance Analysis

**Figure Reference: [Performance Optimization Workflow Diagram]**

```c
/* performance_optimization.c - Performance optimization techniques */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// High-resolution timing utilities
typedef struct {
    struct timespec start;
    struct timespec end;
} Timer;

void timer_start(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->start);
}

double timer_stop(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->end);
    
    double start_time = timer->start.tv_sec + timer->start.tv_nsec / 1e9;
    double end_time = timer->end.tv_sec + timer->end.tv_nsec / 1e9;
    
    return end_time - start_time;
}

// Cache-friendly data structures
typedef struct {
    int *data;
    size_t size;
    size_t capacity;
} IntArray;

// Array of Structures (AoS) - cache unfriendly for some operations
typedef struct {
    float x, y, z;
    int id;
    char padding[4];  // Explicit padding
} Point3D_AoS;

// Structure of Arrays (SoA) - cache friendly
typedef struct {
    float *x;
    float *y;
    float *z;
    int *id;
    size_t count;
} Point3D_SoA;

void compare_memory_layouts(void) {
    printf("=== Memory Layout Performance Comparison ===\n");
    
    const size_t num_points = 1000000;
    Timer timer;
    
    // Allocate AoS
    Point3D_AoS *aos_points = malloc(num_points * sizeof(Point3D_AoS));
    if (!aos_points) {
        printf("Failed to allocate AoS points\n");
        return;
    }
    
    // Allocate SoA
    Point3D_SoA soa_points = {0};
    soa_points.x = malloc(num_points * sizeof(float));
    soa_points.y = malloc(num_points * sizeof(float));
    soa_points.z = malloc(num_points * sizeof(float));
    soa_points.id = malloc(num_points * sizeof(int));
    soa_points.count = num_points;
    
    if (!soa_points.x || !soa_points.y || !soa_points.z || !soa_points.id) {
        printf("Failed to allocate SoA points\n");
        free(aos_points);
        return;
    }
    
    // Initialize data
    for (size_t i = 0; i < num_points; i++) {
        aos_points[i].x = (float)i;
        aos_points[i].y = (float)i * 2.0f;
        aos_points[i].z = (float)i * 3.0f;
        aos_points[i].id = (int)i;
        
        soa_points.x[i] = (float)i;
        soa_points.y[i] = (float)i * 2.0f;
        soa_points.z[i] = (float)i * 3.0f;
        soa_points.id[i] = (int)i;
    }
    
    // Test: Sum all X coordinates (cache friendly operation)
    double sum_aos = 0.0, sum_soa = 0.0;
    
    // AoS version - poor cache usage
    timer_start(&timer);
    for (size_t i = 0; i < num_points; i++) {
        sum_aos += aos_points[i].x;
    }
    double aos_time = timer_stop(&timer);
    
    // SoA version - better cache usage
    timer_start(&timer);
    for (size_t i = 0; i < num_points; i++) {
        sum_soa += soa_points.x[i];
    }
    double soa_time = timer_stop(&timer);
    
    printf("Summing X coordinates:\n");
    printf("  AoS: %.4f seconds (sum: %.0f)\n", aos_time, sum_aos);
    printf("  SoA: %.4f seconds (sum: %.0f)\n", soa_time, sum_soa);
    printf("  SoA speedup: %.2fx\n", aos_time / soa_time);
    
    printf("\nMemory usage:\n");
    printf("  AoS: %zu bytes per point (%zu total)\n", 
           sizeof(Point3D_AoS), num_points * sizeof(Point3D_AoS));
    printf("  SoA: %zu bytes per point (%zu total)\n",
           sizeof(float) * 3 + sizeof(int), 
           num_points * (sizeof(float) * 3 + sizeof(int)));
    
    // Cleanup
    free(aos_points);
    free(soa_points.x);
    free(soa_points.y);
    free(soa_points.z);
    free(soa_points.id);
}

// Loop optimization techniques
void loop_optimizations_demo(void) {
    printf("\n=== Loop Optimization Demo ===\n");
    
    const size_t size = 10000000;
    int *array = malloc(size * sizeof(int));
    if (!array) return;
    
    Timer timer;
    
    // Initialize array
    for (size_t i = 0; i < size; i++) {
        array[i] = (int)(i % 1000);
    }
    
    // Unoptimized loop
    timer_start(&timer);
    volatile long sum1 = 0;
    for (size_t i = 0; i < size; i++) {
        sum1 += array[i];
    }
    double time1 = timer_stop(&timer);
    
    // Loop unrolling
    timer_start(&timer);
    volatile long sum2 = 0;
    size_t i;
    for (i = 0; i < size - 3; i += 4) {
        sum2 += array[i] + array[i+1] + array[i+2] + array[i+3];
    }
    // Handle remaining elements
    for (; i < size; i++) {
        sum2 += array[i];
    }
    double time2 = timer_stop(&timer);
    
    // Loop with reduced function calls
    timer_start(&timer);
    volatile long sum3 = 0;
    int *ptr = array;
    int *end = array + size;
    while (ptr < end) {
        sum3 += *ptr++;
    }
    double time3 = timer_stop(&timer);
    
    printf("Loop optimization results:\n");
    printf("  Standard loop:     %.4f seconds (sum: %ld)\n", time1, sum1);
    printf("  Unrolled loop:     %.4f seconds (sum: %ld)\n", time2, sum2);
    printf("  Pointer-based:     %.4f seconds (sum: %l// Boyer-Moore string search algorithm
#define ALPHABET_SIZE 256

void build_bad_char_table(const char *pattern, int pattern_len, int bad_char[ALPHABET_SIZE]) {
    // Initialize all entries as -1
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        bad_char[i] = -1;
    }
    
    // Store the last occurrence of each character
    for (int i = 0; i < pattern_len; i++) {
        bad_char[(unsigned char)pattern[i]] = i;
    }
}

char* boyer_moore_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    int bad_char[ALPHABET_SIZE];
    build_bad_char_table(pattern, pattern_len, bad_char);
    
    int shift = 0;  // Shift of pattern with respect to text
    
    while (shift <= text_len - pattern_len) {
        int j = pattern_len - 1;
        
        // Match pattern from right to left
        while (j >= 0 && pattern[j] == text[shift + j]) {
            j--;
        }
        
        // Pattern found
        if (j < 0) {
            return (char*)(text + shift);
        }
        
        // Calculate shift based on bad character heuristic
        int bad_char_shift = j - bad_char[(unsigned char)text[shift + j]];
        shift += (bad_char_shift > 1) ? bad_char_shift : 1;
    }
    
    return NULL;  // Pattern not found
}

// KMP (Knuth-Morris-Pratt) string search
void compute_lps_array(const char *pattern, int pattern_len, int *lps) {
    int len = 0;  // Length of previous longest prefix suffix
    lps[0] = 0;   // lps[0] is always 0
    int i = 1;
    
    while (i < pattern_len) {
        if (pattern[i] == pattern[len]) {
            len++;
            lps[i] = len;
            i++;
        } else {
            if (len != 0) {
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

char* kmp_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    // Create LPS array
    int *lps = malloc(pattern_len * sizeof(int));
    if (!lps) return NULL;
    
    compute_lps_array(pattern, pattern_len, lps);
    
    int i = 0;  // Index for text
    int j = 0;  // Index for pattern
    
    while (i < text_len) {
        if (pattern[j] == text[i]) {
            i++;
            j++;
        }
        
        if (j == pattern_len) {
            free(lps);
            return (char*)(text + i - j);
        } else if (i < text_len && pattern[j] != text[i]) {
            if (j != 0) {
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }
    
    free(lps);
    return NULL;  // Pattern not found
}

// Rabin-Karp rolling hash search
#define PRIME 101

char* rabin_karp_search(const char *text, const char *pattern) {
    if (!text || !pattern || !*pattern) return NULL;
    
    int text_len = strlen(text);
    int pattern_len = strlen(pattern);
    
    if (pattern_len > text_len) return NULL;
    
    int pattern_hash = 0;  // Hash value for pattern
    int text_hash = 0;     // Hash value for current window of text
    int h = 1;             // Hash multiplier
    
    // Calculate h = pow(d, pattern_len-1) % PRIME
    for (int i = 0; i < pattern_len - 1; i++) {
        h = (h * ALPHABET_SIZE) % PRIME;
    }
    
    // Calculate hash for pattern and first window
    for (int i = 0; i < pattern_len; i++) {
        pattern_hash = (ALPHABET_SIZE * pattern_hash + pattern[i]) % PRIME;
        text_hash = (ALPHABET_SIZE * text_hash + text[i]) % PRIME;
    }
    
    // Slide the pattern over text one by one
    for (int i = 0; i <= text_len - pattern_len; i++) {
        // Check if hash values match
        if (pattern_hash == text_hash) {
            // Check characters one by one
            int j;
            for (j = 0; j < pattern_len; j++) {
                if (text[i + j] != pattern[j]) {
                    break;
                }
            }
            
            if (j == pattern_len) {
                return (char*)(text + i);
            }
        }
        
        // Calculate hash for next window
        if (i < text_len - pattern_len) {
            text_hash = (ALPHABET_SIZE * (text_hash - text[i] * h) + text[i + pattern_len]) % PRIME;
            
            // Convert negative hash to positive
            if (text_hash < 0) {
                text_hash += PRIME;
            }
        }
    }
    
    return NULL;
}

void string_search_comparison(void) {
    printf("=== String Search Algorithm Comparison ===\n");
    
    const char *text = "ABABDABACDABABCABCABCABCABC";
    const char *pattern = "ABABCABCABCABC";
    
    printf("Text: %s\n", text);
    printf("Pattern: %s\n", pattern);
    
    // Test different algorithms
    char *result1 = strstr(text, pattern);
    char *result2 = boyer_moore_search(text, pattern);
    char *result3 = kmp_search(text, pattern);
    char *result4 = rabin_karp_search(text, pattern);
    
    printf("\nSearch Results:\n");
    printf("strstr:      %s\n", result1 ? "Found" : "Not found");
    printf("Boyer-Moore: %s\n", result2 ? "Found" : "Not found");
    printf("KMP:         %s\n", result3 ? "Found" : "Not found");
    printf("Rabin-Karp:  %s\n", result4 ? "Found" : "Not found");
    
    if (result1) {
        printf("Position: %ld\n", result1 - text);
    }
    
    // Performance characteristics
    printf("\nAlgorithm Characteristics:\n");
    printf("• strstr:      O(nm) worst case, optimized in practice\n");
    printf("• Boyer-Moore: O(n/m) average, O(nm) worst case\n");
    printf("• KMP:         O(n+m) guaranteed, good for repeated searches\n");
    printf("• Rabin-Karp:  O(n+m) average, O(nm) worst case with collisions\n");
}

// Advanced string manipulation functions
typedef struct {
    char **strings;
    size_t count;
    size_t capacity;
} StringArray;

StringArray* string_array_create(size_t initial_capacity) {
    StringArray *arr = malloc(sizeof(StringArray));
    if (!arr) return NULL;
    
    arr->strings = malloc(initial_capacity * sizeof(char*));
    if (!arr->strings) {
        free(arr);
        return NULL;
    }
    
    arr->count = 0;
    arr->capacity = initial_capacity;
    return arr;
}

int string_array_add(StringArray *arr, const char *str) {
    if (!arr || !str) return 0;
    
    // Resize if needed
    if (arr->count >= arr->capacity) {
        size_t new_capacity = arr->capacity * 2;
        char **new_strings = realloc(arr->strings, new_capacity * sizeof(char*));
        if (!new_strings) return 0;
        
        arr->strings = new_strings;
        arr->capacity = new_capacity;
    }
    
    // Duplicate string
    arr->strings[arr->count] = malloc(strlen(str) + 1);
    if (!arr->strings[arr->count]) return 0;
    
    strcpy(arr->strings[arr->count], str);
    arr->count++;
    return 1;
}

void string_array_destroy(StringArray *arr) {
    if (!arr) return;
    
    for (size_t i = 0; i < arr->count; i++) {
        free(arr->strings[i]);
    }
    free(arr->strings);
    free(arr);
}

// Advanced tokenization
StringArray* advanced_split(const char *str, const char *delimiters, int max_tokens) {
    if (!str || !delimiters) return NULL;
    
    StringArray *result = string_array_create(16);
    if (!result) return NULL;
    
    char *str_copy = malloc(strlen(str) + 1);
    if (!str_copy) {
        string_array_destroy(result);
        return NULL;
    }
    strcpy(str_copy, str);
    
    char *token = strtok(str_copy, delimiters);
    int token_count = 0;
    
    while (token && (max_tokens <= 0 || token_count < max_tokens)) {
        if (!string_array_add(result, token)) {
            break;
        }
        token = strtok(NULL, delimiters);
        token_count++;
    }
    
    free(str_copy);
    return result;
}

// String trimming with character set
char* trim_charset(char *str, const char *charset) {
    if (!str || !charset) return str;
    
    char *start = str;
    char *end = str + strlen(str) - 1;
    
    // Trim leading characters
    while (*start && strchr(charset, *start)) {
        start++;
    }
    
    // Trim trailing characters
    while (end > start && strchr(charset, *end)) {
        end--;
    }
    
    end[1] = '\0';
    
    // Move trimmed string to beginning if necessary
    if (start != str) {
        memmove(str, start, end - start + 2);
    }
    
    return str;
}

// Case-insensitive string comparison with locale support
int strcasecmp_locale(const char *s1, const char *s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    
    while (*s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        
        if (c1 != c2) {
            return c1 - c2;
        }
        
        s1++;
        s2++;
    }
    
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

// String replacement with limit
char* string_replace(const char *str, const char *old_substr, 
                    const char *new_substr, int max_replacements) {
    if (!str || !old_substr || !new_substr) return NULL;
    
    size_t old_len = strlen(old_substr);
    size_t new_len = strlen(new_substr);
    size_t str_len = strlen(str);
    
    if (old_len == 0) return strdup(str);
    
    // Count occurrences
    int count = 0;
    const char *pos = str;
    while ((pos = strstr(pos, old_substr)) && (max_replacements <= 0 || count < max_replacements)) {
        count++;
        pos += old_len;
    }
    
    if (count == 0) return strdup(str);
    
    // Calculate new string size
    size_t new_str_len = str_len + count * (new_len - old_len);
    char *result = malloc(new_str_len + 1);
    if (!result) return NULL;
    
    // Perform replacements
    char *dest = result;
    const char *src = str;
    int replacements_made = 0;
    
    while ((pos = strstr(src, old_substr)) && (max_replacements <= 0 || replacements_made < max_replacements)) {
        // Copy text before match
        size_t prefix_len = pos - src;
        memcpy(dest, src, prefix_len);
        dest += prefix_len;
        
        // Copy replacement
        memcpy(dest, new_substr, new_len);
        dest += new_len;
        
        src = pos + old_len;
        replacements_made++;
    }
    
    // Copy remaining text
    strcpy(dest, src);
    
    return result;
}

void advanced_string_functions_demo(void) {
    printf("\n=== Advanced String Functions Demo ===\n");
    
    // Test advanced split
    const char *csv_line = "apple,banana,cherry;date:elderberry|fig,grape";
    StringArray *tokens = advanced_split(csv_line, ",;:|", 0);
    
    printf("Original: %s\n", csv_line);
    printf("Split result (%zu tokens):\n", tokens->count);
    for (size_t i = 0; i < tokens->count; i++) {
        printf("  [%zu]: '%s'\n", i, tokens->strings[i]);
    }
    
    string_array_destroy(tokens);
    
    // Test trimming
    char test_str[] = "  \t\n  Hello, World!  \t\n  ";
    printf("\nTrimming test:\n");
    printf("Before: |%s|\n", test_str);
    trim_charset(test_str, " \t\n");
    printf("After:  |%s|\n", test_str);
    
    // Test case-insensitive comparison
    printf("\nCase-insensitive comparison:\n");
    printf("strcasecmp_locale('Hello', 'HELLO') = %d\n", 
           strcasecmp_locale("Hello", "HELLO"));
    printf("strcasecmp_locale('Apple', 'Banana') = %d\n", 
           strcasecmp_locale("Apple", "Banana"));
    
    // Test string replacement
    const char *original = "The quick brown fox jumps over the lazy dog. The fox is quick.";
    char *replaced = string_replace(original, "fox", "cat", 2);
    
    printf("\nString replacement:\n");
    printf("Original: %s\n", original);
    printf("Replaced: %s\n", replaced);
    
    free(replaced);
}

// Unicode and multibyte string handling
#include <locale.h>
#include <wchar.h>
#include <wctype.h>

void unicode_string_demo(void) {
    printf("\n=== Unicode String Handling Demo ===\n");
    
    // Set locale for proper unicode handling
    setlocale(LC_ALL, "");
    
    // Wide character strings
    wchar_t wide_str[] = L"Hello, 世界! 🌍";
    printf("Wide string length: %zu characters\n", wcslen(wide_str));
    
    // Convert to multibyte string
    size_t mb_len = wcstombs(NULL, wide_str, 0);
    if (mb_len != (size_t)-1) {
        char *mb_str = malloc(mb_len + 1);
        if (mb_str) {
            wcstombs(mb_str, wide_str, mb_len + 1);
            printf("Multibyte string: %s\n", mb_str);
            printf("Multibyte length: %zu bytes\n", strlen(mb_str));
            free(mb_str);
        }
    }
    
    // Wide character manipulation
    wchar_t *pos = wcschr(wide_str, L'世');
    if (pos) {
        printf("Found '世' at position: %ld\n", pos - wide_str);
    }
    
    // Character classification for wide characters
    wchar_t test_chars[] = {L'A', L'中', L'5', L'!', L'🌍', 0};
    printf("\nWide character classification:\n");
    for (int i = 0; test_chars[i]; i++) {
        wchar_t wc = test_chars[i];
        printf("'%lc': alpha=%d, digit=%d, punct=%d\n", 
               (wint_t)wc, iswalpha(wc), iswdigit(wc), iswpunct(wc));
    }
}

// String hashing and fingerprinting
typedef struct {
    uint32_t hash;
    uint16_t length;
    char data[];
} HashedString;

// FNV-1a hash algorithm
uint32_t fnv1a_hash(const char *str, size_t len) {
    const uint32_t FNV_PRIME = 0x01000193;
    const uint32_t FNV_OFFSET_BASIS = 0x811c9dc5;
    
    uint32_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)str[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

HashedString* create_hashed_string(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    if (len > UINT16_MAX) return NULL;  // Length limit
    
    HashedString *hs = malloc(sizeof(HashedString) + len + 1);
    if (!hs) return NULL;
    
    hs->length = (uint16_t)len;
    hs->hash = fnv1a_hash(str, len);
    strcpy(hs->data, str);
    
    return hs;
}

int hashed_string_compare(const HashedString *hs1, const HashedString *hs2) {
    if (!hs1 || !hs2) return hs1 ? 1 : (hs2 ? -1 : 0);
    
    // Quick hash comparison
    if (hs1->hash != hs2->hash || hs1->length != hs2->length) {
        return hs1->hash < hs2->hash ? -1 : 1;
    }
    
    // Fallback to string comparison (handle hash collisions)
    return strcmp(hs1->data, hs2->data);
}

void string_hashing_demo(void) {
    printf("\n=== String Hashing Demo ===\n");
    
    const char *test_strings[] = {
        "hello",
        "world",
        "Hello",  // Different case
        "hello",  // Duplicate
        "programming",
        NULL
    };
    
    printf("String hashing comparison:\n");
    
    for (int i = 0; test_strings[i]; i++) {
        HashedString *hs = create_hashed_string(test_strings[i]);
        if (hs) {
            printf("'%s': hash=0x%08x, length=%u\n", 
                   hs->data, hs->hash, hs->length);
            free(hs);
        }
    }
    
    // Demonstrate hash collision detection
    HashedString *hs1 = create_hashed_string("hello");
    HashedString *hs2 = create_hashed_string("hello");
    HashedString *hs3 = create_hashed_string("world");
    
    if (hs1 && hs2 && hs3) {
        printf("\nHash comparison results:\n");
        printf("'hello' vs 'hello': %d\n", hashed_string_compare(hs1, hs2));
        printf("'hello' vs 'world': %d\n", hashed_string_compare(hs1, hs3));
        
        free(hs1);
        free(hs2);
        free(hs3);
    }
}

int main(void) {
    string_search_comparison();
    advanced_string_functions_demo();
    unicode_string_demo();
    string_hashing_demo();
    
    printf("\n=== Advanced String Manipulation Best Practices ===\n");
    printf("1. Choose appropriate search algorithms based on use case\n");
    printf("2. Handle Unicode properly with wide character functions\n");
    printf("3. Use consistent string hashing for fast comparisons\n");
    printf("4. Always validate input parameters\n");
    printf("5. Consider locale settings for character operations\n");
    printf("6. Use memory-safe string functions\n");
    printf("7. Profile string-heavy code for performance bottlenecks\n");
    
    return 0;
}
```

#### Concepts ⚙
- String search algorithm complexity analysis
- Unicode and multibyte character handling
- Hash-based string operations and collision handling
- Memory-efficient string storage techniques

#### Errors ⚠
- Buffer overflows in string manipulation
- Incorrect Unicode character boundary handling
- Hash collision assumptions
- Locale-dependent behavior inconsistencies

#### Tips 🧠
- Use Boyer-Moore for long patterns, KMP for multiple searches
- Consider string interning for frequently used strings
- Profile different algorithms with your specific data
- Handle Unicode normalization for proper comparisons

#### Tools 🔧
- Unicode normalization libraries (ICU)
- String profiling tools
- Memory leak detectors for string operations
- Locale testing frameworks

---

### 20. Error Handling and Debugging {#error-handling}

Robust error handling and effective debugging are crucial for professional C development.

#### Comprehensive Error Handling Strategies

```c
/* error_handling.c - Comprehensive error handling strategies */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <setjmp.h>
#include <signal.h>

// Error code enumeration
typedef enum {
    ERR_SUCCESS = 0,
    ERR_NULL_POINTER = -1,
    ERR_INVALID_ARGUMENT = -2,
    ERR_OUT_OF_MEMORY = -3,
    ERR_FILE_NOT_FOUND = -4,
    ERR_PERMISSION_DENIED = -5,
    ERR_BUFFER_OVERFLOW = -6,
    ERR_NETWORK_ERROR = -7,
    ERR_TIMEOUT = -8,
    ERR_UNKNOWN = -999
} ErrorCode;

// Error information structure
typedef struct {
    ErrorCode code;
    char message[256];
    char file[64];
    int line;
    char function[64];
} ErrorInfo;

// Global error state
static ErrorInfo g_last_error = {ERR_SUCCESS, "", "", 0, ""};

// Error reporting macros
#define SET_ERROR(code, msg) \
    set_error_info((code), (msg), __FILE__, __LINE__, __func__)

#define RETURN_ERROR(code, msg) \
    do { \
        SET_ERROR((code), (msg)); \
        return (code); \
    } while(0)

#define CHECK_NULL(ptr, msg) \
    do { \
        if (!(ptr)) { \
            RETURN_ERROR(ERR_NULL_POINTER, (msg)); \
        } \
    } while(0)

#define CHECK_ALLOC(ptr) \
    do { \
        if (!(ptr)) { \
            RETURN_ERROR(ERR_OUT_OF_MEMORY, "Memory allocation failed"); \
        } \
    } while(0)

// Error handling functions
void set_error_info(ErrorCode code, const char *message, 
                   const char *file, int line, const char *function) {
    g_last_error.code = code;
    snprintf(g_last_error.message, sizeof(g_last_error.message), "%s", message);
    snprintf(g_last_error.file, sizeof(g_last_error.file), "%s", 
             strrchr(file, '/') ? strrchr(file, '/') + 1 : file);
    g_last_error.line = line;
    snprintf(g_last_error.function, sizeof(g_last_error.function), "%s", function);
}

const char* error_code_to_string(ErrorCode code) {
    switch (code) {
        case ERR_SUCCESS: return "Success";
        case ERR_NULL_POINTER: return "Null pointer";
        case ERR_INVALID_ARGUMENT: return "Invalid argument";
        case ERR_OUT_OF_MEMORY: return "Out of memory";
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_PERMISSION_DENIED: return "Permission denied";
        case ERR_BUFFER_OVERFLOW: return "Buffer overflow";
        case ERR_NETWORK_ERROR: return "Network error";
        case ERR_TIMEOUT: return "Timeout";
        default: return "Unknown error";
    }
}

void print_last_error(void) {
    if (g_last_error.code != ERR_SUCCESS) {
        fprintf(stderr, "ERROR [%d]: %s\n", g_last_error.code, g_last_error.message);
        fprintf(stderr, "  Location: %s:%d in %s()\n", 
                g_last_error.file, g_last_error.line, g_last_error.function);
        fprintf(stderr, "  Description: %s\n", error_code_to_string(g_last_error.code));
    }
}

ErrorCode get_last_error_code(void) {
    return g_last_error.code;
}

// Safe mathematical operations with error checking
ErrorCode safe_divide(double a, double b, double *result) {
    CHECK_NULL(result, "Result pointer is null");
    
    if (b == 0.0) {
        RETURN_ERROR(ERR_INVALID_ARGUMENT, "Division by zero");
    }
    
    *result = a / b;
    return ERR_SUCCESS;
}

ErrorCode safe_sqrt(double x, double *result) {
    CHECK_NULL(result, "Result pointer is null");
    
    if (x < 0.0) {
        RETURN_ERROR(ERR_INVALID_ARGUMENT, "Square root of negative number");
    }
    
    *result = sqrt(x);
    return ERR_SUCCESS;
}

// Safe memory operations
typedef struct {
    void *data;
    size_t size;
    size_t capacity;
} SafeBuffer;

ErrorCode safe_buffer_create(SafeBuffer **buffer, size_t initial_capacity) {
    CHECK_NULL(buffer, "Buffer pointer is null");
    
    *buffer = malloc(sizeof(SafeBuffer));
    CHECK_ALLOC(*buffer);
    
    (*buffer)->data = malloc(initial_capacity);
    if (!(*buffer)->data) {
        free(*buffer);
        *buffer = NULL;
        RETURN_ERROR(ERR_OUT_OF_MEMORY, "Buffer data allocation failed");
    }
    
    (*buffer)->size = 0;
    (*buffer)->capacity = initial_capacity;
    return ERR_SUCCESS;
}

ErrorCode safe_buffer_append(SafeBuffer *buffer, const void *data, size_t data_size) {
    CHECK_NULL(buffer, "Buffer is null");
    CHECK_NULL(data, "Data is null");
    
    if (data_size == 0) {
        return ERR_SUCCESS;  // Nothing to append
    }
    
    // Check for potential overflow
    if (buffer->size > SIZE_MAX - data_size) {
        RETURN_ERROR(ERR_BUFFER_OVERFLOW, "Size overflow");
    }
    
    size_t needed_size = buffer->size + data_size;
    
    // Resize if necessary
    if (needed_size > buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        if (new_capacity < needed_size) {
            new_capacity = needed_size;
        }
        
        void *new_data = realloc(buffer->data, new_capacity);
        CHECK_ALLOC(new_data);
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    memcpy((char*)buffer->data + buffer->size, data, data_size);
    buffer->size += data_size;
    
    return ERR_SUCCESS;
}

void safe_buffer_destroy(SafeBuffer *buffer) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
    }
}

// File operations with comprehensive error handling
ErrorCode safe_file_read(const char *filename, char **content, size_t *size) {
    CHECK_NULL(filename, "Filename is null");
    CHECK_NULL(content, "Content pointer is null");
    CHECK_NULL(size, "Size pointer is null");
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        switch (errno) {
            case ENOENT:
                RETURN_ERROR(ERR_FILE_NOT_FOUND, "File does not exist");
            case EACCES:
                RETURN_ERROR(ERR_PERMISSION_DENIED, "Permission denied");
            default:
                RETURN_ERROR(ERR_UNKNOWN, strerror(errno));
        }
    }
    
    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to seek to end of file");
    }
    
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to get file size");
    }
    
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to seek to beginning of file");
    }
    
    // Allocate buffer
    *content = malloc(file_size + 1);
    if (!*content) {
        fclose(file);
        RETURN_ERROR(ERR_OUT_OF_MEMORY, "Failed to allocate file buffer");
    }
    
    // Read file
    size_t bytes_read = fread(*content, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        free(*content);
        *content = NULL;
        fclose(file);
        RETURN_ERROR(ERR_UNKNOWN, "Failed to read complete file");
    }
    
    (*content)[file_size] = '\0';
    *size = file_size;
    
    fclose(file);
    return ERR    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Coverage support
if(ENABLE_COVERAGE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

# Find dependencies
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(M REQUIRED m)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add subdirectories
add_subdirectory(src)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Package configuration
include(GNUInstallDirs)
set(MATHUTILS_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/MathUtils)

# Export targets
install(TARGETS mathutils
    EXPORT MathUtilsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MathUtilsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfig.cmake"
    INSTALL_DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/MathUtilsConfigVersion.cmake"
    DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)

install(EXPORT MathUtilsTargets
    FILE MathUtilsTargets.cmake
    DESTINATION ${MATHUTILS_INSTALL_CMAKEDIR}
)
```

**src/CMakeLists.txt**:
```cmake
# Define library sources
set(MATHUTILS_SOURCES
    mathutils.c
)

set(MATHUTILS_HEADERS
    ../include/mathutils.h
)

# Create library target
if(BUILD_SHARED_LIBS)
    add_library(mathutils SHARED ${MATHUTILS_SOURCES})
    set_target_properties(mathutils PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_compile_definitions(mathutils PRIVATE MATHUTILS_EXPORTS)
else()
    add_library(mathutils STATIC ${MATHUTILS_SOURCES})
endif()

# Set properties
set_target_properties(mathutils PROPERTIES
    PUBLIC_HEADER "${MATHUTILS_HEADERS}"
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Link libraries
target_link_libraries(mathutils PRIVATE m)

# Include directories
target_include_directories(mathutils
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Symbol visibility
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(mathutils PRIVATE -fvisibility=hidden)
endif()
```

**tests/CMakeLists.txt**:
```cmake
# Find testing framework (we'll use a simple custom framework)
add_executable(test_mathutils
    test_mathutils.c
    test_framework.c
)

target_link_libraries(test_mathutils mathutils)

# Add test
add_test(NAME mathutils_tests COMMAND test_mathutils)

# Coverage target
if(ENABLE_COVERAGE)
    find_program(GCOV_PATH gcov)
    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    
    if(GCOV_PATH AND LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${LCOV_PATH} --directory . --zerocounters
            COMMAND ${CMAKE_MAKE_PROGRAM} test
            COMMAND ${LCOV_PATH} --directory . --capture --output-file coverage.info
            COMMAND ${LCOV_PATH} --remove coverage.info '/usr/*' --output-file coverage.info
            COMMAND ${GENHTML_PATH} -o coverage coverage.info
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )
    endif()
endif()
```

#### Package Management and Distribution

**pkg-config file (mathutils.pc.in)**:
```
prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: MathUtils
Description: Mathematical utilities library
Version: @PROJECT_VERSION@
Libs: -L${libdir} -lmathutils -lm
Cflags: -I${includedir}
```

**Creating Distribution Packages:**

```bash
# Create source distribution
mkdir mathutils-1.2.0
cp -r src include tests examples CMakeLists.txt mathutils-1.2.0/
tar czf mathutils-1.2.0.tar.gz mathutils-1.2.0

# Build RPM package (CentOS/RHEL)
rpmbuild -ta mathutils-1.2.0.tar.gz

# Build DEB package (Ubuntu/Debian)
# Create debian/ directory with control files
debuild -us -uc

# Cross-compilation example
mkdir build-arm
cd build-arm
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/arm-linux.cmake ..
make -j4
```

**Cross-compilation toolchain (arm-linux.cmake)**:
```cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

#### Symbol Visibility and Versioning

**Advanced Symbol Management:**

```c
/* symbol_version.h - Symbol versioning support */
#ifndef SYMBOL_VERSION_H
#define SYMBOL_VERSION_H

#ifdef __GNUC__
// Symbol versioning macros
#define SYMVER(name, version) \
    __asm__(".symver " #name "," #name "@" #version)

#define SYMVER_DEFAULT(name, version) \
    __asm__(".symver " #name "," #name "@@" #version)

// Version script example:
/*
MATHUTILS_1.0 {
    global:
        math_add;
        math_multiply;
    local:
        *;
};

MATHUTILS_1.1 {
    global:
        math_power;
} MATHUTILS_1.0;

MATHUTILS_1.2 {
    global:
        point2d_distance;
        circle_area;
} MATHUTILS_1.1;
*/

#endif // __GNUC__

#endif // SYMBOL_VERSION_H
```

```c
/* versioned_functions.c - Example of API versioning */
#include "mathutils.h"
#include "symbol_version.h"

// Version 1.0 implementation (deprecated)
double math_add_v1_0(double a, double b) {
    return a + b;  // Simple addition
}

// Version 1.2 implementation (current)
double math_add_v1_2(double a, double b) {
    // Enhanced with overflow checking
    double result = a + b;
    if ((a > 0 && b > 0 && result < a) ||
        (a < 0 && b < 0 && result > a)) {
        // Overflow detected
        return (a > 0) ? INFINITY : -INFINITY;
    }
    return result;
}

// Set up symbol versioning
#ifdef __GNUC__
SYMVER(math_add_v1_0, MATHUTILS_1.0);
SYMVER_DEFAULT(math_add_v1_2, MATHUTILS_1.2);

// Create aliases
double math_add(double a, double b) __attribute__((alias("math_add_v1_2")));
#else
// Fallback for non-GCC compilers
double math_add(double a, double b) {
    return math_add_v1_2(a, b);
}
#endif
```

### 18. C Standards Evolution (C11 → C23) {#c-standards}

**Figure Reference: [C Standards Timeline and Features]**

The evolution of C standards brings new features, improved safety, and better performance. Understanding these changes is crucial for modern C development.

#### C11 Features and Improvements

**Threading Support:**

```c
/* c11_threads.c - C11 threading example */
#include <stdio.h>
#include <threads.h>
#include <time.h>

// Thread-local storage
_Thread_local int thread_id = 0;
_Thread_local char thread_name[32];

// Mutex for thread-safe printing
mtx_t print_mutex;
atomic_int global_counter = ATOMIC_VAR_INIT(0);

typedef struct {
    int id;
    int iterations;
} thread_data_t;

int worker_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    thread_id = data->id;
    snprintf(thread_name, sizeof(thread_name), "Worker-%d", thread_id);
    
    for (int i = 0; i < data->iterations; i++) {
        // Thread-safe increment
        int old_value = atomic_fetch_add(&global_counter, 1);
        
        // Thread-safe printing
        mtx_lock(&print_mutex);
        printf("[%s] Iteration %d, global counter: %d -> %d\n", 
               thread_name, i, old_value, old_value + 1);
        mtx_unlock(&print_mutex);
        
        // Simulate work
        struct timespec ts = {0, 10000000}; // 10ms
        thrd_sleep(&ts, NULL);
    }
    
    return thread_id;
}

void c11_threading_demo(void) {
    printf("=== C11 Threading Demo ===\n");
    
    if (mtx_init(&print_mutex, mtx_plain) != thrd_success) {
        printf("Failed to initialize mutex\n");
        return;
    }
    
    const int num_threads = 3;
    thrd_t threads[num_threads];
    thread_data_t thread_data[num_threads];
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].id = i + 1;
        thread_data[i].iterations = 5;
        
        if (thrd_create(&threads[i], worker_thread, &thread_data[i]) != thrd_success) {
            printf("Failed to create thread %d\n", i);
            continue;
        }
    }
    
    // Wait for threads to complete
    for (int i = 0; i < num_threads; i++) {
        int result;
        thrd_join(threads[i], &result);
        printf("Thread %d completed with result: %d\n", i + 1, result);
    }
    
    printf("Final global counter: %d\n", atomic_load(&global_counter));
    
    mtx_destroy(&print_mutex);
}
```

**Static Assertions:**

```c
/* c11_static_assert.c - Compile-time assertions */
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

// Basic static assertions
_Static_assert(sizeof(int) >= 4, "int must be at least 32 bits");
_Static_assert(sizeof(void*) == sizeof(uintptr_t), "pointer size mismatch");

// Structure layout assertions
typedef struct {
    char flag;
    int value;
    double data;
} TestStruct;

_Static_assert(sizeof(TestStruct) >= sizeof(char) + sizeof(int) + sizeof(double),
               "TestStruct appears to have negative padding");

// Conditional compilation with static assertions
#define MAX_BUFFER_SIZE 1024
_Static_assert(MAX_BUFFER_SIZE >= 512, "Buffer size too small");
_Static_assert(MAX_BUFFER_SIZE <= 4096, "Buffer size too large");

// Array size validation
#define ARRAY_SIZE 10
int test_array[ARRAY_SIZE];
_Static_assert(sizeof(test_array) == ARRAY_SIZE * sizeof(int), 
               "Array size calculation error");

void static_assertions_demo(void) {
    printf("=== C11 Static Assertions Demo ===\n");
    
    printf("All static assertions passed at compile time!\n");
    printf("sizeof(int): %zu\n", sizeof(int));
    printf("sizeof(void*): %zu\n", sizeof(void*));
    printf("sizeof(TestStruct): %zu\n", sizeof(TestStruct));
    printf("MAX_BUFFER_SIZE: %d\n", MAX_BUFFER_SIZE);
    
    // Runtime assertion for comparison
    assert(MAX_BUFFER_SIZE > 0);  // This could fail at runtime
    printf("Runtime assertion also passed\n");
}
```

**Generic Selections (_Generic):**

```c
/* c11_generic.c - Generic programming support */
#include <stdio.h>
#include <math.h>
#include <complex.h>

// Generic macro for different types
#define ABS(x) _Generic((x), \
    int: abs, \
    long: labs, \
    long long: llabs, \
    float: fabsf, \
    double: fabs, \
    long double: fabsl, \
    float complex: cabsf, \
    double complex: cabs, \
    long double complex: cabsl \
)(x)

// Generic print macro
#define PRINT_TYPE(x) _Generic((x), \
    char: "char", \
    signed char: "signed char", \
    unsigned char: "unsigned char", \
    short: "short", \
    unsigned short: "unsigned short", \
    int: "int", \
    unsigned int: "unsigned int", \
    long: "long", \
    unsigned long: "unsigned long", \
    long long: "long long", \
    unsigned long long: "unsigned long long", \
    float: "float", \
    double: "double", \
    long double: "long double", \
    char*: "char*", \
    void*: "void*", \
    default: "unknown" \
)

// Generic comparison
#define MAX_GENERIC(a, b) _Generic((a), \
    int: ((a) > (b) ? (a) : (b)), \
    float: fmaxf((a), (b)), \
    double: fmax((a), (b)), \
    long double: fmaxl((a), (b)), \
    default: ((a) > (b) ? (a) : (b)) \
)((a), (b))

void generic_demo(void) {
    printf("=== C11 Generic Programming Demo ===\n");
    
    // Test ABS macro with different types
    int i = -42;
    float f = -3.14f;
    double d = -2.718;
    double complex c = -1.0 + 2.0*I;
    
    printf("ABS(%d) = %d (type: %s)\n", i, ABS(i), PRINT_TYPE(i));
    printf("ABS(%.2f) = %.2f (type: %s)\n", f, ABS(f), PRINT_TYPE(f));
    printf("ABS(%.3f) = %.3f (type: %s)\n", d, ABS(d), PRINT_TYPE(d));
    printf("ABS(%.1f + %.1fi) = %.3f (type: %s)\n", 
           creal(c), cimag(c), ABS(c), PRINT_TYPE(c));
    
    // Test type detection
    char ch = 'A';
    char *str = "Hello";
    void *ptr = &i;
    
    printf("Type of '%c': %s\n", ch, PRINT_TYPE(ch));
    printf("Type of \"%s\": %s\n", str, PRINT_TYPE(str));
    printf("Type of pointer: %s\n", PRINT_TYPE(ptr));
    
    // Generic MAX
    printf("MAX_GENERIC(10, 20) = %d\n", MAX_GENERIC(10, 20));
    printf("MAX_GENERIC(3.14, 2.71) = %.2f\n", MAX_GENERIC(3.14, 2.71));
}
```

#### C17 Improvements

C17 (C18) was primarily a bug-fix release with no major new features, but it clarified several ambiguities:

```c
/* c17_improvements.c - C17 clarifications */
#include <stdio.h>
#include <string.h>

// C17 clarified behavior of these constructs
void c17_clarifications_demo(void) {
    printf("=== C17 Clarifications Demo ===\n");
    
    // Clarified: evaluation order in function calls
    int i = 0;
    printf("Evaluation order: i = %d, ++i = %d\n", i, ++i);
    // C17 clarifies this has unspecified behavior
    
    // Clarified: anonymous structure/union members
    struct {
        int a;
        struct {
            int b;
            int c;
        }; // Anonymous struct - C17 clarified this is valid
    } example = {1, {2, 3}};
    
    printf("Anonymous struct access: a=%d, b=%d, c=%d\n", 
           example.a, example.b, example.c);
    
    // Clarified: atomic operations memory ordering
    printf("C17 clarified memory ordering for atomic operations\n");
    
    // Clarified: thread storage duration
    printf("C17 clarified _Thread_local behavior\n");
}
```

#### C23 New Features

C23 introduces significant new features and improvements:

**New Keywords and Types:**

```c
/* c23_features.c - C23 new features */
#include <stdio.h>

// C23: nullptr constant and nullptr_t type
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 202311L

#include <stddef.h>

void c23_nullptr_demo(void) {
    printf("=== C23 nullptr Demo ===\n");
    
    // nullptr is a new keyword in C23
    int *ptr = nullptr;  // Instead of NULL
    printf("ptr initialized to nullptr: %p\n", (void*)ptr);
    
    // nullptr_t type
    nullptr_t null_value = nullptr;
    ptr = null_value;
    
    if (ptr == nullptr) {
        printf("ptr is nullptr\n");
    }
    
    // nullptr is implicitly convertible to any pointer type
    void *void_ptr = nullptr;
    char *char_ptr = nullptr;
    
    printf("Different pointer types can be set to nullptr\n");
}

// C23: typeof and typeof_unqual operators
void c23_typeof_demo(void) {
    printf("=== C23 typeof Demo ===\n");
    
    int x = 42;
    typeof(x) y = x;  // y has the same type as x
    printf("x = %d, y = %d\n", x, y);
    
    const int cx = 100;
    typeof(cx) cy = 200;         // cy is const int
    typeof_unqual(cx) cz = 300;  // cz is int (qualification removed)
    
    printf("cx = %d, cy = %d, cz = %d\n", cx, cy, cz);
    
    // typeof with expressions
    typeof(x + y) sum = x + y;
    printf("sum = %d\n", sum);
    
    // Array types
    int arr[10];
    typeof(arr) arr2;  // arr2 is int[10]
    printf("sizeof(arr) = %zu, sizeof(arr2) = %zu\n", sizeof(arr), sizeof(arr2));
}

// C23: _BitInt(N) - arbitrary precision integers
void c23_bitint_demo(void) {
    printf("=== C23 _BitInt Demo ===\n");
    
    // _BitInt can have any width from 1 to implementation-defined maximum
    _BitInt(128) big_int = 0;
    _BitInt(7) small_int = 100;  // 7-bit signed integer (-64 to 63)
    
    big_int = 1;
    for (int i = 0; i < 100; i++) {
        big_int *= 2;  // 2^100
    }
    
    printf("2^100 calculated with _BitInt(128)\n");
    printf("small_int (7-bit) = %d\n", (int)small_int);
    
    // Unsigned _BitInt
    unsigned _BitInt(64) ubig = 18446744073709551615UWB;  // Max uint64
    printf("Large unsigned _BitInt value set\n");
}

// C23: char8_t for UTF-8
void c23_char8_demo(void) {
    printf("=== C23 char8_t Demo ===\n");
    
    // char8_t for UTF-8 encoded data
    char8_t utf8_string[] = u8"Hello, 世界! 🌍";
    printf("UTF-8 string length: %zu bytes\n", sizeof(utf8_string));
    
    // Print UTF-8 string (cast to char* for printf)
    printf("UTF-8 content: %s\n", (char*)utf8_string);
}

// C23: Enhanced Enums
enum Color : unsigned char {  // Underlying type specification
    RED = 1,
    GREEN = 2,
    BLUE = 4,
    YELLOW = RED | GREEN,  // Expression in initializer
    CYAN = GREEN | BLUE,
    MAGENTA = RED | BLUE,
    WHITE = RED | GREEN | BLUE
};

void c23_enhanced_enums_demo(void) {
    printf("=== C23 Enhanced Enums Demo ===\n");
    
    enum Color color = YELLOW;
    printf("Color value: %u\n", color);
    printf("sizeof(enum Color): %zu\n", sizeof(enum Color));
    
    // Bitwise operations with enum values
    enum Color purple = RED | BLUE;
    printf("Purple (RED | BLUE): %u\n", purple);
}

// C23: Attributes
[[deprecated("Use new_function() instead")]]
void old_function(void) {
    printf("This is a deprecated function\n");
}

[[nodiscard]]
int important_calculation(int x) {
    return x * x + 2 * x + 1;
}

[[maybe_unused]]
static int debug_value = 42;

void c23_attributes_demo(void) {
    printf("=== C23 Attributes Demo ===\n");
    
    old_function();  // Should generate deprecation warning
    
    // This should generate a warning if result is unused
    important_calculation(5);
    
    // This usage is correct
    int result = important_calculation(10);
    printf("Calculation result: %d\n", result);
}

// C23: Improved Unicode support
void c23_unicode_demo(void) {
    printf("=== C23 Unicode Demo ===\n");
    
    // Named universal character constants (implementation-dependent)
    char32_t emoji = U'🌟';  // Unicode star emoji
    char16_t chinese = u'中'; // Chinese character
    
    printf("Unicode support improved in C23\n");
    printf("char32_t size: %zu\n", sizeof(char32_t));
    printf("char16_t size: %zu\n", sizeof(char16_t));
}

// C23: constexpr for compile-time constants
constexpr int BUFFER_SIZE = 1024;
constexpr double PI = 3.14159265358979323846;

void c23_constexpr_demo(void) {
    printf("=== C23 constexpr Demo ===\n");
    
    char buffer[BUFFER_SIZE];  // Can be used in constant expressions
    printf("Buffer size: %d\n", BUFFER_SIZE);
    printf("PI value: %.10f\n", PI);
    
    // constexpr ensures compile-time evaluation
    constexpr int factorial_5 = 5 * 4 * 3 * 2 * 1;
    printf("Factorial of 5: %d\n", factorial_5);
}

#endif // C23 check
#endif // __STDC_VERSION__ check

// Fallback for older standards
void c23_features_demo(void) {
    printf("=== C23 Features Demo ===\n");
    
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 202311L
    printf("C23 features available!\n");
    c23_nullptr_demo();
    c23_typeof_demo();
    c23_bitint_demo();
    c23_char8_demo();
    c23_enhanced_enums_demo();
    c23_attributes_demo();
    c23_unicode_demo();
    c23_constexpr_demo();
#else
    printf("C23 features not available in this compiler version\n");
    printf("Current standard version: %ld\n", __STDC_VERSION__);
    printf("C23 requires __STDC_VERSION__ >= 202311L\n");
#endif
#else
    printf("Standard version not defined\n");
#endif
}
```

#### Feature Comparison and Migration Guide

**Figure Reference: [C Standards Feature Comparison Table]**

```c
/* standards_comparison.c - Feature comparison across standards */
#include <stdio.h>

void standards_comparison_demo(void) {
    printf("=== C Standards Feature Comparison ===\n");
    
    printf("Standard    | Year | Key Features\n");
    printf("------------|------|------------------------------------------\n");
    printf("C89/C90     | 1989 | First standardized C, function prototypes\n");
    printf("C99         | 1999 | VLA, inline, _Bool, complex, restrict\n");
    printf("C11         | 2011 | threads, atomics, _Generic, _Static_assert\n");
    printf("C17/C18     | 2017 | Bug fixes, clarifications\n");
    printf("C23         | 2023 | nullptr, typeof, _BitInt, attributes\n");
    
    printf("\nFeature availability check:\n");
    
    // C99 features
    #if __STDC_VERSION__ >= 199901L
    printf("✓ C99: Variable Length Arrays available\n");
    printf("✓ C99: inline keyword available\n");
    printf("✓ C99: _Bool type available\n");
    #else
    printf("✗ C99 features not available\n");
    #endif
    
    // C11 features
    #if __STDC_VERSION__ >= 201112L
    printf("✓ C11: _Generic available\n");
    printf("✓ C11: _Static_assert available\n");
    printf("✓ C11: _Atomic available\n");
    #ifndef __STDC_NO_THREADS__
    printf("✓ C11: Threading support available\n");
    #else
    printf("⚠ C11: Threading support not available\n");
    #endif
    #else
    printf("✗ C11 features not available\n");
    #endif
    
    // C23 features
    #if __STDC_VERSION__ >= 202311L
    printf("✓ C23: typeof available\n");
    printf("✓ C23: nullptr available\n");
    printf("✓ C23: _BitInt available\n");
    printf("✓ C23: constexpr available\n");
    #else
    printf("✗ C23 features not available\n");
    #endif
}

// Migration strategies
void migration_strategies(void) {
    printf("\n=== Migration Strategies ===\n");
    
    printf("When migrating between C standards:\n");
    printf("1. Use feature test macros for compatibility\n");
    printf("2. Provide fallback implementations\n");
    printf("3. Use compiler-specific extensions carefully\n");
    printf("4. Test thoroughly on target platforms\n");
    
    // Example: Safe _Generic usage with fallback
    #if __STDC_VERSION__ >= 201112L
    #define TYPE_SAFE_ABS(x) _Generic((x), \
        int: abs, \
        long: labs, \
        double: fabs, \
        float: fabsf \
    )(x)
    #else
    // Fallback macro (less type-safe)
    #define TYPE_SAFE_ABS(x) ((x) < 0 ? -(x) : (x))
    #endif
    
    int test_val = -42;
    printf("TYPE_SAFE_ABS(-42) = %d\n", TYPE_SAFE_ABS(test_val));
}

int main(void) {
    c11_threading_demo();
    static_assertions_demo();
    generic_demo();
    c17_clarifications_demo();
    c23_features_demo();
    standards_comparison_demo();
    migration_strategies();
    
    return 0;
}
```

#### Concepts ⚙
- Thread-local storage and atomic operations
- Generic programming with _Generic
- Compile-time assertions and constexpr
- Modern C type system improvements

#### Errors ⚠
- Threading race conditions without proper synchronization
- Misusing _Generic with incompatible types
- Assuming C23 features in older compilers
- Incorrect attribute usage

#### Tips 🧠
- Use feature test macros for portable code
- Prefer standard threading over platform-specific APIs
- Leverage _Generic for type-safe generic programming
- Consider compiler support before adopting new standards

#### Tools 🔧
- Thread sanitizer for concurrency bug detection
- Static analyzers for modern C features
- Compiler feature detection tools
- Cross-platform build systems with standard selection

---

### 19. Advanced String Manipulation {#advanced-strings}

Advanced string processing involves efficient algorithms, Unicode handling, pattern matching, and memory-safe operations.

#### Efficient String Algorithms

```c
/* advanced_strings.c - Advanced string manipulation techniques */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

// Boyer-Moore string search algorithm    cmp = strcmp("hello", "hello");
    printf("strcmp(\"hello\", \"hello\") = %d\n", cmp);
    
    // Safe string functions (bounds checking)
    char safe_str[10];
    strncpy(safe_str, "This is a very long string", sizeof(safe_str) - 1);
    safe_str[sizeof(safe_str) - 1] = '\0';  // Ensure null termination
    printf("strncpy result: \"%s\"\n", safe_str);
    
    // String search
    char *found = strstr("Hello, World!", "World");
    if (found) {
        printf("Found \"World\" at position: %ld\n", found - "Hello, World!");
    }
    
    // Character search
    found = strchr("programming", 'g');
    if (found) {
        printf("Found 'g' at position: %ld\n", found - "programming");
    }
}

void string_advanced_functions(void) {
    printf("\n=== Advanced String Functions ===\n");
    
    char text[] = "apple,banana,cherry,date";
    char *token;
    char delimiters[] = ",";
    
    printf("Original string: \"%s\"\n", text);
    printf("Tokens:\n");
    
    // String tokenization
    token = strtok(text, delimiters);
    int count = 1;
    while (token != NULL) {
        printf("  Token %d: \"%s\"\n", count++, token);
        token = strtok(NULL, delimiters);
    }
    
    // String to number conversions
    printf("\nString to number conversions:\n");
    
    char *int_str = "42";
    char *float_str = "3.14159";
    char *hex_str = "0xFF";
    char *invalid_str = "abc123";
    
    int int_val = atoi(int_str);
    double float_val = atof(float_str);
    long hex_val = strtol(hex_str, NULL, 16);
    
    printf("atoi(\"%s\") = %d\n", int_str, int_val);
    printf("atof(\"%s\") = %f\n", float_str, float_val);
    printf("strtol(\"%s\", NULL, 16) = %ld\n", hex_str, hex_val);
    
    // Safe conversion with error checking
    char *endptr;
    long safe_val = strtol(invalid_str, &endptr, 10);
    if (*endptr != '\0') {
        printf("strtol(\"%s\") failed at character: '%c'\n", invalid_str, *endptr);
    } else {
        printf("strtol(\"%s\") = %ld\n", invalid_str, safe_val);
    }
    
    // String formatting
    char buffer[200];
    int written = snprintf(buffer, sizeof(buffer), 
                          "Formatted: int=%d, float=%.2f, string=\"%s\"", 
                          42, 3.14159, "test");
    printf("snprintf result: \"%s\" (%d characters)\n", buffer, written);
}

void string_manipulation_functions(void) {
    printf("\n=== String Manipulation Functions ===\n");
    
    char text[] = "  Hello, World!  ";
    printf("Original: \"|%s|\"\n", text);
    
    // Manual string trimming function
    char* trim_whitespace(char *str) {
        // Trim leading whitespace
        while (isspace((unsigned char)*str)) str++;
        
        if (*str == '\0') return str;  // All spaces
        
        // Trim trailing whitespace
        char *end = str + strlen(str) - 1;
        while (end > str && isspace((unsigned char)*end)) end--;
        
        end[1] = '\0';
        return str;
    }
    
    char trimmed[100];
    strcpy(trimmed, text);
    char *result = trim_whitespace(trimmed);
    printf("Trimmed: \"|%s|\"\n", result);
    
    // Case conversion
    char mixed_case[] = "Hello, World!";
    printf("Original case: \"%s\"\n", mixed_case);
    
    // Convert to uppercase
    for (size_t i = 0; mixed_case[i]; i++) {
        mixed_case[i] = toupper((unsigned char)mixed_case[i]);
    }
    printf("Uppercase: \"%s\"\n", mixed_case);
    
    // Convert to lowercase
    for (size_t i = 0; mixed_case[i]; i++) {
        mixed_case[i] = tolower((unsigned char)mixed_case[i]);
    }
    printf("Lowercase: \"%s\"\n", mixed_case);
    
    // String replacement (simple version)
    char source[] = "The quick brown fox jumps over the lazy dog";
    char target[] = "quick";
    char replacement[] = "slow";
    
    printf("Original: \"%s\"\n", source);
    
    char *pos = strstr(source, target);
    if (pos) {
        char result[200];
        size_t prefix_len = pos - source;
        
        // Copy prefix
        strncpy(result, source, prefix_len);
        result[prefix_len] = '\0';
        
        // Add replacement
        strcat(result, replacement);
        
        // Add suffix
        strcat(result, pos + strlen(target));
        
        printf("After replacement: \"%s\"\n", result);
    }
}

// Mathematical Functions
#include <math.h>

void math_basic_functions(void) {
    printf("\n=== Basic Mathematical Functions ===\n");
    
    double x = 16.0, y = 2.5;
    
    // Power and root functions
    printf("pow(%.1f, %.1f) = %.3f\n", x, y, pow(x, y));
    printf("sqrt(%.1f) = %.3f\n", x, sqrt(x));
    printf("cbrt(%.1f) = %.3f\n", x, cbrt(x));  // C99
    
    // Exponential and logarithmic
    printf("exp(%.1f) = %.3f\n", y, exp(y));
    printf("log(%.1f) = %.3f\n", x, log(x));      // Natural log
    printf("log10(%.1f) = %.3f\n", x, log10(x));  // Base-10 log
    printf("log2(%.1f) = %.3f\n", x, log2(x));    // Base-2 log (C99)
    
    // Trigonometric functions
    double angle_deg = 45.0;
    double angle_rad = angle_deg * M_PI / 180.0;
    
    printf("sin(%.0f°) = %.3f\n", angle_deg, sin(angle_rad));
    printf("cos(%.0f°) = %.3f\n", angle_deg, cos(angle_rad));
    printf("tan(%.0f°) = %.3f\n", angle_deg, tan(angle_rad));
    
    // Inverse trigonometric
    double ratio = 0.707;  // approximately sin(45°)
    printf("asin(%.3f) = %.1f°\n", ratio, asin(ratio) * 180.0 / M_PI);
    
    // Hyperbolic functions
    printf("sinh(%.1f) = %.3f\n", y, sinh(y));
    printf("cosh(%.1f) = %.3f\n", y, cosh(y));
    printf("tanh(%.1f) = %.3f\n", y, tanh(y));
}

void math_utility_functions(void) {
    printf("\n=== Mathematical Utility Functions ===\n");
    
    double values[] = {-3.7, -2.3, 0.0, 1.8, 4.2};
    size_t count = sizeof(values) / sizeof(values[0]);
    
    for (size_t i = 0; i < count; i++) {
        double x = values[i];
        printf("x = %.1f:\n", x);
        printf("  fabs(x) = %.1f\n", fabs(x));
        printf("  ceil(x) = %.1f\n", ceil(x));
        printf("  floor(x) = %.1f\n", floor(x));
        printf("  round(x) = %.1f\n", round(x));    // C99
        printf("  trunc(x) = %.1f\n", trunc(x));    // C99
        printf("\n");
    }
    
    // Modulo operations
    double a = 10.5, b = 3.2;
    printf("fmod(%.1f, %.1f) = %.3f\n", a, b, fmod(a, b));
    printf("remainder(%.1f, %.1f) = %.3f\n", a, b, remainder(a, b));  // C99
    
    // Min/Max functions (C99)
    printf("fmin(%.1f, %.1f) = %.1f\n", a, b, fmin(a, b));
    printf("fmax(%.1f, %.1f) = %.1f\n", a, b, fmax(a, b));
    
    // Special values
    printf("\nSpecial floating-point values:\n");
    printf("INFINITY: %f\n", INFINITY);
    printf("NAN: %f\n", NAN);
    printf("isfinite(INFINITY): %d\n", isfinite(INFINITY));
    printf("isnan(NAN): %d\n", isnan(NAN));
    printf("isinf(INFINITY): %d\n", isinf(INFINITY));
}

// Memory Functions
void memory_functions(void) {
    printf("\n=== Memory Functions ===\n");
    
    // Memory allocation functions covered elsewhere
    // Focus on memory manipulation functions
    
    char buffer1[20] = "Hello, World!";
    char buffer2[20];
    
    printf("Original buffer1: \"%s\"\n", buffer1);
    
    // Memory copy
    memcpy(buffer2, buffer1, strlen(buffer1) + 1);
    printf("After memcpy to buffer2: \"%s\"\n", buffer2);
    
    // Memory move (safe for overlapping regions)
    memmove(buffer1 + 2, buffer1, strlen(buffer1) + 1);
    printf("After memmove (shift right 2): \"%s\"\n", buffer1);
    
    // Memory set
    memset(buffer2, '*', 5);
    buffer2[5] = '\0';
    printf("After memset with '*': \"%s\"\n", buffer2);
    
    // Memory comparison
    char data1[] = {1, 2, 3, 4, 5};
    char data2[] = {1, 2, 3, 4, 6};
    
    int cmp = memcmp(data1, data2, 5);
    printf("memcmp result: %d\n", cmp);
    
    // Find byte in memory
    char text[] = "Find the letter 'e' in this text";
    void *found = memchr(text, 'e', strlen(text));
    if (found) {
        printf("Found 'e' at position: %ld\n", (char*)found - text);
    }
}

// Time Functions
#include <time.h>

void time_functions(void) {
    printf("\n=== Time Functions ===\n");
    
    // Current time
    time_t current_time = time(NULL);
    printf("Current timestamp: %ld\n", (long)current_time);
    
    // Convert to string
    printf("Current time string: %s", ctime(&current_time));
    
    // Structured time
    struct tm *local_time = localtime(&current_time);
    printf("Structured time:\n");
    printf("  Year: %d\n", local_time->tm_year + 1900);
    printf("  Month: %d\n", local_time->tm_mon + 1);
    printf("  Day: %d\n", local_time->tm_mday);
    printf("  Hour: %d\n", local_time->tm_hour);
    printf("  Minute: %d\n", local_time->tm_min);
    printf("  Second: %d\n", local_time->tm_sec);
    printf("  Day of week: %d\n", local_time->tm_wday);
    printf("  Day of year: %d\n", local_time->tm_yday);
    
    // Formatted time
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);
    printf("Formatted time: %s\n", time_str);
    
    strftime(time_str, sizeof(time_str), "%A, %B %d, %Y", local_time);
    printf("Long format: %s\n", time_str);
    
    // Timing operations
    clock_t start = clock();
    
    // Simulate some work
    volatile long sum = 0;
    for (long i = 0; i < 1000000; i++) {
        sum += i;
    }
    
    clock_t end = clock();
    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("CPU time for calculation: %.4f seconds\n", cpu_time);
    
    // High-resolution timing (C11)
    #ifdef __STDC_VERSION__
    #if __STDC_VERSION__ >= 201112L
    #include <time.h>
    struct timespec start_time, end_time;
    
    if (timespec_get(&start_time, TIME_UTC)) {
        // Some quick operation
        volatile int result = 0;
        for (int i = 0; i < 1000; i++) result += i;
        
        timespec_get(&end_time, TIME_UTC);
        
        double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
        printf("High-resolution elapsed time: %.6f seconds\n", elapsed);
    }
    #endif
    #endif
}

// Random Number Functions
void random_functions(void) {
    printf("\n=== Random Number Functions ===\n");
    
    // Seed the random number generator
    srand((unsigned int)time(NULL));
    
    printf("Random integers (0 to RAND_MAX):\n");
    for (int i = 0; i < 5; i++) {
        printf("  %d\n", rand());
    }
    
    printf("Random integers (1 to 100):\n");
    for (int i = 0; i < 10; i++) {
        int random_val = rand() % 100 + 1;
        printf("%3d ", random_val);
    }
    printf("\n");
    
    printf("Random doubles (0.0 to 1.0):\n");
    for (int i = 0; i < 5; i++) {
        double random_double = (double)rand() / RAND_MAX;
        printf("  %.6f\n", random_double);
    }
    
    printf("RAND_MAX = %d\n", RAND_MAX);
    
    // Better random number generation (demonstration)
    void generate_random_range(int min, int max, int count) {
        printf("Random numbers in range [%d, %d]:\n", min, max);
        for (int i = 0; i < count; i++) {
            int range = max - min + 1;
            int random_val = min + rand() / (RAND_MAX / range + 1);
            printf("%3d ", random_val);
        }
        printf("\n");
    }
    
    generate_random_range(10, 50, 10);
}

// Character Classification Functions
void character_functions(void) {
    printf("\n=== Character Classification Functions ===\n");
    
    char test_chars[] = "Hello123! @#$";
    
    printf("Character analysis for: \"%s\"\n", test_chars);
    printf("Char | Alpha | Digit | Space | Upper | Lower | Punct | Print\n");
    printf("-----|-------|-------|-------|-------|-------|-------|------\n");
    
    for (size_t i = 0; test_chars[i]; i++) {
        char c = test_chars[i];
        printf(" '%c' |   %d   |   %d   |   %d   |   %d   |   %d   |   %d   |   %d\n",
               c,
               isalpha(c) ? 1 : 0,
               isdigit(c) ? 1 : 0,
               isspace(c) ? 1 : 0,
               isupper(c) ? 1 : 0,
               islower(c) ? 1 : 0,
               ispunct(c) ? 1 : 0,
               isprint(c) ? 1 : 0);
    }
    
    // Character conversion
    printf("\nCharacter conversion examples:\n");
    char mixed[] = "Hello, World!";
    printf("Original: %s\n", mixed);
    
    printf("Uppercase: ");
    for (size_t i = 0; mixed[i]; i++) {
        putchar(toupper(mixed[i]));
    }
    printf("\n");
    
    printf("Lowercase: ");
    for (size_t i = 0; mixed[i]; i++) {
        putchar(tolower(mixed[i]));
    }
    printf("\n");
}

// System Functions
void system_functions(void) {
    printf("\n=== System Functions ===\n");
    
    // Environment variables
    printf("Environment variables:\n");
    char *path = getenv("PATH");
    if (path) {
        printf("PATH length: %zu characters\n", strlen(path));
        printf("PATH starts with: %.50s...\n", path);
    } else {
        printf("PATH not found\n");
    }
    
    char *home = getenv("HOME");  // Unix/Linux
    if (!home) {
        home = getenv("USERPROFILE");  // Windows
    }
    if (home) {
        printf("Home directory: %s\n", home);
    }
    
    // Program termination
    printf("Program termination constants:\n");
    printf("EXIT_SUCCESS = %d\n", EXIT_SUCCESS);
    printf("EXIT_FAILURE = %d\n", EXIT_FAILURE);
    
    // Temporary files
    printf("Temporary filename: %s\n", tmpnam(NULL));
    
    // Note: system() function exists but is dangerous and should be avoided
    printf("Warning: system() function exists but should be avoided for security\n");
}

// Real-world example: String utilities library
typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} String;

String* string_create(const char *initial) {
    String *str = malloc(sizeof(String));
    if (!str) return NULL;
    
    size_t len = initial ? strlen(initial) : 0;
    str->capacity = len + 16;  // Some extra capacity
    str->data = malloc(str->capacity);
    
    if (!str->data) {
        free(str);
        return NULL;
    }
    
    if (initial) {
        strcpy(str->data, initial);
        str->length = len;
    } else {
        str->data[0] = '\0';
        str->length = 0;
    }
    
    return str;
}

void string_append(String *str, const char *text) {
    if (!str || !text) return;
    
    size_t text_len = strlen(text);
    size_t new_length = str->length + text_len;
    
    // Resize if necessary
    if (new_length >= str->capacity) {
        size_t new_capacity = new_length * 2;
        char *new_data = realloc(str->data, new_capacity);
        if (!new_data) return;  // Failed to resize
        
        str->data = new_data;
        str->capacity = new_capacity;
    }
    
    strcat(str->data, text);
    str->length = new_length;
}

void string_destroy(String *str) {
    if (str) {
        free(str->data);
        free(str);
    }
}

void string_utilities_demo(void) {
    printf("\n=== String Utilities Demo ===\n");
    
    String *str = string_create("Hello");
    if (!str) {
        printf("Failed to create string\n");
        return;
    }
    
    printf("Initial string: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    string_append(str, ", ");
    string_append(str, "World!");
    printf("After appends: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    // Force reallocation
    string_append(str, " This is a longer text that should force reallocation.");
    printf("After long append: \"%s\" (length: %zu, capacity: %zu)\n",
           str->data, str->length, str->capacity);
    
    string_destroy(str);
    printf("String destroyed\n");
}

int main(void) {
    string_basic_functions();
    string_advanced_functions();
    string_manipulation_functions();
    math_basic_functions();
    math_utility_functions();
    memory_functions();
    time_functions();
    random_functions();
    character_functions();
    system_functions();
    string_utilities_demo();
    
    printf("\n=== Standard Library Best Practices ===\n");
    printf("1. Always check return values for allocation functions\n");
    printf("2. Use bounds-checking string functions (strncpy, snprintf)\n");
    printf("3. Be aware of locale-dependent functions (isalpha, toupper)\n");
    printf("4. Understand the difference between memcpy and memmove\n");
    printf("5. Initialize random seed appropriately for your use case\n");
    printf("6. Use appropriate math functions for your precision needs\n");
    printf("7. Handle special floating-point values (NaN, infinity)\n");
    
    return 0;
}
```

#### Concepts ⚙
- String manipulation and safety considerations
- Mathematical function accuracy and domains
- Memory manipulation vs string functions
- Locale-dependent character operations

#### Errors ⚠
- Buffer overflows with string functions
- Not null-terminating strings after strncpy
- Ignoring return values from conversion functions
- Using uninitialized random number generator

#### Tips 🧠
- Use `snprintf` instead of `sprintf` for safety
- Check `errno` after math functions for error conditions
- Consider locale settings for character classification
- Use `strtol` family instead of `atoi` for better error handling

#### Tools 🔧
- Address Sanitizer for buffer overflow detection
- Math library unit testing frameworks
- Locale testing tools
- Performance profilers for string-heavy code

---

## Part III: Advanced Level - Professional Development

### 17. Modular Programming and Libraries {#modular-programming}

Modular programming is essential for creating maintainable, reusable, and scalable C applications. This section covers library creation, linking, and best practices.

#### Creating Static and Dynamic Libraries

**Figure Reference: [Library Types Comparison Diagram]**

```c
/* mathutils.h - Header file for mathematical utilities */
#ifndef MATHUTILS_H
#define MATHUTILS_H

#ifdef __cplusplus
extern "C" {
#endif

// Version information
#define MATHUTILS_VERSION_MAJOR 1
#define MATHUTILS_VERSION_MINOR 2
#define MATHUTILS_VERSION_PATCH 0

// API visibility macros
#ifdef _WIN32
    #ifdef MATHUTILS_EXPORTS
        #define MATHUTILS_API __declspec(dllexport)
    #else
        #define MATHUTILS_API __declspec(dllimport)
    #endif
#else
    #ifdef MATHUTILS_EXPORTS
        #define MATHUTILS_API __attribute__((visibility("default")))
    #else
        #define MATHUTILS_API
    #endif
#endif

// Data structures
typedef struct {
    double x, y;
} Point2D;

typedef struct {
    double x, y, z;
} Point3D;

typedef struct {
    Point2D center;
    double radius;
} Circle;

// Basic math operations
MATHUTILS_API double math_add(double a, double b);
MATHUTILS_API double math_multiply(double a, double b);
MATHUTILS_API double math_power(double base, double exponent);

// Geometry functions
MATHUTILS_API double point2d_distance(const Point2D *p1, const Point2D *p2);
MATHUTILS_API Point2D point2d_midpoint(const Point2D *p1, const Point2D *p2);
MATHUTILS_API double circle_area(const Circle *circle);
MATHUTILS_API double circle_circumference(const Circle *circle);

// Advanced operations
MATHUTILS_API int is_point_in_circle(const Point2D *point, const Circle *circle);
MATHUTILS_API double* matrix_multiply(const double *a, const double *b, 
                                     int rows_a, int cols_a, int cols_b);

// Utility functions
MATHUTILS_API const char* mathutils_version(void);
MATHUTILS_API void mathutils_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* MATHUTILS_H */
```

```c
/* mathutils.c - Implementation file */
#include "mathutils.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

// Version string
static char version_string[32];

// Initialize version string
static void init_version_string(void) {
    snprintf(version_string, sizeof(version_string), "%d.%d.%d",
             MATHUTILS_VERSION_MAJOR, MATHUTILS_VERSION_MINOR, MATHUTILS_VERSION_PATCH);
}

// Basic math operations
MATHUTILS_API double math_add(double a, double b) {
    return a + b;
}

MATHUTILS_API double math_multiply(double a, double b) {
    return a * b;
}

MATHUTILS_API double math_power(double base, double exponent) {
    return pow(base, exponent);
}

// Geometry functions
MATHUTILS_API double point2d_distance(const Point2D *p1, const Point2D *p2) {
    if (!p1 || !p2) return -1.0;
    
    double dx = p2->x - p1->x;
    double dy = p2->y - p1->y;
    return sqrt(dx * dx + dy * dy);
}

MATHUTILS_API Point2D point2d_midpoint(const Point2D *p1, const Point2D *p2) {
    Point2D result = {0};
    if (p1 && p2) {
        result.x = (p1->x + p2->x) / 2.0;
        result.y = (p1->y + p2->y) / 2.0;
    }
    return result;
}

MATHUTILS_API double circle_area(const Circle *circle) {
    if (!circle || circle->radius < 0) return -1.0;
    return M_PI * circle->radius * circle->radius;
}

MATHUTILS_API double circle_circumference(const Circle *circle) {
    if (!circle || circle->radius < 0) return -1.0;
    return 2.0 * M_PI * circle->radius;
}

// Advanced operations
MATHUTILS_API int is_point_in_circle(const Point2D *point, const Circle *circle) {
    if (!point || !circle) return 0;
    
    double distance = point2d_distance(point, &circle->center);
    return distance <= circle->radius;
}

MATHUTILS_API double* matrix_multiply(const double *a, const double *b, 
                                     int rows_a, int cols_a, int cols_b) {
    if (!a || !b || rows_a <= 0 || cols_a <= 0 || cols_b <= 0) {
        return NULL;
    }
    
    double *result = calloc(rows_a * cols_b, sizeof(double));
    if (!result) return NULL;
    
    for (int i = 0; i < rows_a; i++) {
        for (int j = 0; j < cols_b; j++) {
            for (int k = 0; k < cols_a; k++) {
                result[i * cols_b + j] += a[i * cols_a + k] * b[k * cols_b + j];
            }
        }
    }
    
    return result;
}

// Utility functions
MATHUTILS_API const char* mathutils_version(void) {
    static int initialized = 0;
    if (!initialized) {
        init_version_string();
        initialized = 1;
    }
    return version_string;
}

MATHUTILS_API void mathutils_cleanup(void) {
    // Cleanup any global resources if needed
    // For this simple library, nothing to clean up
}

// Library constructor/destructor (GCC/Clang)
#ifdef __GNUC__
__attribute__((constructor))
static void mathutils_init(void) {
    printf("MathUtils library loaded (version %s)\n", mathutils_version());
}

__attribute__((destructor))
static void mathutils_fini(void) {
    printf("MathUtils library unloaded\n");
    mathutils_cleanup();
}
#endif
```

**Building the Library:**

```bash
# Static library
gcc -c -fPIC mathutils.c -o mathutils.o
ar rcs libmathutils.a mathutils.o

# Dynamic library (Linux)
gcc -shared -fPIC -DMATHUTILS_EXPORTS mathutils.c -o libmathutils.so -lm

# Dynamic library (macOS)
gcc -dynamiclib -fPIC -DMATHUTILS_EXPORTS mathutils.c -o libmathutils.dylib -lm

# Dynamic library (Windows with MinGW)
gcc -shared -fPIC -DMATHUTILS_EXPORTS mathutils.c -o mathutils.dll -lm
```

#### CMake Build System Integration

**Figure Reference: [CMake Project Structure Diagram]**

**CMakeLists.txt (Root)**:
```cmake
cmake_minimum_required(VERSION 3.15)
project(MathUtils VERSION 1.2.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)

# Compiler-specific settings
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(# Complete Professional Guide to C Programming Language
*From Beginner to Professional Developer*

---

## Table of Contents

### Part I: Beginner Level - Core Foundations
1. [Introduction to C Programming](#introduction)
2. [Development Environment Setup](#environment-setup)
3. [Variables and Constants](#variables-constants)
4. [Data Types and Memory](#data-types)
5. [Operators and Expressions](#operators)
6. [Control Flow Structures](#control-flow)
7. [Functions Fundamentals](#functions-fundamentals)
8. [Scope and Storage Classes](#scope-storage)
9. [Basic Input/Output Operations](#basic-io)

### Part II: Intermediate Level - Advanced Concepts
10. [Pointers and Memory Management](#pointers-memory)
11. [Arrays and Multidimensional Data](#arrays)
12. [Dynamic Memory Allocation](#dynamic-memory)
13. [Structures, Unions, and Enumerations](#structures-unions)
14. [File Input/Output Operations](#file-io)
15. [Preprocessor and Macros](#preprocessor)
16. [Standard Library Deep Dive](#standard-library)

### Part III: Advanced Level - Professional Development
17. [Modular Programming and Libraries](#modular-programming)
18. [Advanced String Manipulation](#advanced-strings)
19. [Error Handling and Debugging](#error-handling)
20. [Multithreading and Concurrency](#multithreading)
21. [System-Level Programming](#system-programming)
22. [C Standards Evolution](#c-standards)
23. [Performance Optimization](#performance)
24. [Secure Coding Practices](#secure-coding)

### Part IV: Special Sections
25. [Professional Development Practices](#professional-practices)
26. [Game Development with C](#game-development)

---

## Part I: Beginner Level - Core Foundations

### 1. Introduction to C Programming {#introduction}

#### Why Learn C?

C programming language, developed by Dennis Ritchie at Bell Labs in 1972, remains one of the most influential and widely-used programming languages today. Its impact extends far beyond its original purpose, serving as the foundation for numerous modern languages and systems.

**Modern Applications of C:**
- **Operating Systems**: Linux kernel, Windows NT components, macOS kernel components
- **Embedded Systems**: IoT devices, microcontrollers, automotive systems
- **Database Systems**: MySQL, PostgreSQL, SQLite core engines
- **Compilers**: GCC, Clang, and many language interpreters
- **Game Engines**: Unreal Engine components, id Tech engines
- **Network Infrastructure**: Router firmware, network protocols
- **Scientific Computing**: High-performance numerical libraries

#### C's Philosophy and Design Principles

C embodies several key design principles that make it enduringly relevant:

1. **Simplicity**: Small set of keywords (32 in C89, expanded in later standards)
2. **Efficiency**: Close-to-hardware performance with minimal runtime overhead
3. **Portability**: Write once, compile anywhere with standard-compliant code
4. **Flexibility**: Powerful enough for system programming, simple enough for learning
5. **Explicitness**: Programmer controls memory management and system resources

#### The C Compilation Process

Understanding how C code becomes executable is crucial for professional development:

```
Source Code (.c) → Preprocessor → Compiler → Assembler → Linker → Executable
     ↓               ↓            ↓          ↓         ↓         ↓
   hello.c    →   hello.i   →  hello.s  → hello.o  →   ld    → hello
```

**Detailed Process:**
1. **Preprocessing**: Handles `#include`, `#define`, conditional compilation
2. **Compilation**: Converts preprocessed C to assembly language
3. **Assembly**: Converts assembly to machine code (object files)
4. **Linking**: Combines object files with libraries to create executable

### 2. Development Environment Setup {#environment-setup}

#### Essential Tools for C Development

**Compiler Options:**
- **GCC (GNU Compiler Collection)**: Most widely used, excellent standards support
- **Clang**: Modern alternative with better error messages and static analysis
- **MSVC**: Microsoft's compiler for Windows development
- **Intel C Compiler**: Optimized for Intel processors

**Development Environments:**
- **Command Line**: Traditional approach, full control
- **IDE Options**: Code::Blocks, Dev-C++, CLion, Visual Studio
- **Text Editors**: VS Code with C extensions, Vim with plugins, Emacs

#### First Program: Beyond "Hello World"

Instead of the typical "Hello World," let's start with a practical program that demonstrates multiple C concepts:

```c
/* file_analyzer.c - A practical first program */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }
    
    // Analyze file content
    int lines = 0, words = 0, chars = 0;
    int ch, in_word = 0;
    
    while ((ch = fgetc(file)) != EOF) {
        chars++;
        
        if (ch == '\n') {
            lines++;
        }
        
        if (ch == ' ' || ch == '\t' || ch == '\n') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            words++;
        }
    }
    
    fclose(file);
    
    // Display results
    printf("File Analysis for: %s\n", argv[1]);
    printf("Lines: %d\n", lines);
    printf("Words: %d\n", words);
    printf("Characters: %d\n", chars);
    
    return EXIT_SUCCESS;
}
```

**Compilation and Execution:**
```bash
gcc -o file_analyzer file_analyzer.c
./file_analyzer sample.txt
```

This program demonstrates:
- Command-line argument handling
- File operations
- Control structures
- Error handling
- Standard library usage

### 3. Variables and Constants {#variables-constants}

#### Variable Declaration and Initialization

C requires explicit variable declaration before use, promoting clear code structure:

```c
#include <stdio.h>

int main(void) {
    // Basic variable declarations
    int age;                    // Declaration only
    int height = 175;          // Declaration with initialization
    double salary = 75000.50;  // Floating-point number
    char grade = 'A';          // Single character
    
    // Multiple variables of same type
    int x, y, z;
    int a = 10, b = 20, c = 30;
    
    // Using variables
    age = 25;
    printf("Age: %d, Height: %d cm, Salary: %.2f, Grade: %c\n",
           age, height, salary, grade);
    
    return 0;
}
```

---

## Part II Continued: Advanced Intermediate Concepts

### 14. File Input/Output Operations {#file-io}

File operations are essential for persistent data storage and inter-process communication in C programs.

#### File Opening, Reading, and Writing

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

// Basic file operations
void basic_file_operations(void) {
    printf("=== Basic File Operations ===\n");
    
    // Writing to a file
    FILE *write_file = fopen("example.txt", "w");
    if (write_file == NULL) {
        perror("Failed to open file for writing");
        return;
    }
    
    fprintf(write_file, "Hello, File I/O!\n");
    fprintf(write_file, "Line 2: Numbers: %d, %.2f\n", 42, 3.14159);
    fprintf(write_file, "Line 3: Character: %c\n", 'A');
    
    fclose(write_file);
    printf("Data written to example.txt\n");
    
    // Reading from a file
    FILE *read_file = fopen("example.txt", "r");
    if (read_file == NULL) {
        perror("Failed to open file for reading");
        return;
    }
    
    char line[256];
    int line_number = 1;
    
    printf("\nFile contents:\n");
    while (fgets(line, sizeof(line), read_file) != NULL) {
        printf("Line %d: %s", line_number++, line);
    }
    
    fclose(read_file);
    
    // Check for errors
    if (ferror(read_file)) {
        printf("Error occurred while reading file\n");
    }
    
    // Cleanup
    remove("example.txt");
}

// Binary file operations
typedef struct {
    int id;
    char name[50];
    double salary;
} Employee;

void binary_file_operations(void) {
    printf("\n=== Binary File Operations ===\n");
    
    Employee employees[] = {
        {1, "John Doe", 75000.0},
        {2, "Jane Smith", 82000.0},
        {3, "Bob Johnson", 68000.0}
    };
    
    int num_employees = sizeof(employees) / sizeof(employees[0]);
    
    // Write binary data
    FILE *bin_file = fopen("employees.dat", "wb");
    if (bin_file == NULL) {
        perror("Failed to create binary file");
        return;
    }
    
    size_t written = fwrite(employees, sizeof(Employee), num_employees, bin_file);
    printf("Wrote %zu employee records\n", written);
    fclose(bin_file);
    
    // Read binary data
    bin_file = fopen("employees.dat", "rb");
    if (bin_file == NULL) {
        perror("Failed to open binary file");
        return;
    }
    
    Employee read_employees[10];
    size_t read_count = fread(read_employees, sizeof(Employee), 10, bin_file);
    printf("Read %zu employee records:\n", read_count);
    
    for (size_t i = 0; i < read_count; i++) {
        printf("  ID: %d, Name: %s, Salary: $%.2f\n",
               read_employees[i].id, read_employees[i].name, read_employees[i].salary);
    }
    
    fclose(bin_file);
    remove("employees.dat");
}

// File positioning and seeking
void file_positioning_demo(void) {
    printf("\n=== File Positioning Demo ===\n");
    
    // Create a test file
    FILE *file = fopen("positions.txt", "w+");
    if (file == NULL) {
        perror("Failed to create positioning test file");
        return;
    }
    
    // Write some data
    fprintf(file, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    
    // Get current position
    long pos = ftell(file);
    printf("Position after writing: %ld\n", pos);
    
    // Seek to beginning
    rewind(file);
    pos = ftell(file);
    printf("Position after rewind: %ld\n", pos);
    
    // Read and display character at different positions
    char ch;
    
    // Position 10
    fseek(file, 10, SEEK_SET);
    ch = fgetc(file);
    printf("Character at position 10: '%c'\n", ch);
    
    // Relative positioning
    fseek(file, 5, SEEK_CUR);
    ch = fgetc(file);
    pos = ftell(file);
    printf("Character at position %ld (after seeking +5 from current): '%c'\n", pos-1, ch);
    
    // Seek from end
    fseek(file, -5, SEEK_END);
    ch = fgetc(file);
    printf("Character 5 positions from end: '%c'\n", ch);
    
    fclose(file);
    remove("positions.txt");
}

// Error handling and file status
void file_error_handling(void) {
    printf("\n=== File Error Handling ===\n");
    
    // Try to open non-existent file
    FILE *file = fopen("nonexistent.txt", "r");
    if (file == NULL) {
        printf("Failed to open file: %s (errno: %d)\n", strerror(errno), errno);
    }
    
    // Create a file for testing
    file = fopen("test_errors.txt", "w+");
    if (file == NULL) {
        perror("Failed to create test file");
        return;
    }
    
    fprintf(file, "Test data for error handling\n");
    
    // Test various file status functions
    printf("\nFile status after writing:\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    printf("  Position: %ld\n", ftell(file));
    
    // Read past end of file
    rewind(file);
    char buffer[1000];
    size_t read_bytes = fread(buffer, 1, sizeof(buffer), file);
    printf("Read %zu bytes\n", read_bytes);
    printf("After reading past end:\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    
    // Clear error state
    clearerr(file);
    printf("After clearerr():\n");
    printf("  ferror(): %d\n", ferror(file));
    printf("  feof(): %d\n", feof(file));
    
    fclose(file);
    remove("test_errors.txt");
}

// Real-world example: Configuration file parser
typedef struct {
    char key[50];
    char value[200];
} ConfigItem;

typedef struct {
    ConfigItem items[100];
    int count;
} Config;

int parse_config_file(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return -1;
    }
    
    config->count = 0;
    char line[512];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file) != NULL && config->count < 100) {
        line_number++;
        
        // Remove newline
        line[strcspn(line, "\n")] = '\0';
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Find key=value separator
        char *equals = strchr(line, '=');
        if (equals == NULL) {
            printf("Warning: Invalid format at line %d: %s\n", line_number, line);
            continue;
        }
        
        // Split key and value
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;
        
        // Trim whitespace
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;
        
        // Remove trailing whitespace from key
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end = '\0';
            key_end--;
        }
        
        // Store configuration item
        strncpy(config->items[config->count].key, key, sizeof(config->items[config->count].key) - 1);
        strncpy(config->items[config->count].value, value, sizeof(config->items[config->count].value) - 1);
        config->items[config->count].key[sizeof(config->items[config->count].key) - 1] = '\0';
        config->items[config->count].value[sizeof(config->items[config->count].value) - 1] = '\0';
        
        config->count++;
    }
    
    fclose(file);
    return config->count;
}

const char* get_config_value(const Config *config, const char *key) {
    for (int i = 0; i < config->count; i++) {
        if (strcmp(config->items[i].key, key) == 0) {
            return config->items[i].value;
        }
    }
    return NULL;
}

void config_file_demo(void) {
    printf("\n=== Configuration File Parser Demo ===\n");
    
    // Create sample config file
    FILE *config_file = fopen("app.conf", "w");
    if (config_file == NULL) {
        perror("Failed to create config file");
        return;
    }
    
    fprintf(config_file, "# Application Configuration\n");
    fprintf(config_file, "app_name = My Application\n");
    fprintf(config_file, "version = 1.2.3\n");
    fprintf(config_file, "debug_mode = true\n");
    fprintf(config_file, "max_connections = 100\n");
    fprintf(config_file, "database_url = postgresql://localhost:5432/mydb\n");
    fprintf(config_file, "\n");
    fprintf(config_file, "; This is also a comment\n");
    fprintf(config_file, "log_level = INFO\n");
    
    fclose(config_file);
    
    // Parse configuration
    Config config;
    int result = parse_config_file("app.conf", &config);
    
    if (result < 0) {
        printf("Failed to parse configuration file\n");
        return;
    }
    
    printf("Parsed %d configuration items:\n", config.count);
    for (int i = 0; i < config.count; i++) {
        printf("  %s = %s\n", config.items[i].key, config.items[i].value);
    }
    
    // Lookup specific values
    printf("\nConfiguration lookup:\n");
    const char *app_name = get_config_value(&config, "app_name");
    const char *max_conn = get_config_value(&config, "max_connections");
    const char *missing = get_config_value(&config, "missing_key");
    
    printf("  App name: %s\n", app_name ? app_name : "Not found");
    printf("  Max connections: %s\n", max_conn ? max_conn : "Not found");
    printf("  Missing key: %s\n", missing ? missing : "Not found");
    
    remove("app.conf");
}

// Large file handling and buffering
void large_file_demo(void) {
    printf("\n=== Large File Handling Demo ===\n");
    
    const char *filename = "large_test.txt";
    const int num_lines = 10000;
    
    // Create a moderately large file
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Failed to create large test file");
        return;
    }
    
    printf("Creating file with %d lines...\n", num_lines);
    for (int i = 1; i <= num_lines; i++) {
        fprintf(file, "Line %05d: This is test data for line number %d\n", i, i);
    }
    fclose(file);
    
    // Get file size
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("File size: %ld bytes\n", st.st_size);
    }
    
    // Read file in chunks
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open large file for reading");
        return;
    }
    
    char buffer[8192];  // 8KB buffer
    size_t total_bytes = 0;
    int chunks = 0;
    
    printf("Reading file in chunks...\n");
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        total_bytes += strlen(buffer);
        chunks++;
        
        // Process every 1000th line
        if (chunks % 1000 == 0) {
            // Remove newline for display
            buffer[strcspn(buffer, "\n")] = '\0';
            printf("  Chunk %d: %s\n", chunks, buffer);
        }
    }
    
    printf("Total bytes read: %zu in %d chunks\n", total_bytes, chunks);
    
    fclose(file);
    remove(filename);
}

int main(void) {
    basic_file_operations();
    binary_file_operations();
    file_positioning_demo();
    file_error_handling();
    config_file_demo();
    large_file_demo();
    
    printf("\n=== File I/O Best Practices ===\n");
    printf("1. Always check return values from file operations\n");
    printf("2. Close files when done (use RAII pattern when possible)\n");
    printf("3. Use appropriate file modes ('r', 'w', 'a', 'rb', 'wb', etc.)\n");
    printf("4. Handle errors gracefully with meaningful messages\n");
    printf("5. Use buffering appropriately for performance\n");
    printf("6. Be careful with binary vs text modes on Windows\n");
    printf("7. Consider using memory-mapped files for large datasets\n");
    
    return 0;
}
```

#### Concepts ⚙
- File modes and permissions
- Text vs binary file handling
- Stream positioning and seeking
- File buffering strategies

#### Errors ⚠
- Forgetting to check fopen() return value
- Not closing files (resource leaks)
- Mixing text and binary operations
- Platform-specific newline handling

#### Tips 🧠
- Use `fflush()` to force write operations
- Check `ferror()` and `feof()` for operation status
- Prefer `snprintf()` over `sprintf()` for safety
- Consider using `mmap()` for large files on Unix systems

#### Tools 🔧
- `strace`/`dtrace` for file operation tracing
- `lsof` to check open file descriptors
- File integrity tools (checksums)
- Performance profilers for I/O bottlenecks

---

### 15. Preprocessor and Macros {#preprocessor}

The C preprocessor is a powerful text processing tool that runs before compilation, enabling conditional compilation, code generation, and symbolic constants.

#### Macro Definition and Usage

```c
#include <stdio.h>
#include <string.h>

// Simple macros
#define PI 3.14159265359
#define MAX_BUFFER_SIZE 1024
#define PROGRAM_VERSION "2.1.0"

// Function-like macros
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Multi-line macros
#define SWAP(type, a, b) \
    do { \
        type temp = (a); \
        (a) = (b); \
        (b) = temp; \
    } while(0)

// Stringification
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Token pasting
#define CONCAT(a, b) a ## b
#define MAKE_FUNCTION(name) \
    void CONCAT(process_, name)(void) { \
        printf("Processing " #name "\n"); \
    }

// Create functions using token pasting
MAKE_FUNCTION(data)
MAKE_FUNCTION(file)
MAKE_FUNCTION(network)

void basic_macros_demo(void) {
    printf("=== Basic Macros Demo ===\n");
    
    // Simple constant macros
    printf("PI value: %f\n", PI);
    printf("Buffer size: %d\n", MAX_BUFFER_SIZE);
    printf("Program version: %s\n", PROGRAM_VERSION);
    
    // Function-like macros
    int a = 5, b = 3;
    printf("SQUARE(%d) = %d\n", a, SQUARE(a));
    printf("MAX(%d, %d) = %d\n", a, b, MAX(a, b));
    printf("MIN(%d, %d) = %d\n", a, b, MIN(a, b));
    
    // Multi-line macro
    printf("Before swap: a=%d, b=%d\n", a, b);
    SWAP(int, a, b);
    printf("After swap: a=%d, b=%d\n", a, b);
    
    // Stringification
    printf("Stringified PI: %s\n", STRINGIFY(PI));
    printf("Converted to string: %s\n", TOSTRING(MAX_BUFFER_SIZE));
    
    // Generated functions
    process_data();
    process_file();
    process_network();
}

// Advanced macro techniques
#define DEBUG_PRINT(fmt, ...) \
    do { \
        printf("[DEBUG %s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while(0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define SAFE_FREE(ptr) \
    do { \
        if (ptr) { \
            free(ptr); \
            ptr = NULL; \
        } \
    } while(0)

// Macro for structure initialization
#define INIT_POINT(x, y) {.x = (x), .y = (y)}

// Generic macro (C11)
#if __STDC_VERSION__ >= 201112L
#define GENERIC_MAX(x, y) _Generic((x), \
    int: MAX, \
    float: fmaxf, \
    double: fmax, \
    default: MAX \
)(x, y)
#endif

void advanced_macros_demo(void) {
    printf("\n=== Advanced Macros Demo ===\n");
    
    // Variadic macros
    DEBUG_PRINT("Application started");
    DEBUG_PRINT("User %s logged in with ID %d", "Alice", 123);
    DEBUG_PRINT("Processing %d items", 42);
    
    // Array size macro
    int numbers[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    printf("Array size: %zu\n", ARRAY_SIZE(numbers));
    
    // Structure initialization macro
    struct Point { double x, y; };
    struct Point p1 = INIT_POINT(3.0, 4.0);
    printf("Point: (%.1f, %.1f)\n", p1.x, p1.y);
    
    // Safe free demonstration
    char *buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "Test data");
        printf("Buffer content: %s\n", buffer);
    }
    
    printf("Freeing buffer...\n");
    SAFE_FREE(buffer);
    printf("Buffer pointer after SAFE_FREE: %p\n", (void*)buffer);
    
    // Generic macro (C11)
    #if __STDC_VERSION__ >= 201112L
    printf("Generic max(10, 5): %d\n", GENERIC_MAX(10, 5));
    printf("Generic max(3.14, 2.71): %f\n", GENERIC_MAX(3.14, 2.71));
    #endif
}

// Conditional compilation
#define FEATURE_LOGGING 1
#define FEATURE_NETWORKING 0
#define DEBUG_LEVEL 2

#if FEATURE_LOGGING
void log_message(const char *message) {
    printf("[LOG] %s\n", message);
}
#else
#define log_message(msg) ((void)0)  // No-op macro
#endif

#if DEBUG_LEVEL >= 1
#define DBG1(fmt, ...) printf("[DBG1] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG1(fmt, ...) ((void)0)
#endif

#if DEBUG_LEVEL >= 2
#define DBG2(fmt, ...) printf("[DBG2] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG2(fmt, ...) ((void)0)
#endif

void conditional_compilation_demo(void) {
    printf("\n=== Conditional Compilation Demo ===\n");
    
    #if FEATURE_LOGGING
    printf("Logging feature is enabled\n");
    log_message("This is a log message");
    #else
    printf("Logging feature is disabled\n");
    #endif
    
    #if FEATURE_NETWORKING
    printf("Networking feature is enabled\n");
    #else
    printf("Networking feature is disabled\n");
    #endif
    
    DBG1("Debug level 1 message");
    DBG2("Debug level 2 message with value: %d", 42);
    
    // Compiler-specific code
    #ifdef __GNUC__
    printf("Compiled with GCC version %d.%d.%d\n", 
           __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    #elif defined(_MSC_VER)
    printf("Compiled with Microsoft Visual C++ version %d\n", _MSC_VER);
    #elif defined(__clang__)
    printf("Compiled with Clang version %s\n", __clang_version__);
    #else
    printf("Compiled with unknown compiler\n");
    #endif
    
    // Platform-specific code
    #ifdef _WIN32
    printf("Running on Windows\n");
    #elif defined(__linux__)
    printf("Running on Linux\n");
    #elif defined(__APPLE__)
    printf("Running on macOS\n");
    #else
    printf("Running on unknown platform\n");
    #endif
}

// Predefined macros
void predefined_macros_demo(void) {
    printf("\n=== Predefined Macros Demo ===\n");
    
    printf("File: %s\n", __FILE__);
    printf("Line: %d\n", __LINE__);
    printf("Function: %s\n", __func__);  // C99
    printf("Date: %s\n", __DATE__);
    printf("Time: %s\n", __TIME__);
    printf("Standard version: %ld\n", __STDC_VERSION__);
    
    #ifdef __STDC__
    printf("Standard C compiler: Yes\n");
    #endif
    
    #ifdef __STDC_HOSTED__
    printf("Hosted implementation: %d\n", __STDC_HOSTED__);
    #endif
    
    // C11 and later features
    #if __STDC_VERSION__ >= 201112L
    printf("C11 features available\n");
    
    #ifdef __STDC_NO_ATOMICS__
    printf("Atomics: Not available\n");
    #else
    printf("Atomics: Available\n");
    #endif
    
    #ifdef __STDC_NO_THREADS__
    printf("Threads: Not available\n");
    #else
    printf("Threads: Available\n");
    #endif
    #endif
}

// Macro pitfalls and best practices
#define BAD_MAX(a, b) (a > b ? a : b)  // Side effects!
#define GOOD_MAX(a, b) ((a) > (b) ? (a) : (b))  // Proper parentheses

// Multi-evaluation problem
#define INCREMENT_BAD(x) (++x)  // Dangerous
#define INCREMENT_GOOD(x) ((x) + 1)  // Safe

// Statement-like macros
#define ASSERT_BAD(cond) if (!(cond)) { printf("Assertion failed\n"); exit(1); }
#define ASSERT_GOOD(cond) \
    do { \
        if (!(cond)) { \
            printf("Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while(0)

void macro_pitfalls_demo(void) {
    printf("\n=== Macro Pitfalls and Solutions ===\n");
    
    // Side effect demonstration
    int x = 5, y = 3;
    
    printf("Before: x=%d, y=%d\n", x, y);
    
    // This works fine
    int result1 = GOOD_MAX(x, y);
    printf("GOOD_MAX(x, y) = %d, x=%d, y=%d\n", result1, x, y);
    
    // This has side effects with increment
    x = 5;
    // int bad_result = BAD_MAX(++x, y);  // x incremented twice!
    int good_result = GOOD_MAX(++x, y);   // x incremented once
    printf("After GOOD_MAX(++x, y): result=%d, x=%d\n", good_result, x);
    
    // Statement-like macro usage
    int value = 10;
    if (value > 0)
        ASSERT_GOOD(value > 5);  // This works correctly
    
    printf("Assertion passed\n");
    
    // Show macro expansion (conceptual)
    printf("\nMacro expansion examples:\n");
    printf("SQUARE(3+2) expands to: ((3+2) * (3+2)) = %d\n", SQUARE(3+2));
    printf("Without parentheses it would be: 3+2 * 3+2 = %d\n", 3+2 * 3+2);
}

// Real-world example: Logging system with macros
typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO = 2,
    LOG_WARN = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5
} LogLevel;

static LogLevel current_log_level = LOG_INFO;

#define LOG(level, fmt, ...) \
    do { \
        if ((level) >= current_log_level) { \
            const char* level_names[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}; \
            printf("[%s %s:%d] " fmt "\n", \
                   level_names[level], __FILE__, __LINE__, ##__VA_ARGS__); \
        } \
    } while(0)

#define LOG_TRACE(fmt, ...) LOG(LOG_TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG(LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG(LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) LOG(LOG_FATAL, fmt, ##__VA_ARGS__)

void logging_system_demo(void) {
    printf("\n=== Logging System Demo ===\n");
    
    printf("Current log level: INFO\n");
    
    LOG_TRACE("This trace message won't appear");
    LOG_DEBUG("This debug message won't appear");
    LOG_INFO("Application started");
    LOG_WARN("Low disk space: %d%% full", 85);
    LOG_ERROR("Failed to connect to database: %s", "Connection timeout");
    LOG_FATAL("Critical system error occurred");
    
    // Change log level
    current_log_level = LOG_DEBUG;
    printf("\nChanged log level to DEBUG:\n");
    
    LOG_TRACE("This trace message still won't appear");
    LOG_DEBUG("Now debug messages appear");
    LOG_INFO("Debug mode enabled");
}

int main(void) {
    basic_macros_demo();
    advanced_macros_demo();
    conditional_compilation_demo();
    predefined_macros_demo();
    macro_pitfalls_demo();
    logging_system_demo();
    
    return 0;
}
```

#### Concepts ⚙
- Macro expansion phases
- Token stringification and pasting
- Variadic macros with `__VA_ARGS__`
- Conditional compilation directives

#### Errors ⚠
- Multiple evaluation of macro arguments
- Missing parentheses in macro definitions  
- Side effects in macro arguments
- Macro name collisions with functions

#### Tips 🧠
- Use `do-while(0)` for statement-like macros
- Always parenthesize macro parameters
- Use `##__VA_ARGS__` for optional arguments
- Prefer `const` variables over simple `#define` when possible

#### Tools 🔧
- `gcc -E` to see preprocessor output
- Static analysis tools for macro complexity
- IDE macro expansion viewers
- Compiler warnings for macro redefinition

---

### 16. Standard Library Deep Dive {#standard-library}

The C Standard Library provides essential functions for string manipulation, mathematical operations, memory management, and system interfaces.

#### String Handling Functions

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <locale.h>

void string_basic_functions(void) {
    printf("=== Basic String Functions ===\n");
    
    char str1[100] = "Hello";
    char str2[100] = "World";
    char str3[100];
    
    // String length
    printf("strlen(\"%s\") = %zu\n", str1, strlen(str1));
    
    // String copy
    strcpy(str3, str1);
    printf("strcpy result: \"%s\"\n", str3);
    
    // String concatenation
    strcat(str1, ", ");
    strcat(str1, str2);
    printf("After strcat: \"%s\"\n", str1);
    
    // String comparison
    int cmp = strcmp("apple", "banana");
    printf("strcmp(\"apple\", \"banana\") = %d\n", cmp);
    
    cmp = strcmp("hello", "hello");
    printf
```

#### Naming Conventions and Best Practices

**Valid Identifiers:**
- Must start with letter or underscore
- Can contain letters, digits, underscores
- Case-sensitive (`myVar` ≠ `myvar`)

**Professional Naming Conventions:**
```c
// Variables: snake_case (preferred) or camelCase
int user_count;        // snake_case
int userCount;         // camelCase

// Constants: SCREAMING_SNAKE_CASE
#define MAX_BUFFER_SIZE 1024
const int DEFAULT_PORT = 8080;

// Functions: snake_case
int calculate_area(int width, int height);

// Types: PascalCase or snake_case with _t suffix
typedef struct {
    int x, y;
} Point;

typedef struct user_data_s {
    char name[50];
    int age;
} user_data_t;
```

#### Constants: Multiple Approaches

C provides several ways to define constants, each with specific use cases:

**1. Preprocessor Macros:**
```c
#define PI 3.14159265359
#define MAX_USERS 100
#define WELCOME_MSG "Welcome to the system"

// Advantages: Compile-time substitution, no memory usage
// Disadvantages: No type checking, no scope respect
```

**2. Const Keyword:**
```c
const double PI = 3.14159265359;
const int MAX_USERS = 100;
const char WELCOME_MSG[] = "Welcome to the system";

// Advantages: Type safety, scope rules apply
// Disadvantages: Uses memory, runtime initialization
```

**3. Enumerated Constants:**
```c
enum Status {
    STATUS_INACTIVE,    // 0
    STATUS_ACTIVE,      // 1
    STATUS_PENDING,     // 2
    STATUS_SUSPENDED = 10,  // Explicit value
    STATUS_DELETED      // 11
};

// Usage
enum Status user_status = STATUS_ACTIVE;
```

**Real-World Example: Configuration System**
```c
/* config.h - Application configuration */
#ifndef CONFIG_H
#define CONFIG_H

// Compile-time configuration
#define APP_VERSION "2.1.4"
#define BUILD_DATE __DATE__
#define MAX_CONNECTIONS 1000

// Runtime configuration
extern const char* const DEFAULT_CONFIG_PATH;
extern const int DEFAULT_TIMEOUT;

// Status codes
enum ErrorCode {
    ERR_SUCCESS = 0,
    ERR_INVALID_INPUT = -1,
    ERR_OUT_OF_MEMORY = -2,
    ERR_FILE_NOT_FOUND = -3,
    ERR_NETWORK_ERROR = -4
};

#endif /* CONFIG_H */
```

### 4. Data Types and Memory {#data-types}

#### Fundamental Data Types

C provides several fundamental data types, with sizes that can vary by platform:

**Integer Types:**
```c
#include <stdio.h>
#include <limits.h>
#include <stdint.h>

int main(void) {
    // Basic integer types
    char c = 'A';              // At least 8 bits
    short s = 32767;           // At least 16 bits
    int i = 2147483647;        // At least 16 bits (usually 32)
    long l = 2147483647L;      // At least 32 bits
    long long ll = 9223372036854775807LL; // At least 64 bits (C99)
    
    // Unsigned variants
    unsigned char uc = 255;
    unsigned short us = 65535;
    unsigned int ui = 4294967295U;
    unsigned long ul = 4294967295UL;
    unsigned long long ull = 18446744073709551615ULL;
    
    // Fixed-width integers (C99, recommended for portability)
    int8_t i8 = 127;           // Exactly 8 bits
    int16_t i16 = 32767;       // Exactly 16 bits
    int32_t i32 = 2147483647;  // Exactly 32 bits
    int64_t i64 = 9223372036854775807LL; // Exactly 64 bits
    
    uint8_t u8 = 255;
    uint16_t u16 = 65535;
    uint32_t u32 = 4294967295U;
    uint64_t u64 = 18446744073709551615ULL;
    
    // Display sizes
    printf("Size of char: %zu bytes\n", sizeof(char));
    printf("Size of int: %zu bytes\n", sizeof(int));
    printf("Size of long: %zu bytes\n", sizeof(long));
    printf("Size of long long: %zu bytes\n", sizeof(long long));
    printf("Size of pointer: %zu bytes\n", sizeof(void*));
    
    return 0;
}
```

**Floating-Point Types:**
```c
#include <stdio.h>
#include <float.h>

int main(void) {
    float f = 3.14159f;        // Single precision (usually 32 bits)
    double d = 3.14159265359;  // Double precision (usually 64 bits)
    long double ld = 3.14159265358979323846L; // Extended precision
    
    printf("Float: %.7f (precision: %d digits)\n", f, FLT_DIG);
    printf("Double: %.15f (precision: %d digits)\n", d, DBL_DIG);
    printf("Long Double: %.18Lf (precision: %d digits)\n", ld, LDBL_DIG);
    
    // Scientific notation
    double large_number = 1.23e6;   // 1,230,000
    double small_number = 1.23e-6;  // 0.00000123
    
    printf("Large: %e, Small: %e\n", large_number, small_number);
    
    return 0;
}
```

#### Memory Layout and Alignment

Understanding how data is stored in memory is crucial for efficient C programming:

```c
#include <stdio.h>
#include <stddef.h>

struct UnalignedData {
    char a;      // 1 byte
    int b;       // 4 bytes
    char c;      // 1 byte
    double d;    // 8 bytes
}; // Total: 24 bytes (with padding)

struct AlignedData {
    double d;    // 8 bytes
    int b;       // 4 bytes
    char a;      // 1 byte
    char c;      // 1 byte
}; // Total: 16 bytes (with padding)

int main(void) {
    printf("Unaligned struct size: %zu bytes\n", sizeof(struct UnalignedData));
    printf("Aligned struct size: %zu bytes\n", sizeof(struct AlignedData));
    
    // Demonstrate memory addresses and alignment
    struct UnalignedData unaligned;
    
    printf("\nMemory layout of unaligned struct:\n");
    printf("Address of a: %p (offset: %zu)\n", 
           (void*)&unaligned.a, offsetof(struct UnalignedData, a));
    printf("Address of b: %p (offset: %zu)\n", 
           (void*)&unaligned.b, offsetof(struct UnalignedData, b));
    printf("Address of c: %p (offset: %zu)\n", 
           (void*)&unaligned.c, offsetof(struct UnalignedData, c));
    printf("Address of d: %p (offset: %zu)\n", 
           (void*)&unaligned.d, offsetof(struct UnalignedData, d));
    
    return 0;
}
```

#### Type Qualifiers and Modifiers

**Storage Class Specifiers:**
```c
// auto - default for local variables (rarely used explicitly)
auto int local_var = 10;

// register - hint to store in CPU register (deprecated in modern C)
register int counter;

// static - retains value between function calls, internal linkage
static int function_calls = 0;

// extern - declares variable defined elsewhere
extern int global_variable;
```

**Type Qualifiers:**
```c
// const - immutable after initialization
const int MAX_SIZE = 100;
const char* const filename = "config.txt"; // Immutable pointer to immutable data

// volatile - prevents compiler optimization, value may change unexpectedly
volatile int hardware_register;
volatile sig_atomic_t signal_flag; // Common in signal handlers

// restrict - pointer is the only way to access the object (C99)
void process_arrays(int* restrict input, int* restrict output, size_t count);
```

**Real-World Example: Embedded System Register Mapping**
```c
/* Hardware abstraction for embedded system */
#include <stdint.h>

// Memory-mapped I/O registers
#define GPIO_BASE_ADDR 0x40020000

typedef struct {
    volatile uint32_t MODER;    // Mode register
    volatile uint32_t OTYPER;   // Output type register
    volatile uint32_t OSPEEDR;  // Output speed register
    volatile uint32_t PUPDR;    // Pull-up/pull-down register
    volatile uint32_t IDR;      // Input data register
    volatile uint32_t ODR;      // Output data register
} GPIO_TypeDef;

// Map structure to hardware address
#define GPIOA ((GPIO_TypeDef*)GPIO_BASE_ADDR)

void configure_gpio_pin(void) {
    // Configure pin 5 as output
    GPIOA->MODER |= (1 << (5 * 2));
    
    // Set pin 5 high
    GPIOA->ODR |= (1 << 5);
}
```

### 5. Operators and Expressions {#operators}

#### Arithmetic and Assignment Operators

C provides a comprehensive set of operators for mathematical operations and variable manipulation:

```c
#include <stdio.h>

int main(void) {
    int a = 10, b = 3;
    double x = 10.0, y = 3.0;
    
    // Basic arithmetic operators
    printf("Integer arithmetic:\n");
    printf("%d + %d = %d\n", a, b, a + b);    // Addition: 13
    printf("%d - %d = %d\n", a, b, a - b);    // Subtraction: 7
    printf("%d * %d = %d\n", a, b, a * b);    // Multiplication: 30
    printf("%d / %d = %d\n", a, b, a / b);    // Integer division: 3
    printf("%d %% %d = %d\n", a, b, a % b);   // Modulo: 1
    
    printf("\nFloating-point arithmetic:\n");
    printf("%.2f / %.2f = %.2f\n", x, y, x / y); // 3.33
    
    // Compound assignment operators
    int c = 20;
    printf("\nCompound assignments (starting with c = %d):\n", c);
    
    c += 5; // c = c + 5
    printf("After c += 5: %d\n", c);
    
    c -= 3; // c = c - 3
    printf("After c -= 3: %d\n", c);
    
    c *= 2; // c = c * 2
    printf("After c *= 2: %d\n", c);
    
    c /= 4; // c = c / 4
    printf("After c /= 4: %d\n", c);
    
    c %= 7; // c = c % 7
    printf("After c %%= 7: %d\n", c);
    
    // Increment and decrement operators
    int i = 10;
    printf("\nIncrement/Decrement (starting with i = %d):\n", i);
    printf("i++ returns %d, i is now %d\n", i++, i);
    printf("++i returns %d, i is now %d\n", ++i, i);
    printf("i-- returns %d, i is now %d\n", i--, i);
    printf("--i returns %d, i is now %d\n", --i, i);
    
    return 0;
}
```

#### Bitwise Operations

Bitwise operations are essential for low-level programming, embedded systems, and performance optimization:

```c
#include <stdio.h>

// Function to display binary representation
void print_binary(unsigned int n) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
        if (i % 4 == 0) printf(" ");
    }
    printf("\n");
}

int main(void) {
    unsigned int a = 60;  // 0011 1100
    unsigned int b = 13;  // 0000 1101
    
    printf("a = %u: ", a);
    print_binary(a);
    printf("b = %u: ", b);
    print_binary(b);
    
    // Bitwise AND
    printf("\nBitwise AND (a & b):\n");
    unsigned int and_result = a & b; // 0000 1100 = 12
    printf("Result = %u: ", and_result);
    print_binary(and_result);
    
    // Bitwise OR
    printf("\nBitwise OR (a | b):\n");
    unsigned int or_result = a | b; // 0011 1101 = 61
    printf("Result = %u: ", or_result);
    print_binary(or_result);
    
    // Bitwise XOR
    printf("\nBitwise XOR (a ^ b):\n");
    unsigned int xor_result = a ^ b; // 0011 0001 = 49
    printf("Result = %u: ", xor_result);
    print_binary(xor_result);
    
    // Bitwise NOT
    printf("\nBitwise NOT (~a):\n");
    unsigned int not_result = ~a;
    printf("Result = %u: ", not_result);
    print_binary(not_result);
    
    // Left shift
    printf("\nLeft shift (a << 2):\n");
    unsigned int left_shift = a << 2; // 1111 0000 = 240
    printf("Result = %u: ", left_shift);
    print_binary(left_shift);
    
    // Right shift
    printf("\nRight shift (a >> 2):\n");
    unsigned int right_shift = a >> 2; // 0000 1111 = 15
    printf("Result = %u: ", right_shift);
    print_binary(right_shift);
    
    return 0;
}
```

**Practical Bitwise Operations:**
```c
#include <stdio.h>
#include <stdint.h>

// Set bit at position
#define SET_BIT(x, pos) ((x) |= (1U << (pos)))

// Clear bit at position
#define CLEAR_BIT(x, pos) ((x) &= ~(1U << (pos)))

// Toggle bit at position
#define TOGGLE_BIT(x, pos) ((x) ^= (1U << (pos)))

// Check if bit is set
#define IS_BIT_SET(x, pos) (((x) >> (pos)) & 1U)

// Extract bits from position with mask
#define EXTRACT_BITS(x, pos, len) (((x) >> (pos)) & ((1U << (len)) - 1))

// Permission system example
typedef enum {
    PERM_READ    = 1 << 0,  // 001
    PERM_WRITE   = 1 << 1,  // 010
    PERM_EXECUTE = 1 << 2   // 100
} Permission;

void demonstrate_permissions(void) {
    uint8_t user_perms = 0;
    
    // Grant permissions
    user_perms |= PERM_READ;
    user_perms |= PERM_WRITE;
    
    printf("User permissions: ");
    if (user_perms & PERM_READ) printf("READ ");
    if (user_perms & PERM_WRITE) printf("WRITE ");
    if (user_perms & PERM_EXECUTE) printf("EXECUTE ");
    printf("\n");
    
    // Check specific permission
    if (user_perms & PERM_EXECUTE) {
        printf("User can execute\n");
    } else {
        printf("User cannot execute\n");
    }
    
    // Revoke write permission
    user_perms &= ~PERM_WRITE;
    printf("After revoking WRITE: %s\n", 
           (user_perms & PERM_WRITE) ? "Has WRITE" : "No WRITE");
}

int main(void) {
    // Demonstrate bit manipulation functions
    uint32_t flags = 0x12345678;
    
    printf("Original: 0x%08X\n", flags);
    
    SET_BIT(flags, 3);
    printf("After SET_BIT(3): 0x%08X\n", flags);
    
    CLEAR_BIT(flags, 4);
    printf("After CLEAR_BIT(4): 0x%08X\n", flags);
    
    TOGGLE_BIT(flags, 0);
    printf("After TOGGLE_BIT(0): 0x%08X\n", flags);
    
    printf("Bit 5 is %s\n", IS_BIT_SET(flags, 5) ? "set" : "clear");
    
    // Extract nibble (4 bits) starting at position 8
    uint32_t extracted = EXTRACT_BITS(flags, 8, 4);
    printf("Extracted 4 bits from position 8: 0x%X\n", extracted);
    
    demonstrate_permissions();
    
    return 0;
}
```

#### Logical and Relational Operators

```c
#include <stdio.h>
#include <stdbool.h>

int main(void) {
    int a = 10, b = 20, c = 10;
    bool result;
    
    // Relational operators
    printf("Relational operators (a=%d, b=%d, c=%d):\n", a, b, c);
    printf("a == c: %s\n", (a == c) ? "true" : "false");
    printf("a != b: %s\n", (a != b) ? "true" : "false");
    printf("a < b: %s\n", (a < b) ? "true" : "false");
    printf("a > b: %s\n", (a > b) ? "true" : "false");
    printf("a <= c: %s\n", (a <= c) ? "true" : "false");
    printf("b >= a: %s\n", (b >= a) ? "true" : "false");
    
    // Logical operators
    printf("\nLogical operators:\n");
    result = (a < b) && (b > c);  // Logical AND
    printf("(a < b) && (b > c): %s\n", result ? "true" : "false");
    
    result = (a > b) || (a == c); // Logical OR
    printf("(a > b) || (a == c): %s\n", result ? "true" : "false");
    
    result = !(a > b);            // Logical NOT
    printf("!(a > b): %s\n", result ? "true" : "false");
    
    // Short-circuit evaluation
    printf("\nShort-circuit evaluation:\n");
    int x = 0, y = 0;
    
    // AND: if first is false, second isn't evaluated
    if ((x = 1) && (y = 2)) {
        printf("Both conditions evaluated\n");
    }
    printf("After AND: x=%d, y=%d\n", x, y); // x=1, y=0
    
    x = 0; y = 0;
    // OR: if first is true, second isn't evaluated
    if ((x = 1) || (y = 2)) {
        printf("At least one condition was true\n");
    }
    printf("After OR: x=%d, y=%d\n", x, y); // x=1, y=0
    
    return 0;
}
```

#### Operator Precedence and Associativity

Understanding operator precedence is crucial for writing correct expressions:

**Operator Precedence Table (High to Low):**
```c
// 1. Postfix: () [] -> . ++ --
// 2. Prefix: ++ -- + - ! ~ (type) * & sizeof
// 3. Multiplicative: * / %
// 4. Additive: + -
// 5. Shift: << >>
// 6. Relational: < <= > >=
// 7. Equality: == !=
// 8. Bitwise AND: &
// 9. Bitwise XOR: ^
// 10. Bitwise OR: |
// 11. Logical AND: &&
// 12. Logical OR: ||
// 13. Conditional: ?:
// 14. Assignment: = += -= *= /= %= &= ^= |= <<= >>=
// 15. Comma: ,

#include <stdio.h>

int main(void) {
    int a = 5, b = 3, c = 2, d = 8;
    
    // Without parentheses - relies on precedence
    int result1 = a + b * c;        // 5 + (3 * 2) = 11
    int result2 = a < b + c * d;    // a < (b + (c * d)) = 5 < (3 + 16) = true
    int result3 = a & b << c;       // a & (b << c) = 5 & (3 << 2) = 5 & 12 = 4
    
    // With parentheses - explicit grouping
    int result4 = (a + b) * c;      // (5 + 3) * 2 = 16
    int result5 = (a < b) + c * d;  // (5 < 3) + (2 * 8) = 0 + 16 = 16
    int result6 = (a & b) << c;     // (5 & 3) << 2 = 1 << 2 = 4
    
    printf("Without parentheses:\n");
    printf("a + b * c = %d\n", result1);
    printf("a < b + c * d = %d\n", result2);
    printf("a & b << c = %d\n", result3);
    
    printf("\nWith parentheses:\n");
    printf("(a + b) * c = %d\n", result4);
    printf("(a < b) + c * d = %d\n", result5);
    printf("(a & b) << c = %d\n", result6);
    
    // Common mistakes
    printf("\nCommon precedence mistakes:\n");
    
    // Mistake 1: Bitwise AND with comparison
    if (a & 1 == 0) {  // Wrong: a & (1 == 0) = a & 0 = 0
        printf("This might not work as expected\n");
    }
    
    if ((a & 1) == 0) {  // Correct: (a & 1) == 0
        printf("a is even\n");
    } else {
        printf("a is odd\n");
    }
    
    // Mistake 2: Assignment in condition
    int x = 0;
    if (x = 5) {  // Assignment, not comparison!
        printf("x was assigned 5, condition is true\n");
    }
    
    x = 0;
    if (x == 5) {  // Correct comparison
        printf("x equals 5\n");
    } else {
        printf("x does not equal 5\n");
    }
    
    return 0;
}
```

### 6. Control Flow Structures {#control-flow}

#### Conditional Statements

**Basic if-else Structures:**
```c
#include <stdio.h>

// Function to demonstrate grade classification
char classify_grade(int score) {
    if (score >= 90) {
        return 'A';
    } else if (score >= 80) {
        return 'B';
    } else if (score >= 70) {
        return 'C';
    } else if (score >= 60) {
        return 'D';
    } else {
        return 'F';
    }
}

// Real-world example: HTTP status code handling
const char* get_status_message(int status_code) {
    if (status_code >= 200 && status_code < 300) {
        return "Success";
    } else if (status_code >= 300 && status_code < 400) {
        return "Redirection";
    } else if (status_code >= 400 && status_code < 500) {
        return "Client Error";
    } else if (status_code >= 500 && status_code < 600) {
        return "Server Error";
    } else {
        return "Unknown Status";
    }
}

int main(void) {
    int scores[] = {95, 87, 72, 61, 45};
    int num_scores = sizeof(scores) / sizeof(scores[0]);
    
    printf("Grade Classification:\n");
    for (int i = 0; i < num_scores; i++) {
        printf("Score %d: Grade %c\n", scores[i], classify_grade(scores[i]));
    }
    
    // HTTP status code examples
    int status_codes[] = {200, 301, 404, 500, 999};
    int num_codes = sizeof(status_codes) / sizeof(status_codes[0]);
    
    printf("\nHTTP Status Messages:\n");
    for (int i = 0; i < num_codes; i++) {
        printf("Status %d: %s\n", status_codes[i], 
               get_status_message(status_codes[i]));
    }
    
    return 0;
}
```

**Switch Statements:**
```c
#include <stdio.h>
#include <ctype.h>

// Calculator function using switch
double calculate(double a, double b, char operator) {
    switch (operator) {
        case '+':
            return a + b;
        case '-':
            return a - b;
        case '*':
            return a * b;
        case '/':
            if (b != 0) {
                return a / b;
            } else {
                printf("Error: Division by zero\n");
                return 0;
            }
        case '%':
            // Modulo only works with integers
            if (b != 0) {
                return (int)a % (int)b;
            } else {
                printf("Error: Modulo by zero\n");
                return 0;
            }
        default:
            printf("Error: Unknown operator '%c'\n", operator);
            return 0;
    }
}

// Real-world example: Menu system
void handle_menu_choice(int choice) {
    switch (choice) {
        case 1:
            printf("Opening file...\n");
            // file_open_dialog();
            break;
            
        case 2:
            printf("Saving file...\n");
            // file_save();
            break;
            
        case 3:
        case 4:  // Fall-through for multiple cases
            printf("Import/Export operation...\n");
            // handle_import_export(choice);
            break;
            
        case 5:
            printf("Settings menu...\n");
            // show_settings();
            break;
            
        case 6:
            printf("Help and documentation...\n");
            // show_help();
            break;
            
        case 0:
            printf("Exiting application...\n");
            break;
            
        default:
            printf("Invalid choice. Please select 0-6.\n");
            break;
    }
}

// State machine example using switch
typedef enum {
    STATE_IDLE,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_DISCONNECTING,
    STATE_ERROR
} ConnectionState;

void process_connection_event(ConnectionState *state, int event) {
    switch (*state) {
        case STATE_IDLE:
            if (event == 1) {  // Connect event
                printf("Starting connection...\n");
                *state = STATE_CONNECTING;
            }
            break;
            
        case STATE_CONNECTING:
            if (event == 2) {  // Connection successful
                printf("Connected successfully\n");
                *state = STATE_CONNECTED;
            } else if (event == 3) {  // Connection failed
                printf("Connection failed\n");
                *state = STATE_ERROR;
            }
            break;
            
        case STATE_CONNECTED:
            if (event == 4) {  // Disconnect event
                printf("Disconnecting...\n");
                *state = STATE_DISCONNECTING;
            } else if (event == 3) {  // Connection lost
                printf("Connection lost\n");
                *state = STATE_ERROR;
            }
            break;
            
        case STATE_DISCONNECTING:
            if (event == 5) {  // Disconnect complete
                printf("Disconnected\n");
                *state = STATE_IDLE;
            }
            break;
            
        case STATE_ERROR:
            if (event == 6) {  // Reset
                printf("Resetting to idle\n");
                *state = STATE_IDLE;
            }
            break;
            
        default:
            printf("Unknown state\n");
            break;
    }
}

int main(void) {
    // Calculator demo
    printf("Calculator Demo:\n");
    printf("10 + 5 = %.2f\n", calculate(10, 5, '+'));
    printf("10 / 3 = %.2f\n", calculate(10, 3, '/'));
    printf("10 %% 3 = %.0f\n", calculate(10, 3, '%'));
    printf("10 & 5 = %.2f\n", calculate(10, 5, '&')); // Invalid operator
    
    printf("\nMenu System Demo:\n");
    int menu_choices[] = {1, 3, 7, 0};
    for (int i = 0; i < 4; i++) {
        printf("Choice %d: ", menu_choices[i]);
        handle_menu_choice(menu_choices[i]);
    }
    
    printf("\nState Machine Demo:\n");
    ConnectionState state = STATE_IDLE;
    int events[] = {1, 2, 4, 5, 6}; // Connect, Success, Disconnect, Complete, Reset
    
    for (int i = 0; i < 5; i++) {
        printf("Event %d: ", events[i]);
        process_connection_event(&state, events[i]);
    }
    
    return 0;
}
```

#### Loops: for, while, and do-while

**For Loops:**
```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Basic for loop
    printf("Basic counting:\n");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Reverse counting
    printf("Reverse counting:\n");
    for (int i = 10; i >= 0; i--) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Step by different values
    printf("Even numbers from 0 to 20:\n");
    for (int i = 0; i <= 20; i += 2) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Multiple variables in for loop
    printf("Multiple variables:\n");
    for (int i = 0, j = 10; i < j; i++, j--) {
        printf("i=%d, j=%d\n", i, j);
    }
    
    // Nested loops - multiplication table
    printf("\nMultiplication Table (5x5):\n");
    for (int i = 1; i <= 5; i++) {
        for (int j = 1; j <= 5; j++) {
            printf("%3d", i * j);
        }
        printf("\n");
    }
    
    // Loop through string characters
    char message[] = "Hello, World!";
    printf("\nCharacter analysis of '%s':\n", message);
    int vowel_count = 0;
    
    for (int i = 0; message[i] != '\0'; i++) {
        printf("message[%d] = '%c'\n", i, message[i]);
        
        // Count vowels
        char c = tolower(message[i]);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    printf("Total vowels: %d\n", vowel_count);
    
    return 0;
}
```

**While Loops:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function to demonstrate input validation with while loop
int get_valid_input(int min, int max) {
    int input;
    while (1) {
        printf("Enter a number between %d and %d: ", min, max);
        if (scanf("%d", &input) == 1) {
            if (input >= min && input <= max) {
                return input;
            } else {
                printf("Number out of range. Please try again.\n");
            }
        } else {
            printf("Invalid input. Please enter a number.\n");
            // Clear input buffer
            while (getchar() != '\n');
        }
    }
}

// Simple number guessing game
void number_guessing_game(void) {
    srand(time(NULL));
    int secret = rand() % 100 + 1;  // Random number 1-100
    int guess, attempts = 0;
    
    printf("Welcome to the Number Guessing Game!\n");
    printf("I'm thinking of a number between 1 and 100.\n");
    
    while (1) {
        printf("Enter your guess: ");
        if (scanf("%d", &guess) != 1) {
            printf("Please enter a valid number.\n");
            while (getchar() != '\n'); // Clear buffer
            continue;
        }
        
        attempts++;
        
        if (guess == secret) {
            printf("Congratulations! You guessed it in %d attempts!\n", attempts);
            break;
        } else if (guess < secret) {
            printf("Too low! Try again.\n");
        } else {
            printf("Too high! Try again.\n");
        }
        
        // Optional: Limit attempts
        if (attempts >= 10) {
            printf("Sorry, you've used all 10 attempts. The number was %d.\n", secret);
            break;
        }
    }
}

int main(void) {
    // Basic while loop - countdown
    printf("Countdown:\n");
    int count = 5;
    while (count > 0) {
        printf("%d...\n", count);
        count--;
    }
    printf("Blast off!\n");
    
    // While loop for processing data until condition met
    printf("\nProcessing data:\n");
    double values[] = {1.5, 2.3, -1.0, 4.7, 0.0, 3.2, -2.1};
    int index = 0;
    double sum = 0.0;
    
    // Process until we hit a negative number or end of array
    while (index < 7 && values[index] >= 0) {
        sum += values[index];
        printf("Added %.1f, running sum: %.1f\n", values[index], sum);
        index++;
    }
    
    if (index < 7) {
        printf("Stopped at negative value: %.1f\n", values[index]);
    }
    
    // Uncomment to run interactive examples
    // printf("\nInput validation demo:\n");
    // int user_choice = get_valid_input(1, 10);
    // printf("You entered: %d\n", user_choice);
    
    // number_guessing_game();
    
    return 0;
}
```

**Do-While Loops:**
```c
#include <stdio.h>
#include <ctype.h>

// Menu system using do-while
void display_menu(void) {
    printf("\n=== Application Menu ===\n");
    printf("1. Create new document\n");
    printf("2. Open existing document\n");
    printf("3. Save document\n");
    printf("4. Print document\n");
    printf("5. Settings\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
}

int get_menu_choice(void) {
    int choice;
    char buffer[100];
    
    do {
        display_menu();
        
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            if (sscanf(buffer, "%d", &choice) == 1) {
                if (choice >= 0 && choice <= 5) {
                    return choice;
                }
            }
        }
        
        printf("Invalid choice. Please enter 0-5.\n");
    } while (1);
}

// Data validation with do-while
double get_positive_double(const char* prompt) {
    double value;
    char buffer[100];
    
    do {
        printf("%s", prompt);
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            if (sscanf(buffer, "%lf", &value) == 1 && value > 0) {
                return value;
            }
        }
        printf("Please enter a positive number.\n");
    } while (1);
}

// Password strength checker
int check_password_strength(const char* password) {
    int length = strlen(password);
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    
    if (length < 8) {
        return 0; // Too short
    }
    
    for (int i = 0; i < length; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else if (strchr("!@#$%^&*()_+-=[]{}|;:,.<>?", password[i])) has_special = 1;
    }
    
    int strength = has_upper + has_lower + has_digit + has_special;
    return strength; // 0-4, where 4 is strongest
}

void password_creation_demo(void) {
    char password[100];
    int strength;
    
    printf("Password Creation Demo:\n");
    printf("Password must be at least 8 characters long and contain:\n");
    printf("- Uppercase letters\n- Lowercase letters\n- Numbers\n- Special characters\n\n");
    
    do {
        printf("Enter password: ");
        if (fgets(password, sizeof(password), stdin) != NULL) {
            // Remove newline
            password[strcspn(password, "\n")] = '\0';
            
            strength = check_password_strength(password);
            
            if (strength < 2) {
                printf("Password too weak (strength: %d/4). Please try again.\n", strength);
            } else {
                printf("Password accepted (strength: %d/4)\n", strength);
                break;
            }
        }
    } while (1);
}

int main(void) {
    printf("Do-While Loop Examples\n");
    printf("======================\n");
    
    // Simple do-while example
    int i = 0;
    printf("Basic do-while (executes at least once):\n");
    do {
        printf("i = %d\n", i);
        i++;
    } while (i < 3);
    
    // Compare with while loop that might not execute
    int j = 10;
    printf("\nWhile loop with initial condition false:\n");
    while (j < 3) {
        printf("j = %d\n", j); // This won't execute
        j++;
    }
    printf("j remains %d\n", j);
    
    // Do-while with same condition
    printf("\nDo-while with same condition:\n");
    do {
        printf("j = %d\n", j); // This executes once
        j++;
    } while (j < 3);
    
    // Interactive examples (commented out for demo)
    /*
    printf("\nMenu System Demo:\n");
    int choice;
    do {
        choice = get_menu_choice();
        
        switch (choice) {
            case 1: printf("Creating new document...\n"); break;
            case 2: printf("Opening existing document...\n"); break;
            case 3: printf("Saving document...\n"); break;
            case 4: printf("Printing document...\n"); break;
            case 5: printf("Opening settings...\n"); break;
            case 0: printf("Goodbye!\n"); break;
        }
        
    } while (choice != 0);
    
    // Data validation demo
    printf("\nData Validation Demo:\n");
    double radius = get_positive_double("Enter circle radius: ");
    double area = 3.14159 * radius * radius;
    printf("Circle area: %.2f\n", area);
    
    // Password demo
    password_creation_demo();
    */
    
    return 0;
}
```

#### Loop Control: break and continue

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Find first occurrence of a character in string
int find_first_char(const char* str, char target) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == target) {
            return i; // Found it, break out of loop
        }
    }
    return -1; // Not found
}

// Process array until specific condition using break
void process_until_negative(int arr[], int size) {
    printf("Processing array until negative number:\n");
    
    for (int i = 0; i < size; i++) {
        if (arr[i] < 0) {
            printf("Encountered negative number %d at index %d. Stopping.\n", 
                   arr[i], i);
            break; // Exit loop immediately
        }
        
        printf("Processing arr[%d] = %d\n", i, arr[i]);
        // Some processing logic here
    }
}

// Skip processing of certain elements using continue
void process_positive_numbers(int arr[], int size) {
    printf("\nProcessing only positive numbers:\n");
    int processed_count = 0;
    
    for (int i = 0; i < size; i++) {
        if (arr[i] <= 0) {
            printf("Skipping non-positive number: %d\n", arr[i]);
            continue; // Skip rest of loop body, go to next iteration
        }
        
        // This code only executes for positive numbers
        printf("Processing positive number: %d\n", arr[i]);
        processed_count++;
    }
    
    printf("Total positive numbers processed: %d\n", processed_count);
}

// Real-world example: Log file parser
void parse_log_entries(const char* log_data[], int num_entries) {
    printf("\nParsing log entries:\n");
    
    for (int i = 0; i < num_entries; i++) {
        // Skip empty lines
        if (strlen(log_data[i]) == 0) {
            continue;
        }
        
        // Skip comment lines (starting with #)
        if (log_data[i][0] == '#') {
            continue;
        }
        
        // Stop processing if we encounter "END" marker
        if (strncmp(log_data[i], "END", 3) == 0) {
            printf("End marker found. Stopping log processing.\n");
            break;
        }
        
        // Process valid log entry
        printf("Processing log entry %d: %s\n", i + 1, log_data[i]);
        
        // Example: Extract log level
        if (strncmp(log_data[i], "ERROR", 5) == 0) {
            printf("  -> Error detected! Needs attention.\n");
        } else if (strncmp(log_data[i], "WARN", 4) == 0) {
            printf("  -> Warning logged.\n");
        } else if (strncmp(log_data[i], "INFO", 4) == 0) {
            printf("  -> Information logged.\n");
        }
    }
}

// Nested loop control
void find_in_2d_array(int matrix[][4], int rows, int target) {
    printf("\nSearching for %d in 2D array:\n", target);
    int found = 0;
    
    for (int i = 0; i < rows && !found; i++) {
        for (int j = 0; j < 4; j++) {
            printf("Checking matrix[%d][%d] = %d\n", i, j, matrix[i][j]);
            
            if (matrix[i][j] == target) {
                printf("Found %d at position [%d][%d]\n", target, i, j);
                found = 1;
                break; // Break inner loop
            }
        }
        // The !found condition in outer loop prevents unnecessary iterations
    }
    
    if (!found) {
        printf("%d not found in matrix\n", target);
    }
}

// Input validation with break and continue
void validate_user_inputs(void) {
    printf("\nInput validation demo (enter 'quit' to stop):\n");
    char input[100];
    int valid_inputs = 0;
    
    while (1) {
        printf("Enter a positive integer (or 'quit'): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break; // End of input
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = '\0';
        
        // Check for quit command
        if (strcmp(input, "quit") == 0) {
            printf("Exiting input validation.\n");
            break;
        }
        
        // Convert to integer
        char* endptr;
        long value = strtol(input, &endptr, 10);
        
        // Check if conversion was successful and value is positive
        if (*endptr != '\0') {
            printf("Invalid input: not a number. Please try again.\n");
            continue;
        }
        
        if (value <= 0) {
            printf("Invalid input: must be positive. Please try again.\n");
            continue;
        }
        
        // Valid input - process it
        printf("Valid input received: %ld\n", value);
        valid_inputs++;
        
        if (valid_inputs >= 5) {
            printf("Collected enough valid inputs. Thank you!\n");
            break;
        }
    }
    
    printf("Total valid inputs collected: %d\n", valid_inputs);
}

int main(void) {
    // Break example with array processing
    int numbers[] = {10, 25, 33, -5, 42, 17};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    process_until_negative(numbers, size);
    
    // Continue example with same array
    process_positive_numbers(numbers, size);
    
    // Log parsing example
    const char* log_entries[] = {
        "# This is a comment",
        "",  // Empty line
        "INFO: Application started",
        "INFO: User logged in",
        "WARN: Low disk space",
        "ERROR: Database connection failed",
        "INFO: Retrying connection",
        "END",
        "INFO: This won't be processed"
    };
    
    int num_entries = sizeof(log_entries) / sizeof(log_entries[0]);
    parse_log_entries(log_entries, num_entries);
    
    // 2D array search example
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    find_in_2d_array(matrix, 3, 7);
    find_in_2d_array(matrix, 3, 15);
    
    // String search example
    const char* text = "Hello, World!";
    char search_char = 'o';
    int position = find_first_char(text, search_char);
    
    if (position != -1) {
        printf("\nFound '%c' at position %d in \"%s\"\n", 
               search_char, position, text);
    } else {
        printf("\n'%c' not found in \"%s\"\n", search_char, text);
    }
    
    // Interactive validation (commented for demo)
    // validate_user_inputs();
    
    return 0;
}
```

### 7. Functions Fundamentals {#functions-fundamentals}

Functions are the building blocks of modular C programming, enabling code reuse, organization, and abstraction.

#### Function Declaration, Definition, and Calling

**Basic Function Structure:**
```c
#include <stdio.h>
#include <math.h>

// Function declarations (prototypes)
double calculate_circle_area(double radius);
double calculate_circle_circumference(double radius);
void print_circle_info(double radius);
int factorial(int n);
double power(double base, int exponent);

// Function definitions
double calculate_circle_area(double radius) {
    if (radius < 0) {
        printf("Error: Radius cannot be negative\n");
        return -1.0;
    }
    return M_PI * radius * radius;
}

double calculate_circle_circumference(double radius) {
    if (radius < 0) {
        printf("Error: Radius cannot be negative\n");
        return -1.0;
    }
    return 2 * M_PI * radius;
}

void print_circle_info(double radius) {
    printf("\nCircle Information (radius = %.2f):\n", radius);
    printf("Area: %.2f square units\n", calculate_circle_area(radius));
    printf("Circumference: %.2f units\n", calculate_circle_circumference(radius));
}

// Recursive function
int factorial(int n) {
    if (n < 0) {
        printf("Error: Factorial not defined for negative numbers\n");
        return -1;
    }
    if (n == 0 || n == 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Iterative alternative to power function
double power(double base, int exponent) {
    if (exponent == 0) return 1.0;
    
    double result = 1.0;
    int abs_exp = abs(exponent);
    
    for (int i = 0; i < abs_exp; i++) {
        result *= base;
    }
    
    return (exponent < 0) ? 1.0 / result : result;
}

int main(void) {
    // Function calls
    double radius = 5.0;
    print_circle_info(radius);
    
    // Factorial examples
    printf("\nFactorial calculations:\n");
    for (int i = 0; i <= 10; i++) {
        printf("%d! = %d\n", i, factorial(i));
    }
    
    // Power function examples
    printf("\nPower calculations:\n");
    printf("2^8 = %.0f\n", power(2.0, 8));
    printf("3^4 = %.0f\n", power(3.0, 4));
    printf("2^(-3) = %.3f\n", power(2.0, -3));
    
    return 0;
}
```

#### Parameter Passing: Pass by Value vs Pass by Reference

**Pass by Value (Default in C):**
```c
#include <stdio.h>

// Pass by value - function receives copies of arguments
void modify_value(int x) {
    printf("Inside modify_value: x = %d\n", x);
    x = 100;  // This only modifies the local copy
    printf("Inside modify_value after change: x = %d\n", x);
}

// Function that returns a modified value
int double_value(int x) {
    return x * 2;
}

// Pass by reference using pointers
void modify_by_reference(int *x) {
    printf("Inside modify_by_reference: *x = %d\n", *x);
    *x = 200;  // This modifies the original variable
    printf("Inside modify_by_reference after change: *x = %d\n", *x);
}

// Swap function - demonstrates why pointers are necessary
void swap_values(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

// Function that modifies an array (arrays are always passed by reference)
void modify_array(int arr[], int size) {
    printf("Inside modify_array, modifying elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;  // Double each element
        printf("arr[%d] = %d\n", i, arr[i]);
    }
}

// Calculate array statistics using pointers for output parameters
void calculate_stats(int arr[], int size, int *min, int *max, double *average) {
    if (size <= 0) return;
    
    *min = arr[0];
    *max = arr[0];
    int sum = 0;
    
    for (int i = 0; i < size; i++) {
        sum += arr[i];
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
    }
    
    *average = (double)sum / size;
}

int main(void) {
    // Pass by value demonstration
    printf("Pass by Value Demo:\n");
    int original = 42;
    printf("Before function call: original = %d\n", original);
    modify_value(original);
    printf("After function call: original = %d\n", original);  // Still 42
    
    // Returning modified value
    int doubled = double_value(original);
    printf("Double of %d is %d\n", original, doubled);
    
    printf("\nPass by Reference Demo:\n");
    printf("Before function call: original = %d\n", original);
    modify_by_reference(&original);  // Pass address of original
    printf("After function call: original = %d\n", original);   // Now 200
    
    // Swap demonstration
    printf("\nSwap Demo:\n");
    int x = 10, y = 20;
    printf("Before swap: x = %d, y = %d\n", x, y);
    swap_values(&x, &y);
    printf("After swap: x = %d, y = %d\n", x, y);
    
    // Array modification
    printf("\nArray Modification Demo:\n");
    int numbers[] = {1, 2, 3, 4, 5};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    printf("Original array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    modify_array(numbers, size);
    
    printf("Array after modification: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Statistics calculation
    printf("\nArray Statistics Demo:\n");
    int data[] = {15, 23, 8, 42, 16, 4, 38, 12};
    int data_size = sizeof(data) / sizeof(data[0]);
    int min, max;
    double avg;
    
    calculate_stats(data, data_size, &min, &max, &avg);
    printf("Array: ");
    for (int i = 0; i < data_size; i++) {
        printf("%d ", data[i]);
    }
    printf("\nMin: %d, Max: %d, Average: %.2f\n", min, max, avg);
    
    return 0;
}
```

#### Return Values and Multiple Return Values

**Single Return Values:**
```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// Return different types
int add(int a, int b) {
    return a + b;
}

double calculate_bmi(double weight_kg, double height_m) {
    if (height_m <= 0) {
        return -1.0; // Error indicator
    }
    return weight_kg / (height_m * height_m);
}

// Return boolean (using stdbool.h)
bool is_prime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

// Return pointer to string
char* get_grade_description(char grade) {
    switch (grade) {
        case 'A': return "Excellent";
        case 'B': return "Good";
        case 'C': return "Average";
        case 'D': return "Below Average";
        case 'F': return "Failing";
        default: return "Invalid Grade";
    }
}

// Multiple return values using structure
typedef struct {
    int quotient;
    int remainder;
    bool valid;
} DivisionResult;

DivisionResult divide_with_remainder(int dividend, int divisor) {
    DivisionResult result;
    
    if (divisor == 0) {
        result.quotient = 0;
        result.remainder = 0;
        result.valid = false;
    } else {
        result.quotient = dividend / divisor;
        result.remainder = dividend % divisor;
        result.valid = true;
    }
    
    return result;
}

// Multiple return values using output parameters
void polar_to_cartesian(double radius, double angle_radians, 
                       double *x, double *y) {
    *x = radius * cos(angle_radians);
    *y = radius * sin(angle_radians);
}

// String processing with multiple outputs
typedef struct {
    int length;
    int word_count;
    int vowel_count;
    int digit_count;
} StringAnalysis;

StringAnalysis analyze_string(const char *str) {
    StringAnalysis analysis = {0, 0, 0, 0};
    bool in_word = false;
    
    for (int i = 0; str[i] != '\0'; i++) {
        analysis.length++;
        
        char c = tolower(str[i]);
        
        // Count words
        if (isalpha(str[i])) {
            if (!in_word) {
                analysis.word_count++;
                in_word = true;
            }
        } else {
            in_word = false;
        }
        
        // Count vowels
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            analysis.vowel_count++;
        }
        
        // Count digits
        if (isdigit(str[i])) {
            analysis.digit_count++;
        }
    }
    
    return analysis;
}

int main(void) {
    // Simple return values
    printf("Addition: 15 + 27 = %d\n", add(15, 27));
    
    double bmi = calculate_bmi(70.0, 1.75);
    printf("BMI: %.2f\n", bmi);
    
    // Boolean return
    printf("\nPrime number check:\n");
    for (int i = 10; i <= 20; i++) {
        printf("%d is %s\n", i, is_prime(i) ? "prime" : "not prime");
    }
    
    // String return
    printf("\nGrade descriptions:\n");
    char grades[] = {'A', 'C', 'F', 'X'};
    for (int i = 0; i < 4; i++) {
        printf("Grade %c: %s\n", grades[i], get_grade_description(grades[i]));
    }
    
    // Multiple return values with structure
    printf("\nDivision with remainder:\n");
    DivisionResult div_result = divide_with_remainder(17, 5);
    if (div_result.valid) {
        printf("17 ÷ 5 = %d remainder %d\n", 
               div_result.quotient, div_result.remainder);
    }
    
    div_result = divide_with_remainder(10, 0);
    if (!div_result.valid) {
        printf("Division by zero detected\n");
    }
    
    // Multiple return values with output parameters
    printf("\nPolar to Cartesian conversion:\n");
    double x, y;
    polar_to_cartesian(5.0, M_PI / 4, &x, &y);  // 45 degrees
    printf("Polar (5.0, π/4) = Cartesian (%.2f, %.2f)\n", x, y);
    
    // String analysis
    printf("\nString analysis:\n");
    const char *text = "Hello World! I have 123 characters.";
    StringAnalysis analysis = analyze_string(text);
    
    printf("Text: \"%s\"\n", text);
    printf("Length: %d characters\n", analysis.length);
    printf("Words: %d\n", analysis.word_count);
    printf("Vowels: %d\n", analysis.vowel_count);
    printf("Digits: %d\n", analysis.digit_count);
    
    return 0;
}
```

#### Function Pointers and Callbacks

Function pointers enable powerful programming patterns like callbacks, function tables, and dynamic behavior selection.

**Basic Function Pointers:**
```c
#include <stdio.h>
#include <stdlib.h>

// Simple mathematical functions
double add_double(double a, double b) { return a + b; }
double subtract_double(double a, double b) { return a - b; }
double multiply_double(double a, double b) { return a * b; }
double divide_double(double a, double b) { 
    return (b != 0) ? a / b : 0.0; 
}

// Function that takes a function pointer as parameter
double apply_operation(double x, double y, double (*operation)(double, double)) {
    return operation(x, y);
}

// Array of function pointers for calculator
typedef double (*MathOperation)(double, double);

// Calculator using function pointer array
void calculator_demo(void) {
    MathOperation operations[] = {
        add_double,
        subtract_double,
        multiply_double,
        divide_double
    };
    
    const char *op_names[] = {"Addition", "Subtraction", "Multiplication", "Division"};
    double a = 15.0, b = 4.0;
    
    printf("Calculator Demo (%.1f and %.1f):\n", a, b);
    for (int i = 0; i < 4; i++) {
        double result = operations[i](a, b);
        printf("%s: %.2f\n", op_names[i], result);
    }
}

// Callback example: Processing arrays with different functions
typedef void (*ArrayProcessor)(int[], int);

void print_array(int arr[], int size) {
    printf("Array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

void double_array(int arr[], int size) {
    printf("Doubling array elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}

void square_array(int arr[], int size) {
    printf("Squaring array elements:\n");
    for (int i = 0; i < size; i++) {
        arr[i] *= arr[i];
    }
}

void process_array(int arr[], int size, ArrayProcessor processor) {
    processor(arr, size);
}

// Real-world example: Event handling system
typedef enum {
    EVENT_CLICK,
    EVENT_KEYPRESS,
    EVENT_MOUSE_MOVE,
    EVENT_WINDOW_CLOSE
} EventType;

typedef struct {
    EventType type;
    int x, y;  // For mouse events
    char key;  // For key events
} Event;

typedef void (*EventHandler)(Event*);

// Event handlers
void handle_click(Event *e) {
    printf("Click handled at (%d, %d)\n", e->x, e->y);
}

void handle_keypress(Event *e) {
    printf("Key '%c' pressed\n", e->key);
}

void handle_mouse_move(Event *e) {
    printf("Mouse moved to (%d, %d)\n", e->x, e->y);
}

void handle_window_close(Event *e) {
    printf("Window close requested\n");
}

// Event system
typedef struct {
    EventHandler handlers[4];
} EventSystem;

void register_handlers(EventSystem *system) {
    system->handlers[EVENT_CLICK] = handle_click;
    system->handlers[EVENT_KEYPRESS] = handle_keypress;
    system->handlers[EVENT_MOUSE_MOVE] = handle_mouse_move;
    system->handlers[EVENT_WINDOW_CLOSE] = handle_window_close;
}

void dispatch_event(EventSystem *system, Event *event) {
    if (event->type >= 0 && event->type < 4) {
        system->handlers[event->type](event);
    }
}

// Sorting with comparison function pointers
typedef int (*ComparisonFunc)(const void *a, const void *b);

int compare_int_ascending(const void *a, const void *b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);  // Clever comparison
}

int compare_int_descending(const void *a, const void *b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ib > ia) - (ib < ia);
}

void print_int_array(int arr[], int size, const char* label) {
    printf("%s: ", label);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    // Basic function pointer usage
    printf("Function Pointer Basics:\n");
    double (*math_op)(double, double) = add_double;
    printf("Using function pointer for addition: %.2f\n", math_op(10.5, 3.7));
    
    math_op = multiply_double;
    printf("Using same pointer for multiplication: %.2f\n", math_op(10.5, 3.7));
    
    // Using function pointer as parameter
    printf("\nFunction as Parameter:\n");
    printf("Apply addition: %.2f\n", apply_operation(8.0, 2.0, add_double));
    printf("Apply division: %.2f\n", apply_operation(8.0, 2.0, divide_double));
    
    // Calculator demo
    printf("\n");
    calculator_demo();
    
    // Array processing with callbacks
    printf("\nArray Processing with Callbacks:\n");
    int numbers[] = {2, 4, 6, 8, 10};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    
    process_array(numbers, size, print_array);
    process_array(numbers, size, double_array);
    process_array(numbers, size, print_array);
    
    // Reset array
    int numbers2[] = {2, 4, 6, 8, 10};
    process_array(numbers2, size, square_array);
    process_array(numbers2, size, print_array);
    
    // Event handling system
    printf("\nEvent Handling System:\n");
    EventSystem event_system;
    register_handlers(&event_system);
    
    Event events[] = {
        {EVENT_CLICK, 100, 200, 0},
        {EVENT_KEYPRESS, 0, 0, 'A'},
        {EVENT_MOUSE_MOVE, 150, 250, 0},
        {EVENT_WINDOW_CLOSE, 0, 0, 0}
    };
    
    for (int i = 0; i < 4; i++) {
        dispatch_event(&event_system, &events[i]);
    }
    
    // Sorting with function pointers
    printf("\nSorting with Function Pointers:\n");
    int data[] = {64, 34, 25, 12, 22, 11, 90};
    int data_size = sizeof(data) / sizeof(data[0]);
    
    // Make copies for different sorts
    int ascending[7], descending[7];
    memcpy(ascending, data, sizeof(data));
    memcpy(descending, data, sizeof(data));
    
    print_int_array(data, data_size, "Original");
    
    qsort(ascending, data_size, sizeof(int), compare_int_ascending);
    print_int_array(ascending, data_size, "Ascending");
    
    qsort(descending, data_size, sizeof(int), compare_int_descending);
    print_int_array(descending, data_size, "Descending");
    
    return 0;
}
```

### 8. Scope and Storage Classes {#scope-storage}

Understanding scope and storage classes is crucial for writing maintainable and efficient C programs.

#### Local vs Global Scope

```c
#include <stdio.h>

// Global variables - accessible throughout the program
int global_counter = 0;
const char* program_name = "Scope Demo";

// Global function accessible from other files (external linkage)
void increment_global_counter(void) {
    global_counter++;
    printf("Global counter incremented to: %d\n", global_counter);
}

// Static global function - only accessible within this file
static void internal_helper(void) {
    printf("This function has internal linkage\n");
}

void demonstrate_local_scope(void) {
    // Local variables - only accessible within this function
    int local_var = 10;
    printf("Local variable: %d\n", local_var);
    
    // Block scope
    {
        int block_var = 20;
        int local_var = 30;  // Shadows the outer local_var
        printf("Block scope - local_var: %d, block_var: %d\n", 
               local_var, block_var);
    }
    
    // block_var is no longer accessible here
    printf("After block - local_var: %d\n", local_var);
    
    // Local variable shadows global
    int global_counter = 100;  // Shadows global global_counter
    printf("Local global_counter: %d\n", global_counter);
}

void demonstrate_scope_rules(void) {
    printf("\n=== Scope Rules Demo ===\n");
    
    // Access global variables
    printf("Program: %s\n", program_name);
    printf("Global counter: %d\n", global_counter);
    
    // Call functions with different scope
    demonstrate_local_scope();
    increment_global_counter();
    internal_helper();  // Can call static function within same file
    
    // Loop variable scope (C99 and later)
    for (int i = 0; i < 3; i++) {
        printf("Loop iteration: %d\n", i);
    }
    // i is not accessible here in C99+ mode
}

// Function parameters have function scope
int calculate_area(int width, int height) {
    // width and height are accessible throughout the function
    if (width <= 0 || height <= 0) {
        printf("Invalid dimensions\n");
        return -1;
    }
    
    int area = width * height;  // Local variable
    return area;
}

int main(void) {
    demonstrate_scope_rules();
    
    // Function parameter scope
    int w = 5, h = 10;
    int result = calculate_area(w, h);
    printf("Area calculation result: %d\n", result);
    
    return 0;
}
```

#### Static Variables and Functions

```c
#include <stdio.h>

// Static global variable - internal linkage (file scope only)
static int file_local_counter = 0;

// Regular function counter using static local variable
int get_next_id(void) {
    static int id_counter = 1000;  // Initialized only once
    return ++id_counter;
}

// Function call counter
void function_with_static(void) {
    static int call_count = 0;  // Retains value between calls
    int local_count = 0;        // Reset every call
    
    call_count++;
    local_count++;
    
    printf("Call #%d: static_count = %d, local_count = %d\n",
           call_count, call_count, local_count);
}

// Static function - internal linkage
static void helper_function(void) {
    printf("This static function is only accessible within this file\n");
    file_local_counter++;
}

// Demonstrate static array initialization
void static_array_demo(void) {
    static int numbers[5] = {1, 2, 3, 4, 5};  // Initialized once
    static int initialized = 0;
    
    if (!initialized) {
        printf("Static array initialized\n");
        initialized = 1;
    }
    
    printf("Static array contents: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
        numbers[i] *= 2;  // Modify for next call
    }
    printf("\n");
}

// Real-world example: Simple cache implementation
typedef struct {
    int key;
    int value;
    int valid;
} CacheEntry;

int cached_expensive_calculation(int input) {
    static CacheEntry cache[10] = {0};  // Static cache array
    static int cache_size = 0;
    
    // Check if result is cached
    for (int i = 0; i < cache_size; i++) {
        if (cache[i].valid && cache[i].key == input) {
            printf("Cache hit for input %d\n", input);
            return cache[i].value;
        }
    }
    
    // Simulate expensive calculation
    printf("Performing expensive calculation for input %d\n", input);
    int result = input * input + 2 * input + 1;  // Some computation
    
    // Store in cache if there's room
    if (cache_size < 10) {
        cache[cache_size].key = input;
        cache[cache_size].value = result;
        cache[cache_size].valid = 1;
        cache_size++;
        printf("Result cached (cache size: %d)\n", cache_size);
    }
    
    return result;
}

// Configuration system using static variables
typedef struct {
    int debug_level;
    int max_connections;
    char log_file[256];
} Config;

Config* get_config(void) {
    static Config config = {
        .debug_level = 1,
        .max_connections = 100,
        .log_file = "application.log"
    };
    
    static int initialized = 0;
    if (!initialized) {
        printf("Configuration initialized with defaults\n");
        initialized = 1;
    }
    
    return &config;
}

void set_debug_level(int level) {
    Config* config = get_config();
    config->debug_level = level;
    printf("Debug level set to: %d\n", level);
}

int get_debug_level(void) {
    return get_config()->debug_level;
}

int main(void) {
    printf("=== Static Variables Demo ===\n");
    
    // Static local variables
    printf("\nStatic local variable demo:\n");
    for (int i = 0; i < 5; i++) {
        function_with_static();
    }
    
    // ID generation with static
    printf("\nID generation:\n");
    for (int i = 0; i < 5; i++) {
        printf("Generated ID: %d\n", get_next_id());
    }
    
    // Static array demo
    printf("\nStatic array demo:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d: ", i + 1);
        static_array_demo();
    }
    
    // Static function demo
    printf("\nStatic function demo:\n");
    helper_function();
    printf("File local counter: %d\n", file_local_counter);
    
    // Cache demo
    printf("\nCache implementation demo:\n");
    int test_inputs[] = {5, 3, 5, 7, 3, 9, 5};
    for (int i = 0; i < 7; i++) {
        int result = cached_expensive_calculation(test_inputs[i]);
        printf("Input: %d, Result: %d\n", test_inputs[i], result);
    }
    
    // Configuration system demo
    printf("\nConfiguration system demo:\n");
    Config* config = get_config();
    printf("Initial debug level: %d\n", get_debug_level());
    
    set_debug_level(3);
    printf("Updated debug level: %d\n", get_debug_level());
    printf("Max connections: %d\n", config->max_connections);
    
    return 0;
}
```

#### External and Internal Linkage

Understanding linkage is crucial for multi-file programs.

**File 1: main.c**
```c
/* main.c - Demonstrates external and internal linkage */
#include <stdio.h>

// External declarations (defined in other files)
extern int shared_counter;           // Defined in utils.c
extern void increment_shared(void);  // Defined in utils.c
extern void print_shared(void);     // Defined in utils.c

// External function declaration
void demonstrate_linkage(void);     // Defined below

// Global variable with external linkage (available to other files)
int main_global = 100;

// Static global variable with internal linkage (file scope only)
static int main_local = 200;

// Static function with internal linkage
static void internal_function(void) {
    printf("This function is only accessible within main.c\n");
    printf("main_local = %d\n", main_local);
}

// Function with external linkage (default for functions)
void demonstrate_linkage(void) {
    printf("=== Linkage Demonstration ===\n");
    
    printf("main_global (external): %d\n", main_global);
    printf("main_local (static): %d\n", main_local);
    
    internal_function();
    
    printf("shared_counter (external): %d\n", shared_counter);
    increment_shared();
    print_shared();
}

int main(void) {
    demonstrate_linkage();
    
    // Call external functions
    printf("\nCalling external functions:\n");
    increment_shared();
    increment_shared();
    print_shared();
    
    return 0;
}
```

**File 2: utils.c**
```c
/* utils.c - Utility functions and variables */
#include <stdio.h>

// External variable accessible from other files
int shared_counter = 0;

// Static variable - internal linkage (only accessible in this file)
static int internal_counter = 1000;

// External function - accessible from other files
void increment_shared(void) {
    shared_counter++;
    internal_counter++;
    printf("Incremented: shared=%d, internal=%d\n", 
           shared_counter, internal_counter);
}

// External function
void print_shared(void) {
    printf("Current shared_counter: %d\n", shared_counter);
}

// Static function - internal linkage only
static void internal_utility(void) {
    printf("Internal utility function called\n");
}

// Function that uses internal static function
void call_internal(void) {
    internal_utility();
}

// Access external variable from main.c
extern int main_global;

void access_main_global(void) {
    printf("Accessing main_global from utils.c: %d\n", main_global);
    main_global += 50;
    printf("Modified main_global: %d\n", main_global);
}
```

**Complete Linkage Example:**
```c
/* complete_linkage_demo.c - Self-contained linkage demonstration */
#include <stdio.h>

// === Global Variables with Different Linkage ===

// External linkage - accessible from other translation units
int global_external = 10;

// Internal linkage - only accessible within this file
static int global_internal = 20;

// === Function Declarations ===

// External linkage function (default)
void external_function(void);

// Internal linkage function
static void internal_function(void);

// === Function Definitions ===

void external_function(void) {
    printf("External function called\n");
    printf("Can access global_external: %d\n", global_external);
    printf("Can access global_internal: %d\n", global_internal);
    
    // Can call internal function from same file
    internal_function();
}

static void internal_function(void) {
    static int call_count = 0;  // Static local variable
    call_count++;
    
    printf("Internal function called (call #%d)\n", call_count);
    printf("Modifying global_internal: %d -> ", global_internal);
    global_internal += 5;
    printf("%d\n", global_internal);
}

// Function to demonstrate const linkage
const int const_global = 42;  // External linkage
static const int const_internal = 84;  // Internal linkage

void demonstrate_const_linkage(void) {
    printf("const_global (external): %d\n", const_global);
    printf("const_internal (internal): %d\n", const_internal);
}

// === Storage Class Summary ===
void storage_class_summary(void) {
    // auto storage class (default for local variables)
    auto int auto_var = 1;
    
    // register storage class (hint to compiler)
    register int reg_var = 2;
    
    // static storage class (retains value, internal linkage)
    static int static_var = 3;
    
    // No extern needed here since we're not declaring, just using
    printf("\nStorage Class Summary:\n");
    printf("auto variable: %d\n", auto_var);
    printf("register variable: %d\n", reg_var);
    printf("static variable: %d\n", static_var);
    
    static_var++;  // Will retain this change
}

int main(void) {
    printf("=== Complete Linkage Demonstration ===\n");
    
    // Access global variables
    printf("global_external: %d\n", global_external);
    printf("global_internal: %d\n", global_internal);
    
    // Call functions
    external_function();
    
    // Note: Cannot call internal_function directly from outside
    // internal_function();  // This would cause a compilation error
    
    // Demonstrate const linkage
    printf("\n");
    demonstrate_const_linkage();
    
    // Storage class demonstration
    printf("\nCalling storage_class_summary multiple times:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d:\n", i + 1);
        storage_class_summary();
    }
    
    // Show final state
    printf("\nFinal global values:\n");
    printf("global_external: %d\n", global_external);
    printf("global_internal: %d\n", global_internal);
    
    return 0;
}
```

#### Storage Duration

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Static storage duration - global variables
int global_static_duration = 100;
static int file_static_duration = 200;

// Function to demonstrate automatic storage duration
void automatic_storage_demo(void) {
    // Automatic storage duration - local variables
    int local_auto = 10;        // Destroyed when function exits
    char local_array[100];      // Also automatic storage
    
    printf("Automatic storage - local_auto: %d\n", local_auto);
    
    // Modify local variables
    local_auto += 5;
    strcpy(local_array, "Hello from automatic storage");
    printf("Modified local_auto: %d\n", local_auto);
    printf("Local array: %s\n", local_array);
    
    // These variables will be destroyed when function returns
}

// Function to demonstrate static storage duration (local static)
void static_local_demo(void) {
    static int persistent_counter = 0;  // Static storage duration
    int temporary_counter = 0;          // Automatic storage duration
    
    persistent_counter++;
    temporary_counter++;
    
    printf("Static local: %d, Automatic local: %d\n", 
           persistent_counter, temporary_counter);
    
    // persistent_counter retains its value between calls
    // temporary_counter is reset to 0 each call
}

// Dynamic storage duration examples
void dynamic_storage_demo(void) {
    printf("\n=== Dynamic Storage Duration ===\n");
    
    // Allocate dynamic memory
    int *dynamic_array = malloc(5 * sizeof(int));
    if (dynamic_array == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Initialize dynamic memory
    for (int i = 0; i < 5; i++) {
        dynamic_array[i] = i * 10;
    }
    
    printf("Dynamic array contents: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", dynamic_array[i]);
    }
    printf("\n");
    
    // Dynamic memory persists until explicitly freed
    // (Even after this function returns, if we don't free it)
    
    // Allocate and initialize a string
    char *dynamic_string = malloc(50);
    if (dynamic_string != NULL) {
        strcpy(dynamic_string, "Dynamic string");
        printf("Dynamic string: %s\n", dynamic_string);
        
        // Must free dynamic memory
        free(dynamic_string);
        dynamic_string = NULL;  // Good practice
    }
    
    // Free the array
    free(dynamic_array);
    dynamic_array = NULL;
    
    printf("Dynamic memory freed\n");
}

// Thread-local storage duration (C11 feature)
// Note: This requires C11 compiler support
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 201112L
#include <threads.h>
_Thread_local int thread_local_var = 0;

void thread_local_demo(void) {
    printf("Thread-local variable: %d\n", thread_local_var);
    thread_local_var++;
}
#endif
#endif

// Real-world example: Memory pool for frequent allocations
typedef struct MemoryBlock {
    void *data;
    size_t size;
    int in_use;
    struct MemoryBlock *next;
} MemoryBlock;

typedef struct {
    MemoryBlock *blocks;
    size_t block_size;
    int total_blocks;
    int used_blocks;
} MemoryPool;

static MemoryPool global_pool = {NULL, 0, 0, 0};  // Static storage duration

void initialize_memory_pool(size_t block_size, int num_blocks) {
    global_pool.block_size = block_size;
    global_pool.total_blocks = num_blocks;
    global_pool.used_blocks = 0;
    
    // Allocate blocks (dynamic storage duration)
    for (int i = 0; i < num_blocks; i++) {
        MemoryBlock *block = malloc(sizeof(MemoryBlock));
        if (block == NULL) break;
        
        block->data = malloc(block_size);
        if (block->data == NULL) {
            free(block);
            break;
        }
        
        block->size = block_size;
        block->in_use = 0;
        block->next = global_pool.blocks;
        global_pool.blocks = block;
    }
    
    printf("Memory pool initialized: %d blocks of %zu bytes each\n", 
           num_blocks, block_size);
}

void* pool_allocate(void) {
    MemoryBlock *current = global_pool.blocks;
    
    while (current != NULL) {
        if (!current->in_use) {
            current->in_use = 1;
            global_pool.used_blocks++;
            printf("Allocated block from pool (used: %d/%d)\n", 
                   global_pool.used_blocks, global_pool.total_blocks);
            return current->data;
        }
        current = current->next;
    }
    
    printf("No available blocks in pool\n");
    return NULL;
}

void pool_free(void *ptr) {
    MemoryBlock *current = global_pool.blocks;
    
    while (current != NULL) {
        if (current->data == ptr && current->in_use) {
            current->in_use = 0;
            global_pool.used_blocks--;
            printf("Block returned to pool (used: %d/%d)\n", 
                   global_pool.used_blocks, global_pool.total_blocks);
            return;
        }
        current = current->next;
    }
    
    printf("Block not found in pool\n");
}

void cleanup_memory_pool(void) {
    MemoryBlock *current = global_pool.blocks;
    int freed_count = 0;
    
    while (current != NULL) {
        MemoryBlock *next = current->next;
        free(current->data);
        free(current);
        current = next;
        freed_count++;
    }
    
    global_pool.blocks = NULL;
    global_pool.used_blocks = 0;
    printf("Memory pool cleaned up: %d blocks freed\n", freed_count);
}

int main(void) {
    printf("=== Storage Duration Demonstration ===\n");
    
    // Static storage duration
    printf("Global static storage:\n");
    printf("global_static_duration: %d\n", global_static_duration);
    printf("file_static_duration: %d\n", file_static_duration);
    
    // Automatic storage duration
    printf("\nAutomatic storage duration:\n");
    for (int i = 0; i < 3; i++) {
        printf("Call %d: ", i + 1);
        automatic_storage_demo();
    }
    
    // Static local storage duration
    printf("\nStatic local storage duration:\n");
    for (int i = 0; i < 5; i++) {
        printf("Call %d: ", i + 1);
        static_local_demo();
    }
    
    // Dynamic storage duration
    dynamic_storage_demo();
    
    // Thread-local storage (if supported)
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 201112L
    printf("\nThread-local storage (C11):\n");
    for (int i = 0; i < 3; i++) {
        thread_local_demo();
    }
#endif
#endif
    
    // Memory pool demonstration
    printf("\nMemory Pool Demonstration:\n");
    initialize_memory_pool(256, 5);
    
    // Allocate some blocks
    void *ptr1 = pool_allocate();
    void *ptr2 = pool_allocate();
    void *ptr3 = pool_allocate();
    
    // Use the memory
    if (ptr1) strcpy((char*)ptr1, "Block 1 data");
    if (ptr2) strcpy((char*)ptr2, "Block 2 data");
    
    // Free some blocks
    pool_free(ptr2);
    
    // Allocate again (should reuse freed block)
    void *ptr4 = pool_allocate();
    if (ptr4) strcpy((char*)ptr4, "Block 4 data (reused)");
    
    // Display memory contents
    if (ptr1) printf("ptr1 contents: %s\n", (char*)ptr1);
    if (ptr3) printf("ptr3 contents: %s\n", (char*)ptr3);
    if (ptr4) printf("ptr4 contents: %s\n", (char*)ptr4);
    
    // Clean up
    pool_free(ptr1);
    pool_free(ptr3);
    pool_free(ptr4);
    cleanup_memory_pool();
    
    return 0;
}
```

### 9. Basic Input/Output Operations {#basic-io}

Input/output operations are fundamental to interactive C programs. C provides both formatted and unformatted I/O functions.

#### Formatted Input/Output: printf and scanf

**printf Family Functions:**
```c
#include <stdio.h>
#include <stdarg.h>

// Custom printf-like function demonstration
void debug_printf(const char *format, ...) {
    printf("[DEBUG] ");
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int main(void) {
    // === Basic printf Usage ===
    printf("=== printf Format Specifiers ===\n");
    
    // Integer formats
    int num = 42;
    printf("Decimal: %d\n", num);
    printf("Octal: %o\n", num);
    printf("Hexadecimal: %x (lowercase), %X (uppercase)\n", num, num);
    printf("With field width: %5d\n", num);
    printf("With leading zeros: %05d\n", num);
    printf("Left-justified: %-5d|\n", num);
    
    // Floating-point formats
    double pi = 3.14159265359;
    printf("\nFloating-point formats:\n");
    printf("Default: %f\n", pi);
    printf("Scientific: %e\n", pi);
    printf("Scientific (uppercase): %E\n", pi);
    printf("Shorter of f/e: %g\n", pi);
    printf("Precision control: %.3f\n", pi);
    printf("Field width and precision: %10.4f\n", pi);
    
    // Character and string formats
    char ch = 'A';
    char name[] = "Alice";
    printf("\nCharacter and string formats:\n");
    printf("Character: %c (ASCII: %d)\n", ch, ch);
    printf("String: %s\n", name);
    printf("String with width: %10s|\n", name);
    printf("String left-justified: %-10s|\n", name);
    printf("String with precision: %.3s\n", name);
    
    // Pointer format
    int *ptr = &num;
    printf("\nPointer format:\n");
    printf("Pointer address: %p\n", (void*)ptr);
    printf("Pointer value: %d\n", *ptr);
    
    // Size and count formats
    size_t size = sizeof(int);
    printf("\nSize format:\n");
    printf("Size of int: %zu bytes\n", size);
    
    // Advanced formatting
    printf("\n=== Advanced printf Features ===\n");
    
    // Dynamic field width and precision
    int width = 10, precision = 3;
    printf("Dynamic formatting: %*.*f\n", width, precision, pi);
    
    // Positional parameters (not standard C, but GNU extension)
    // printf("Reorder: %2$s is %1$d years old\n", 25, "Bob");
    
    // Using sprintf for string formatting
    char buffer[100];
    int written = sprintf(buffer, "Formatted: %d %.2f %s", num, pi, name);
    printf("sprintf result: %s (wrote %d chars)\n", buffer, written);
    
    // Using snprintf for safe string formatting
    char safe_buffer[20];
    int would_write = snprintf(safe_buffer, sizeof(safe_buffer), 
                              "Very long string: %d %.6f %s", num, pi, name);
    printf("snprintf result: %s\n", safe_buffer);
    printf("Would write %d chars (buffer size: %zu)\n", would_write, sizeof(safe_buffer));
    
    // Custom debug function
    debug_printf("Custom printf: value=%d, pi=%.2f\n", num, pi);
    
    return 0;
}
```

**scanf Family Functions and Input Validation:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Safe integer input function
int safe_get_int(const char *prompt, int min, int max) {
    char buffer[100];
    int value;
    char *endptr;
    
    while (1) {
        printf("%s", prompt);
        
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            printf("Error reading input\n");
            continue;
        }
        
        // Remove newline
        buffer[strcspn(buffer, "\n")] = '\0';
        
        // Convert to integer
        errno = 0;
        value = strtol(buffer, &endptr, 10);
        
        // Check for conversion errors
        if (errno == ERANGE) {
            printf("Number out of range. Please try again.\n");
            continue;
        }
        
        if (endptr == buffer || *endptr != '\0') {
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        
        if (value < min || value > max) {
            printf("Value must be between %d and %d. Please try again.\n", min, max);
            continue;
        }
        
        return value;
    }
}

// Safe string input function
void safe_get_string(const char *prompt, char *buffer, size_t buffer_size) {
    while (1) {
        printf("%s", prompt);
        
        if (fgets(buffer, buffer_size, stdin) != NULL) {
            // Remove trailing newline
            buffer[strcspn(buffer, "\n")] = '\0';
            
            if (strlen(buffer) > 0) {
                return; // Valid non-empty string
            }
        }
        
        printf("Please enter a valid string.\n");
    }
}

// Demonstrate scanf variations
void scanf_demonstration(void) {
    printf("\n=== scanf Demonstration ===\n");
    printf("Note: This demo uses scanf for educational purposes.\n");
    printf("In real applications, prefer safer alternatives.\n");
    
    // Basic scanf usage (commented out for safety)
    /*
    int age;
    printf("Enter your age: ");
    if (scanf("%d", &age) == 1) {
        printf("You entered: %d\n", age);
    } else {
        printf("Invalid input\n");
    }
    
    // Clear input buffer after scanf
    while (getchar() != '\n');
    
    // Multiple inputs
    int day, month, year;
    printf("Enter date (dd mm yyyy): ");
    if (scanf("%d %d %d", &day, &month, &year) == 3) {
        printf("Date: %02d/%02d/%04d\n", day, month, year);
    }
    
    // String input with scanf (dangerous without width limit)
    char name[50];
    printf("Enter name (max 49 chars): ");
    scanf("%49s", name);  // Limit input to prevent buffer overflow
    printf("Hello, %s!\n", name);
    */
    
    printf("Skipping interactive scanf demo for safety.\n");
}

// Real-world input validation example
typedef struct {
    char name[50];
    int age;
    double salary;
    char email[100];
} Employee;

Employee input_employee_data(void) {
    Employee emp = {0};
    
    printf("\n=== Employee Data Entry ===\n");
    
    // Get name
    safe_get_string("Enter employee name: ", emp.name, sizeof(emp.name));
    
    // Get age with validation
    emp.age = safe_get_int("Enter age (18-100): ", 18, 100);
    
    // Get salary
    char buffer[100];
    while (1) {
        printf("Enter salary: $");
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            char *endptr;
            emp.salary = strtod(buffer, &endptr);
            
            if (endptr != buffer && (*endptr == '\n' || *endptr == '\0')) {
                if (emp.salary >= 0) {
                    break;
                }
            }
        }
        printf("Please enter a valid positive number.\n");
    }
    
    // Get email
    safe_get_string("Enter email: ", emp.email, sizeof(emp.email));
    
    return emp;
}

void print_employee(const Employee *emp) {
    printf("\n=== Employee Information ===\n");
    printf("Name: %s\n", emp->name);
    printf("Age: %d\n", emp->age);
    printf("Salary: $%.2f\n", emp->salary);
    printf("Email: %s\n", emp->email);
}

// Menu-driven input example
int display_menu(void) {
    printf("\n=== Main Menu ===\n");
    printf("1. Add employee\n");
    printf("2. Display employee\n");
    printf("3. Calculate statistics\n");
    printf("0. Exit\n");
    
    return safe_get_int("Select option (0-3): ", 0, 3);
}

int main(void) {
    // printf demonstrations
    printf("=== Input/Output Demonstrations ===\n");
    
    // Show scanf concepts (but don't actually use it)
    scanf_demonstration();
    
    // Safe input methods
    printf("\n=== Safe Input Methods ===\n");
    
    // Interactive employee data entry (commented for demo)
    /*
    Employee emp = input_employee_data();
    print_employee(&emp);
    
    // Menu system example
    int choice;
    do {
        choice = display_menu();
        
        switch (choice) {
            case 1:
                printf("Adding employee...\n");
                // emp = input_employee_data();
                break;
            case 2:
                printf("Displaying employee...\n");
                // print_employee(&emp);
                break;
            case 3:
                printf("Calculating statistics...\n");
                break;
            case 0:
                printf("Goodbye!\n");
                break;
        }
    } while (choice != 0);
    */
    
    // Instead, demonstrate with preset data
    Employee sample_emp = {
        .name = "John Doe",
        .age = 30,
        .salary = 75000.50,
        .email = "john.doe@company.com"
    };
    
    printf("Sample employee data:\n");
    print_employee(&sample_emp);
    
    // Show different output formatting
    printf("\n=== Alternative Formatting ===\n");
    printf("Compact: %s (%d) - $%.0f\n", 
           sample_emp.name, sample_emp.age, sample_emp.salary);
    printf("Detailed: %-20s | Age: %2d | Salary: $%8.2f\n", 
           sample_emp.name, sample_emp.age, sample_emp.salary);
    
    return 0;
}
```

#### Character Input/Output

```c
#include <stdio.h>
#include <ctype.h>
#include <string.h>

// Character processing utilities
void analyze_character(int ch) {
    printf("Character: ");
    if (isprint(ch)) {
        printf("'%c' ", ch);
    } else {
        printf("(non-printable) ");
    }
    
    printf("ASCII: %d", ch);
    
    if (isalpha(ch)) printf(" [Letter]");
    if (isdigit(ch)) printf(" [Digit]");
    if (isspace(ch)) printf(" [Whitespace]");
    if (ispunct(ch)) printf(" [Punctuation]");
    if (isupper(ch)) printf(" [Uppercase]");
    if (islower(ch)) printf(" [Lowercase]");
    
    printf("\n");
}

// Read and process characters one by one
void character_input_demo(void) {
    printf("=== Character Input Demo ===\n");
    printf("Type some characters (Ctrl+D or Ctrl+Z to end):\n");
    
    int ch;
    int char_count = 0, line_count = 0, word_count = 0;
    int in_word = 0;
    
    while ((ch = getchar()) != EOF) {
        char_count++;
        
        if (ch == '\n') {
            line_count++;
            in_word = 0;
        } else if (isspace(ch)) {
            in_word = 0;
        } else if (!in_word) {
            word_count++;
            in_word = 1;
        }
        
        analyze_character(ch);
    }
    
    printf("\nStatistics:\n");
    printf("Characters: %d\n", char_count);
    printf("Lines: %d\n", line_count);
    printf("Words: %d\n", word_count);
}

// Text filter examples
void uppercase_filter(void) {
    printf("\n=== Uppercase Filter ===\n");
    printf("Enter text (empty line to end):\n");
    
    int ch;
    while ((ch = getchar()) != EOF && ch != '\n') {
        putchar(toupper(ch));
    }
    putchar('\n');
}

void character_replacement_filter(void) {
    printf("\n=== Character Replacement Filter ===\n");
    printf("Enter text (replaces vowels with '*'):\n");
    
    int ch;
    while ((ch = getchar()) != EOF && ch != '\n') {
        char lower_ch = tolower(ch);
        if (lower_ch == 'a' || lower_ch == 'e' || lower_ch == 'i' || 
            lower_ch == 'o' || lower_ch == 'u') {
            putchar('*');
        } else {
            putchar(ch);
        }
    }
    putchar('\n');
}

// Password input (hiding characters)
void get_password(char *password, size_t max_len) {
    printf("Enter password: ");
    
    size_t i = 0;
    int ch;
    
    // Note: This is a simplified example. Real password input
    // requires platform-specific code to disable echo.
    while (i < max_len - 1 && (ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 8 || ch == 127) { // Backspace or DEL
            if (i > 0) {
                i--;
                printf("\b \b"); // Move back, print space, move back
            }
        } else {
            password[i++] = ch;
            putchar('*'); // Print asterisk instead of character
        }
    }
    
    password[i] = '\0';
    putchar('\n');
}

// Line-oriented input processing
void process_lines(void) {
    printf("\n=== Line Processing Demo ===\n");
    printf("Enter lines of text ('quit' to stop):\n");
    
    char line[256];
    int line_number = 1;
    
    while (fgets(line, sizeof(line), stdin) != NULL) {
        // Remove trailing newline
        line[strcspn(line, "\n")] = '\0';
        
        if (strcmp(line, "quit") == 0) {
            break;
        }
        
        // Process the line
        printf("Line %d (%zu chars): %s\n", 
               line_number++, strlen(line), line);
        
        // Reverse the line
        printf("Reversed: ");
        for (int i = strlen(line) - 1; i >= 0; i--) {
            putchar(line[i]);
        }
        putchar('\n');
        
        // Count words in line
        int words = 0;
        int in_word = 0;
        for (size_t i = 0; i < strlen(line); i++) {
            if (isspace(line[i])) {
                in_word = 0;
            } else if (!in_word) {
                words++;
                in_word = 1;
            }
        }
        printf("Words: %d\n", words);
        printf("---\n");
    }
}

// Binary character operations
void hex_dump(const char *data, size_t length) {
    printf("\n=== Hex Dump ===\n");
    
    for (size_t i = 0; i < length; i += 16) {
        // Print address
        printf("%08zx: ", i);
        
        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", (unsigned char)data[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        // Print ASCII representation
        for (size_t j = 0; j < 16 && i + j < length; j++) {
            char ch = data[i + j];
            putchar(isprint(ch) ? ch : '.');
        }
        
        printf("|\n");
    }
}

int main(void) {
    printf("=== Character Input/Output Operations ===\n");
    
    // Demonstrate character analysis
    printf("Character Analysis Examples:\n");
    char test_chars[] = {'A', 'a', '5', ' ', '\n', '\t', '!', '@'};
    for (size_t i = 0; i < sizeof(test_chars); i++) {
        analyze_character(test_chars[i]);
    }
    
    // Demo data for other functions (to avoid interactive input in demo)
    printf("\n=== Filter Demonstrations ===\n");
    
    // Simulate uppercase filter
    char sample_text[] = "Hello, World! This is a test.";
    printf("Original: %s\n", sample_text);
    printf("Uppercase: ");
    for (size_t i = 0; i < strlen(sample_text); i++) {
        putchar(toupper(sample_text[i]));
    }
    putchar('\n');
    
    // Simulate vowel replacement
    printf("Vowel replacement: ");
    for (size_t i = 0; i < strlen(sample_text); i++) {
        char ch = tolower(sample_text[i]);
        if (ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u') {
            putchar('*');
        } else {
            putchar(sample_text[i]);
        }
    }
    putchar('\n');
    
    // Hex dump demonstration
    hex_dump(sample_text, strlen(sample_text));
    
    // Interactive demos (commented out for this demonstration)
    /*
    character_input_demo();
    uppercase_filter();
    character_replacement_filter();
    
    char password[100];
    get_password(password, sizeof(password));
    printf("Password length: %zu\n", strlen(password));
    
    process_lines();
    */
    
    return 0;
}
```

#### Buffered vs Unbuffered I/O

```c
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

// Demonstrate different buffering modes
void demonstrate_buffering(void) {
    printf("=== I/O Buffering Demonstration ===\n");
    
    // Full buffering (default for files)
    printf("Full buffering test: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        // Output may not appear immediately
        sleep(1);
    }
    printf("\n");
    
    // Forced flush
    printf("With fflush(): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        fflush(stdout);  // Force output
        sleep(1);
    }
    printf("\n");
    
    // Line buffering demonstration
    printf("Line buffering (terminal default):\n");
    printf("This appears immediately because it ends with newline\n");
    printf("This might not appear immediately...");
    fflush(stdout);
    printf(" until now!\n");
    
    // No buffering
    setbuf(stdout, NULL);  // Disable buffering
    printf("Unbuffered output: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
        sleep(1);  // Each character should appear immediately
    }
    printf("\n");
    
    // Restore default buffering
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
}

// Custom buffering example
void custom_buffering_demo(void) {
    printf("\n=== Custom Buffering ===\n");
    
    FILE *file = fopen("buffer_test.txt", "w");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }
    
    // Set custom buffer size
    char custom_buffer[1024];
    setvbuf(file, custom_buffer, _IOFBF, sizeof(custom_buffer));
    
    // Write data (will be buffered)
    fprintf(file, "Line 1: This is buffered output\n");
    fprintf(file, "Line 2: Still in buffer\n");
    fprintf(file, "Line 3: Buffer might be full soon\n");
    
    printf("Data written to file (but may be in buffer)\n");
    
    // Force flush
    fflush(file);
    printf("Buffer flushed to file\n");
    
    fclose(file);
    
    // Read back the file
    file = fopen("buffer_test.txt", "r");
    if (file != NULL) {
        char line[256];
        printf("File contents:\n");
        while (fgets(line, sizeof(line), file) != NULL) {
            printf("  %s", line);
        }
        fclose(file);
    }
    
    // Clean up
    remove("buffer_test.txt");
}

// Performance comparison: buffered vs unbuffered
void performance_comparison(void) {
    printf("\n=== Performance Comparison ===\n");
    
    const int num_writes = 10000;
    clock_t start, end;
    
    // Test 1: Buffered output
    FILE *buffered = fopen("buffered_test.txt", "w");
    if (buffered == NULL) {
        perror("Cannot create buffered test file");
        return;
    }
    
    start = clock();
    for (int i = 0; i < num_writes; i++) {
        fprintf(buffered, "Line %d: Some test data here\n", i);
    }
    fclose(buffered);
    end = clock();
    
    double buffered_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Buffered writes (%d lines): %.4f seconds\n", num_writes, buffered_time);
    
    // Test 2: Unbuffered output
    FILE *unbuffered = fopen("unbuffered_test.txt", "w");
    if (unbuffered == NULL) {
        perror("Cannot create unbuffered test file");
        return;
    }
    
    setbuf(unbuffered, NULL);  // Disable buffering
    
    start = clock();
    for (int i = 0; i < num_writes; i++) {
        fprintf(unbuffered, "Line %d: Some test data here\n", i);
    }
    fclose(unbuffered);
    end = clock();
    
    double unbuffered_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Unbuffered writes (%d lines): %.4f seconds\n", num_writes, unbuffered_time);
    
    printf("Performance difference: %.2fx\n", unbuffered_time / buffered_time);
    
    // Clean up
    remove("buffered_test.txt");
    remove("unbuffered_test.txt");
}

// Buffer overflow protection example
void safe_input_with_buffer_control(void) {
    printf("\n=== Safe Input with Buffer Control ===\n");
    
    char buffer[10];  // Small buffer to demonstrate overflow protection
    
    printf("Enter text (max 9 chars): ");
    fflush(stdout);
    
    // Simulate safe input (without actual user input for demo)
    const char *simulated_input = "This is a very long input string";
    printf("Simulated input: \"%s\"\n", simulated_input);
    
    // Safe copy with size limit
    strncpy(buffer, simulated_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    
    printf("Buffer contents (safely truncated): \"%s\"\n", buffer);
    printf("Buffer size: %zu, String length: %zu\n", 
           sizeof(buffer), strlen(buffer));
    
    // Show what happens without protection
    char unsafe_buffer[10];
    // DON'T DO THIS: strcpy(unsafe_buffer, simulated_input);  // Buffer overflow!
    
    printf("Safe programming prevented buffer overflow!\n");
}

// Stream state management
void stream_state_demo(void) {
    printf("\n=== Stream State Management ===\n");
    
    FILE *file = fopen("stream_test.txt", "w+");
    if (file == NULL) {
        perror("Cannot create test file");
        return;
    }
    
    // Write some data
    fprintf(file, "Hello, World!\n");
    fprintf(file, "Line 2\n");
    fprintf(file, "Line 3\n");
    
    // Check stream state
    if (ferror(file)) {
        printf("Error occurred during write\n");
    } else {
        printf("Write operations successful\n");
    }
    
    // Flush to ensure data is written
    fflush(file);
    
    // Try to read without rewinding (will fail)
    char buffer[100];
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        if (feof(file)) {
            printf("End of file reached (expected)\n");
        } else if (ferror(file)) {
            printf("Error occurred during read\n");
        }
    }
    
    // Clear error state and rewind
    clearerr(file);
    rewind(file);
    
    printf("Stream state cleared, reading from beginning:\n");
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("  %s", buffer);
    }
    
    fclose(file);
    remove("stream_test.txt");
}

int main(void) {
    printf("=== Buffered vs Unbuffered I/O ===\n");
    
    // Note: Some demonstrations may not show differences on all systems
    // as modern systems optimize I/O operations
    
    demonstrate_buffering();
    custom_buffering_demo();
    performance_comparison();
    safe_input_with_buffer_control();
    stream_state_demo();
    
    printf("\nBuffer types summary:\n");
    printf("_IOFBF: Full buffering (default for files)\n");
    printf("_IOLBF: Line buffering (default for terminals)\n");
    printf("_IONBF: No buffering (unbuffered I/O)\n");
    
    return 0;
}
```

---

## Part II: Intermediate Level - Advanced Concepts

### 10. Pointers and Memory Management {#pointers-memory}

Pointers are one of the most powerful and fundamental features of C, enabling direct memory access and efficient data manipulation.

#### Pointer Fundamentals

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pointer_basics(void) {
    printf("=== Pointer Fundamentals ===\n");
    
    // Basic pointer declaration and initialization
    int value = 42;
    int *ptr = &value;  // ptr points to the address of value
    
    printf("value = %d\n", value);
    printf("Address of value: %p\n", (void*)&value);
    printf("ptr = %p\n", (void*)ptr);
    printf("*ptr = %d\n", *ptr);  // Dereference ptr to get value
    
    // Modify value through pointer
    *ptr = 100;
    printf("After *ptr = 100:\n");
    printf("value = %d\n", value);
    printf("*ptr = %d\n", *ptr);
    
    // Pointer to pointer
    int **double_ptr = &ptr;
    printf("\nPointer to pointer:\n");
    printf("ptr = %p\n", (void*)ptr);
    printf("&ptr = %p\n", (void*)&ptr);
    printf("double_ptr = %p\n", (void*)double_ptr);
    printf("*double_ptr = %p\n", (void*)*double_ptr);
    printf("**double_ptr = %d\n", **double_ptr);
    
    // NULL pointer
    int *null_ptr = NULL;
    printf("\nNULL pointer:\n");
    printf("null_ptr = %p\n", (void*)null_ptr);
    
    if (null_ptr == NULL) {
        printf("null_ptr is NULL\n");
    }
    
    // Don't dereference NULL pointer!
    // printf("*null_ptr = %d\n", *null_ptr);  // This would crash
}

// Different data types and their pointers
void pointer_types_demo(void) {
    printf("\n=== Pointer Types ===\n");
    
    // Integer pointer
    int i = 10;
    int *int_ptr = &i;
    printf("int: value=%d, size=%zu, ptr=%p\n", 
           *int_ptr, sizeof(int), (void*)int_ptr);
    
    // Character pointer
    char c = 'A';
    char *char_ptr = &c;
    printf("char: value='%c', size=%zu, ptr=%p\n", 
           *char_ptr, sizeof(char), (void*)char_ptr);
    
    // Double pointer
    double d = 3.14159;
    double *double_ptr = &d;
    printf("double: value=%.5f, size=%zu, ptr=%p\n", 
           *double_ptr, sizeof(double), (void*)double_ptr);
    
    // Pointer arithmetic
    printf("\nPointer arithmetic:\n");
    printf("int_ptr = %p\n", (void*)int_ptr);
    printf("int_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(int_ptr + 1), (char*)(int_ptr + 1) - (char*)int_ptr);
    
    printf("char_ptr = %p\n", (void*)char_ptr);
    printf("char_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(char_ptr + 1), (char*)(char_ptr + 1) - (char*)char_ptr);
    
    printf("double_ptr = %p\n", (void*)double_ptr);
    printf("double_ptr + 1 = %p (difference: %ld bytes)\n", 
           (void*)(double_ptr + 1), (char*)(double_ptr + 1) - (char*)double_ptr);
}

// Function pointers revisited
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }

void function_pointers_advanced(void) {
    printf("\n=== Advanced Function Pointers ===\n");
    
    // Function pointer declaration
    int (*operation)(int, int);
    
    // Assign function to pointer
    operation = add;
    printf("add(5, 3) = %d\n", operation(5, 3));
    
    operation = multiply;
    printf("multiply(5, 3) = %d\n", operation(5, 3));
    
    // Array of function pointers
    int (*operations[])(int, int) = {add, multiply};
    const char *names[] = {"add", "multiply"};
    
    for (size_t i = 0; i < 2; i++) {
        printf("%s(7, 4) = %d\n", names[i], operations[i](7, 4));
    }
    
    // Function pointer as parameter
    void apply_operation(int x, int y, int (*op)(int, int), const char *name) {
        printf("%s(%d, %d) = %d\n", name, x, y, op(x, y));
    }
    
    apply_operation(8, 2, add, "add");
    apply_operation(8, 2, multiply, "multiply");
}

// Const pointers and pointer to const
void const_pointers_demo(void) {
    printf("\n=== Const Pointers ===\n");
    
    int value1 = 10, value2 = 20;
    
    // Regular pointer - can change both pointer and value
    int *ptr1 = &value1;
    printf("Regular pointer: *ptr1 = %d\n", *ptr1);
    *ptr1 = 15;  // OK: change value
    ptr1 = &value2;  // OK: change pointer
    printf("After changes: *ptr1 = %d\n", *ptr1);
    
    // Pointer to const - can change pointer, cannot change value
    const int *ptr2 = &value1;
    printf("Pointer to const: *ptr2 = %d\n", *ptr2);
    // *ptr2 = 25;  // ERROR: cannot change value
    ptr2 = &value2;  // OK: can change pointer
    printf("After pointer change: *ptr2 = %d\n", *ptr2);
    
    // Const pointer - cannot change pointer, can change value
    int *const ptr3 = &value1;
    printf("Const pointer: *ptr3 = %d\n", *ptr3);
    *ptr3 = 30;  // OK: can change value
    // ptr3 = &value2;  // ERROR: cannot change pointer
    printf("After value change: *ptr3 = %d\n", *ptr3);
    
    // Const pointer to const - cannot change either
    const int *const ptr4 = &value1;
    printf("Const pointer to const: *ptr4 = %d\n", *ptr4);
    // *ptr4 = 35;  // ERROR: cannot change value
    // ptr4 = &value2;  // ERROR: cannot change pointer
}

// Real-world example: Generic swap function
void swap_ints(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void swap_generic(void *a, void *b, size_t size) {
    unsigned char *pa = (unsigned char*)a;
    unsigned char *pb = (unsigned char*)b;
    
    for (size_t i = 0; i < size; i++) {
        unsigned char temp = pa[i];
        pa[i] = pb[i];
        pb[i] = temp;
    }
}

void swap_demo(void) {
    printf("\n=== Swap Functions Demo ===\n");
    
    // Integer swap
    int x = 10, y = 20;
    printf("Before swap: x=%d, y=%d\n", x, y);
    swap_ints(&x, &y);
    printf("After int swap: x=%d, y=%d\n", x, y);
    
    // Generic swap with doubles
    double a = 3.14, b = 2.71;
    printf("Before swap: a=%.2f, b=%.2f\n", a, b);
    swap_generic(&a, &b, sizeof(double));
    printf("After generic swap: a=%.2f, b=%.2f\n", a, b);
    
    // Generic swap with strings (array of characters)
    char str1[] = "Hello";
    char str2[] = "World";
    printf("Before swap: str1='%s', str2='%s'\n", str1, str2);
    
    // Swap individual characters
    for (size_t i = 0; i < 5; i++) {
        swap_generic(&str1[i], &str2[i], sizeof(char));
    }
    printf("After character swap: str1='%s', str2='%s'\n", str1, str2);
}

int main(void) {
    pointer_basics();
    pointer_types_demo();
    function_pointers_advanced();
    const_pointers_demo();
    swap_demo();
    
    printf("\n=== Pointer Best Practices ===\n");
    printf("1. Always initialize pointers (or set to NULL)\n");
    printf("2. Check for NULL before dereferencing\n");
    printf("3. Set pointer to NULL after freeing memory\n");
    printf("4. Use const appropriately for read-only data\n");
    printf("5. Be careful with pointer arithmetic\n");
    printf("6. Don't return pointers to local variables\n");
    
    return 0;
}
```

#### Pointer Arithmetic and Arrays

```c
#include <stdio.h>
#include <string.h>

void array_pointer_relationship(void) {
    printf("=== Array-Pointer Relationship ===\n");
    
    int numbers[] = {10, 20, 30, 40, 50};
    int *ptr = numbers;  // Same as &numbers[0]
    
    printf("Array elements using array notation:\n");
    for (size_t i = 0; i < 5; i++) {
        printf("numbers[%zu] = %d (address: %p)\n", 
               i, numbers[i], (void*)&numbers[i]);
    }
    
    printf("\nSame elements using pointer notation:\n");
    for (size_t i = 0; i < 5; i++) {
        printf("*(ptr + %zu) = %d (address: %p)\n", 
               i, *(ptr + i), (void*)(ptr + i));
    }
    
    printf("\nEquivalent expressions:\n");
    printf("numbers[2] = %d\n", numbers[2]);
    printf("*(numbers + 2) = %d\n", *(numbers + 2));
    printf("*(ptr + 2) = %d\n", *(ptr + 2));
    printf("ptr[2] = %d\n", ptr[2]);
    
    // Array name is a constant pointer
    printf("\nArray name as pointer:\n");
    printf("numbers = %p\n", (void*)numbers);
    printf("&numbers[0] = %p\n", (void*)&numbers[0]);
    printf("ptr = %p\n", (void*)ptr);
}

void pointer_arithmetic_demo(void) {
    printf("\n=== Pointer Arithmetic ===\n");
    
    int data[] = {100, 200, 300, 400, 500};
    int *start = data;
    int *end = data + 5;  // Points one past the last element
    
    printf("Array traversal using pointer arithmetic:\n");
    for (int *current = start; current < end; current++) {
        printf("Address: %p, Value: %d, Index: %ld\n", 
               (void*)current, *current, current - start);
    }
    
    // Pointer subtraction
    printf("\nPointer subtraction:\n");
    printf("end - start = %ld elements\n", end - start);
    printf("Distance in bytes: %ld\n", (char*)end - (char*)start);
    
    // Reverse traversal
    printf("\nReverse traversal:\n");
    for (int *current = end - 1; current >= start; current--) {
        printf("Value: %d, Position from start: %ld\n", 
               *current, current - start);
    }
}

// String manipulation using pointers
void string_pointer_operations(void) {
    printf("\n=== String Pointer Operations ===\n");
    
    char message[] = "Hello, World!";
    char *ptr = message;
    
    printf("Original string: '%s'\n", message);
    
    // Count characters using pointers
    int length = 0;
    char *temp = ptr;
    while (*temp != '\0') {
        length++;
        temp++;
    }
    printf("Length calculated with pointers: %d\n", length);
    
    // Find first occurrence of character
    char target = 'o';
    char *found = ptr;
    while (*found != '\0' && *found != target) {
        found++;
    }
    
    if (*found == target) {
        printf("Found '%c' at position %ld\n", target, found - ptr);
    } else {
        printf("Character '%c' not found\n", target);
    }
    
    // Reverse string in place using two pointers
    char copy[] = "Hello, World!";
    char *left = copy;
    char *right = copy + strlen(copy) - 1;
    
    while (left < right) {
        char temp = *left;
        *left = *right;
        *right = temp;
        left++;
        right--;
    }
    
    printf("Reversed string: '%s'\n", copy);
}

// Multi-dimensional arrays and pointers
void multidimensional_array_pointers(void) {
    printf("\n=== Multi-dimensional Arrays and Pointers ===\n");
    
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    // Different ways to access elements
    printf("Different access methods:\n");
    printf("matrix[1][2] = %d\n", matrix[1][2]);
    printf("*(*(matrix + 1) + 2) = %d\n", *(*(matrix + 1) + 2));
    printf("*((int*)matrix + 1*4 + 2) = %d\n", *((int*)matrix + 1*4 + 2));
    
    // Pointer to array vs array of pointers
    int (*ptr_to_array)[4] = matrix;  // Pointer to array of 4 ints
    printf("\nUsing pointer to array:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%d ", ptr_to_array[i][j]);
        }
        printf("\n");
    }
    
    // Array of pointers
    int row0[] = {1, 2, 3, 4};
    int row1[] = {5, 6, 7, 8};
    int row2[] = {9, 10, 11, 12};
    int *array_of_ptrs[] = {row0, row1, row2};
    
    printf("\nUsing array of pointers:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%d ", array_of_ptrs[i][j]);
        }
        printf("\n");
    }
}

// Pointer-based data structures
typedef struct Node {
    int data;
    struct Node *next;
} Node;

Node* create_node(int value) {
    Node *node = malloc(sizeof(Node));
    if (node != NULL) {
        node->data = value;
        node->next = NULL;
    }
    return node;
}

void linked_list_demo(void) {
    printf("\n=== Linked List with Pointers ===\n");
    
    // Create nodes
    Node *head = create_node(10);
    head->next = create_node(20);
    head->next->next = create_node(30);
    head->next->next->next = create_node(40);
    
    // Traverse using pointers
    printf("Linked list contents: ");
    Node *current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
    
    // Count nodes
    int count = 0;
    current = head;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    printf("Number of nodes: %d\n", count);
    
    // Free memory
    current = head;
    while (current != NULL) {
        Node *next = current->next;
        free(current);
        current = next;
    }
    printf("Memory freed\n");
}

// Advanced pointer patterns
void pointer_patterns(void) {
    printf("\n=== Advanced Pointer Patterns ===\n");
    
    // Function returning pointer
    int values[] = {1, 2, 3, 4, 5};
    
    int* find_max(int arr[], size_t size) {
        if (size == 0) return NULL;
        
        int *max_ptr = &arr[0];
        for (size_t i = 1; i < size; i++) {
            if (arr[i] > *max_ptr) {
                max_ptr = &arr[i];
            }
        }
        return max_ptr;
    }
    
    int *max_value = find_max(values, 5);
    if (max_value != NULL) {
        printf("Maximum value: %d at index %ld\n", 
               *max_value, max_value - values);
    }
    
    // Pointer to function returning pointer
    int* (*func_ptr)(int[], size_t) = find_max;
    int *result = func_ptr(values, 5);
    printf("Using function pointer: max = %d\n", *result);
    
    // Array of pointers to functions
    int sum_func(int a, int b) { return a + b; }
    int diff_func(int a, int b) { return a - b; }
    
    int (*math_funcs[])(int, int) = {sum_func, diff_func};
    const char *func_names[] = {"sum", "difference"};
    
    for (size_t i = 0; i < 2; i++) {
        printf("%s(10, 3) = %d\n", func_names[i], math_funcs[i](10, 3));
    }
}

int main(void) {
    array_pointer_relationship();
    pointer_arithmetic_demo();
    string_pointer_operations();
    multidimensional_array_pointers();
    linked_list_demo();
    pointer_patterns();
    
    printf("\n=== Pointer Arithmetic Rules ===\n");
    printf("1. ptr + n: Move n elements forward\n");
    printf("2. ptr - n: Move n elements backward\n");
    printf("3. ptr1 - ptr2: Number of elements between pointers\n");
    printf("4. Comparison operators work with pointers to same array\n");
    printf("5. Only addition/subtraction of integers allowed\n");
    printf("6. No multiplication or division of pointers\n");
    
    return 0;
}
```

### 11. Arrays and Multidimensional Data {#arrays}

Arrays are fundamental data structures in C, providing efficient storage and access to collections of elements.

#### Array Declaration and Initialization

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void array_basics(void) {
    printf("=== Array Declaration and Initialization ===\n");
    
    // Different ways to declare and initialize arrays
    int numbers1[5];  // Uninitialized array
    int numbers2[5] = {1, 2, 3, 4, 5};  // Full initialization
    int numbers3[5] = {1, 2};  // Partial initialization (rest are 0)
    int numbers4[] = {1, 2, 3, 4, 5, 6};  // Size inferred from initializer
    int numbers5[5] = {0};  // All elements initialized to 0
    
    printf("numbers1 (uninitialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers1[i]);  // May contain garbage values
    }
    printf("\n");
    
    printf("numbers2 (full init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers2[i]);
    }
    printf("\n");
    
    printf("numbers3 (partial init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers3[i]);
    }
    printf("\n");
    
    printf("numbers4 (inferred size): ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", numbers4[i]);
    }
    printf("\n");
    
    printf("numbers5 (zero init): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers5[i]);
    }
    printf("\n");
    
    // Character arrays (strings)
    char string1[] = "Hello";  // Size is 6 (including '\0')
    char string2[10] = "World";  // Remaining chars are '\0'
    char string3[] = {'H', 'e', 'l', 'l', 'o', '\0'};  // Explicit
    
    printf("string1: '%s' (length: %zu, size: %zu)\n", 
           string1, strlen(string1), sizeof(string1));
    printf("string2: '%s' (length: %zu, size: %zu)\n", 
           string2, strlen(string2), sizeof(string2));
    printf("string3: '%s' (length: %zu, size: %zu)\n", 
           string3, strlen(string3), sizeof(string3));
    
    // Designated initializers (C99)
    int sparse[10] = {[0] = 1, [4] = 5, [9] = 10};
    printf("sparse array: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", sparse[i]);
    }
    printf("\n");
}

// Array operations and utilities
void array_operations(void) {
    printf("\n=== Array Operations ===\n");
    
    int numbers[] = {64, 34, 25, 12, 22, 11, 90, 88, 76, 50, 42};
    size_t size = sizeof(numbers) / sizeof(numbers[0]);
    
    printf("Original array: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Find minimum and maximum
    int min = numbers[0], max = numbers[0];
    size_t min_idx = 0, max_idx = 0;
    
    for (size_t i = 1; i < size; i++) {
        if (numbers[i] < min) {
            min = numbers[i];
            min_idx = i;
        }
        if (numbers[i] > max) {
            max = numbers[i];
            max_idx = i;
        }
    }
    
    printf("Minimum: %d at index %zu\n", min, min_idx);
    printf("Maximum: %d at index %zu\n", max, max_idx);
    
    // Calculate sum and average
    long sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += numbers[i];
    }
    
    double average = (double)sum / size;
    printf("Sum: %ld, Average: %.2f\n", sum, average);
    
    // Search for element (linear search)
    int target = 22;
    int found_idx = -1;
    
    for (size_t i = 0; i < size; i++) {
        if (numbers[i] == target) {
            found_idx = i;
            break;
        }
    }
    
    if (found_idx != -1) {
        printf("Found %d at index %d\n", target, found_idx);
    } else {
        printf("%d not found in array\n", target);
    }
    
    // Reverse array
    int reversed[size];
    for (size_t i = 0; i < size; i++) {
        reversed[i] = numbers[size - 1 - i];
    }
    
    printf("Reversed array: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", reversed[i]);
    }
    printf("\n");
}

// Array copying and comparison
void array_copy_compare(void) {
    printf("\n=== Array Copying and Comparison ===\n");
    
    int source[] = {1, 2, 3, 4, 5};
    int destination[5];
    size_t size = sizeof(source) / sizeof(source[0]);
    
    // Copy array manually
    printf("Manual copy:\n");
    for (size_t i = 0; i < size; i++) {
        destination[i] = source[i];
    }
    
    printf("Source: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", source[i]);
    }
    printf("\n");
    
    printf("Destination: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", destination[i]);
    }
    printf("\n");
    
    // Copy using memcpy
    int dest_memcpy[5];
    memcpy(dest_memcpy, source, sizeof(source));
    
    printf("Copied with memcpy: ");
    for (size_t i = 0; i < size; i++) {
        printf("%d ", dest_memcpy[i]);
    }
    printf("\n");
    
    // Array comparison
    int array1[] = {1, 2, 3, 4, 5};
    int array2[] = {1, 2, 3, 4, 5};
    int array3[] = {1, 2, 3, 4, 6};
    
    // Manual comparison
    int arrays_equal = 1;
    for (size_t i = 0; i < size; i++) {
        if (array1[i] != array2[i]) {
            arrays_equal = 0;
            break;
        }
    }
    
    printf("array1 == array2: %s\n", arrays_equal ? "true" : "false");
    
    // Using memcmp
    int cmp_result = memcmp(array1, array3, sizeof(array1));
    printf("memcmp(array1, array3): %d\n", cmp_result);
    printf("array1 %s array3\n", 
           cmp_result == 0 ? "equals" : (cmp_result < 0 ? "is less than" : "is greater than"));
}

// String arrays and manipulation
void string_arrays(void) {
    printf("\n=== String Arrays ===\n");
    
    // Array of strings (array of pointers)
    const char *fruits[] = {
        "apple", "banana", "cherry", "date", "elderberry"
    };
    
    size_t num_fruits = sizeof(fruits) / sizeof(fruits[0]);
    
    printf("Fruits array:\n");
    for (size_t i = 0; i < num_fruits; i++) {
        printf("%zu: %s\n", i, fruits[i]);
    }
    
    // 2D character array
    char colors[][10] = {"red", "green", "blue", "yellow", "purple"};
    size_t num_colors = sizeof(colors) / sizeof(colors[0]);
    
    printf("\nColors array:\n");
    for (size_t i = 0; i < num_colors; i++) {
        printf("%zu: %s (length: %zu)\n", i, colors[i], strlen(colors[i]));
    }
    
    // String manipulation in array
    char sentences[][50] = {
        "The quick brown fox",
        "jumps over the lazy dog",
        "Pack my box with",
        "five dozen liquor jugs"
    };
    
    printf("\nOriginal sentences:\n");
    for (size_t i = 0; i < 4; i++) {
        printf("%s\n", sentences[i]);
    }
    
    // Convert to uppercase
    printf("\nConverted to uppercase:\n");
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; sentences[i][j] != '\0'; j++) {
            sentences[i][j] = toupper(sentences[i][j]);
        }
        printf("%s\n", sentences[i]);
    }
}

// Multidimensional arrays
void multidimensional_arrays(void) {
    printf("\n=== Multidimensional Arrays ===\n");
    
    // 2D array (matrix)
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    printf("3x4 Matrix:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // Matrix operations
    printf("\nMatrix transpose (4x3):\n");
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 3; i++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // 3D array
    int cube[2][3][4];
    int value = 1;
    
    // Initialize 3D array
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                cube[i][j][k] = value++;
            }
        }
    }
    
    printf("\n3D Array (2x3x4):\n");
    for (int i = 0; i < 2; i++) {
        printf("Layer %d:\n", i);
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                printf("%3d ", cube[i][j][k]);
            }
            printf("\n");
        }
        printf("\n");
    }
}

// Dynamic arrays (variable length arrays - C99)
void variable_length_arrays(void) {
    printf("\n=== Variable Length Arrays (C99) ===\n");
    
    int rows = 3, cols = 4;
    
    // VLA declaration
    int vla_matrix[rows][cols];
    
    // Initialize VLA
    int counter = 1;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            vla_matrix[i][j] = counter++;
        }
    }
    
    printf("Variable Length Array (%dx%d):\n", rows, cols);
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%3d ", vla_matrix[i][j]);
        }
        printf("\n");
    }
    
    // Function with VLA parameter
    void print_matrix(int r, int c, int mat[r][c]) {
        printf("Matrix printed by function:\n");
        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                printf("%3d ", mat[i][j]);
            }
            printf("\n");
        }
    }
    
    print_matrix(rows, cols, vla_matrix);
}

// Real-world example: Grade management system
typedef struct {
    char name[50];
    float grades[5];  // 5 subjects
    float average;
} Student;

void grade_management_demo(void) {
    printf("\n=== Grade Management System ===\n");
    
    const char *subjects[] = {"Math", "English", "Science", "History", "Art"};
    const int num_subjects = 5;
    
    Student students[] = {
        {"Alice Johnson", {85.5, 92.0, 88.5, 90.0, 87.5}, 0},
        {"Bob Smith", {78.0, 85.5, 82.0, 79.5, 88.0}, 0},
        {"Carol Davis", {95.0, 91.5, 96.0, 93.5, 89.0}, 0},
        {"David Wilson", {82.5, 78.0, 85.0, 87.5, 84.0}, 0}
    };
    
    int num_students = sizeof(students) / sizeof(students[0]);
    
    // Calculate averages
    for (int i = 0; i < num_students; i++) {
        float sum = 0;
        for (int j = 0; j < num_subjects; j++) {
            sum += students[i].grades[j];
        }
        students[i].average = sum / num_subjects;
    }
    
    // Display student grades
    printf("Student Grade Report:\n");
    printf("%-15s", "Name");
    for (int j = 0; j < num_subjects; j++) {
        printf("%-10s", subjects[j]);
    }
    printf("%-10s\n", "Average");
    
    printf("%-15s", "---------------");
    for (int j = 0; j < num_subjects; j++) {
        printf("%-10s", "--------");
    }
    printf("%-10s\n", "--------");
    
    for (int i = 0; i < num_students; i++) {
        printf("%-15s", students[i].name);
        for (int j = 0; j < num_subjects; j++) {
            printf("%-10.1f", students[i].grades[j]);
        }
        printf("%-10.1f\n", students[i].average);
    }
    
    // Calculate subject averages
    printf("\nSubject Averages:\n");
    for (int j = 0; j < num_subjects; j++) {
        float subject_sum = 0;
        for (int i = 0; i < num_students; i++) {
            subject_sum += students[i].grades[j];
        }
        printf("%-10s: %.1f\n", subjects[j], subject_sum / num_students);
    }
    
    // Find best student
    int best_student_idx = 0;
    for (int i = 1; i < num_students; i++) {
        if (students[i].average > students[best_student_idx].average) {
            best_student_idx = i;
        }
    }
    
    printf("\nBest performing student: %s (Average: %.1f)\n",
           students[best_student_idx].name, students[best_student_idx].average);
}

// Array sorting algorithms
void bubble_sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

void selection_sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        int min_idx = i;
        for (int j = i + 1; j < n; j++) {
            if (arr[j] < arr[min_idx]) {
                min_idx = j;
            }
        }
        if (min_idx != i) {
            int temp = arr[i];
            arr[i] = arr[min_idx];
            arr[min_idx] = temp;
        }
    }
}

void insertion_sort(int arr[], int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j = i - 1;
        
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j = j - 1;
        }
        arr[j + 1] = key;
    }
}

void sorting_algorithms_demo(void) {
    printf("\n=== Array Sorting Algorithms ===\n");
    
    int original[] = {64, 34, 25, 12, 22, 11, 90, 88, 76, 50, 42};
    int size = sizeof(original) / sizeof(original[0]);
    
    printf("Original array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", original[i]);
    }
    printf("\n");
    
    // Test different sorting algorithms
    int bubble_array[size], selection_array[size], insertion_array[size];
    
    // Copy original array for each sorting method
    memcpy(bubble_array, original, sizeof(original));
    memcpy(selection_array, original, sizeof(original));
    memcpy(insertion_array, original, sizeof(original));
    
    // Bubble sort
    bubble_sort(bubble_array, size);
    printf("Bubble sort:    ");
    for (int i = 0; i < size; i++) {
        printf("%d ", bubble_array[i]);
    }
    printf("\n");
    
    // Selection sort
    selection_sort(selection_array, size);
    printf("Selection sort: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", selection_array[i]);
    }
    printf("\n");
    
    // Insertion sort
    insertion_sort(insertion_array, size);
    printf("Insertion sort: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", insertion_array[i]);
    }
    printf("\n");
}

// Binary search (requires sorted array)
int binary_search(int arr[], int size, int target) {
    int left = 0, right = size - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (arr[mid] == target) {
            return mid;
        } else if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    return -1;  // Not found
}

void search_algorithms_demo(void) {
    printf("\n=== Array Search Algorithms ===\n");
    
    int sorted_array[] = {2, 5, 8, 12, 16, 23, 38, 45, 56, 67, 78};
    int size = sizeof(sorted_array) / sizeof(sorted_array[0]);
    
    printf("Sorted array: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", sorted_array[i]);
    }
    printf("\n");
    
    int targets[] = {23, 67, 15, 2, 100};
    int num_targets = sizeof(targets) / sizeof(targets[0]);
    
    for (int i = 0; i < num_targets; i++) {
        int result = binary_search(sorted_array, size, targets[i]);
        if (result != -1) {
            printf("Found %d at index %d\n", targets[i], result);
        } else {
            printf("%d not found in array\n", targets[i]);
        }
    }
}

int main(void) {
    array_basics();
    array_operations();
    array_copy_compare();
    string_arrays();
    multidimensional_arrays();
    
    // VLA demo (C99 feature)
#if __STDC_VERSION__ >= 199901L
    variable_length_arrays();
#else
    printf("\nVariable Length Arrays require C99 or later\n");
#endif
    
    grade_management_demo();
    sorting_algorithms_demo();
    search_algorithms_demo();
    
    printf("\n=== Array Best Practices ===\n");
    printf("1. Always initialize arrays before use\n");
    printf("2. Use sizeof() to calculate array size\n");
    printf("3. Be careful with array bounds (no automatic checking)\n");
    printf("4. Consider using const for read-only arrays\n");
    printf("5. Use meaningful names for array indices\n");
    printf("6. Prefer standard library functions (memcpy, memcmp) when possible\n");
    printf("7. Consider using VLAs for runtime-sized arrays (C99+)\n");
    
    return 0;
}
```

### 12. Dynamic Memory Allocation {#dynamic-memory}

Dynamic memory allocation allows programs to request memory at runtime, enabling flexible data structures and efficient memory usage.

#### malloc, calloc, realloc, and free

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void basic_malloc_demo(void) {
    printf("=== Basic malloc() Demo ===\n");
    
    // Allocate memory for 5 integers
    int *numbers = malloc(5 * sizeof(int));
    
    if (numbers == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    printf("Memory allocated successfully\n");
    
    // Initialize the allocated memory
    for (int i = 0; i < 5; i++) {
        numbers[i] = (i + 1) * 10;
    }
    
    printf("Allocated array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // Always free allocated memory
    free(numbers);
    numbers = NULL;  // Good practice to avoid dangling pointer
    printf("Memory freed\n");
}

void calloc_vs_malloc_demo(void) {
    printf("\n=== calloc() vs malloc() Demo ===\n");
    
    // malloc - memory contains garbage values
    int *malloc_array = malloc(5 * sizeof(int));
    if (malloc_array == NULL) {
        printf("malloc failed\n");
        return;
    }
    
    printf("malloc array (uninitialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", malloc_array[i]);
    }
    printf("\n");
    
    // calloc - memory is zero-initialized
    int *calloc_array = calloc(5, sizeof(int));
    if (calloc_array == NULL) {
        printf("calloc failed\n");
        free(malloc_array);
        return;
    }
    
    printf("calloc array (zero-initialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", calloc_array[i]);
    }
    printf("\n");
    
    // Performance comparison
    printf("\nPerformance note: calloc is slightly slower due to initialization\n");
    printf("Use malloc when you'll immediately initialize all elements\n");
    printf("Use calloc when you want zero-initialized memory\n");
    
    free(malloc_array);
    free(calloc_array);
}

void realloc_demo(void) {
    printf("\n=== realloc() Demo ===\n");
    
    // Start with small array
    int *array = malloc(3 * sizeof(int));
    if (array == NULL) {
        printf("Initial allocation failed\n");
        return;
    }
    
    // Initialize
    for (int i = 0; i < 3; i++) {
        array[i] = i + 1;
    }
    
    printf("Initial array (size 3): ");
    for (int i = 0; i < 3; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // Expand the array
    int *temp = realloc(array, 6 * sizeof(int));
    if (temp == NULL) {
        printf("Reallocation failed\n");
        free(array);
        return;
    }
    
    array = temp;  // Update pointer
    
    // Initialize new elements
    for (int i = 3; i < 6; i++) {
        array[i] = i + 1;
    }
    
    printf("Expanded array (size 6): ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // Shrink the array
    temp = realloc(array, 4 * sizeof(int));
    if (temp == NULL) {
        printf("Reallocation failed\n");
        free(array);
        return;
    }
    
    array = temp;
    
    printf("Shrunk array (size 4): ");
    for (int i = 0; i < 4; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    // realloc with size 0 is equivalent to free
    array = realloc(array, 0);  // array becomes NULL
    printf("Array freed using realloc(ptr, 0)\n");
}

// Dynamic string handling
void dynamic_string_demo(void) {
    printf("\n=== Dynamic String Handling ===\n");
    
    // Allocate memory for a string
    char *message = malloc(20);
    if (message == NULL) {
        printf("String allocation failed\n");
        return;
    }
    
    strcpy(message, "Hello");
    printf("Initial string: '%s'\n", message);
    
    // Expand to accommodate more text
    message = realloc(message, 50);
    if (message == NULL) {
        printf("String reallocation failed\n");
        return;
    }
    
    strcat(message, ", World!");
    printf("Expanded string: '%s'\n", message);
    
    // Create a copy
    size_t len = strlen(message);
    char *copy = malloc(len + 1);
    if (copy != NULL) {
        strcpy(copy, message);
        printf("Copy: '%s'\n", copy);
        free(copy);
    }
    
    free(message);
}

// Error handling in memory allocation
void allocation_error_handling(void) {
    printf("\n=== Memory Allocation Error Handling ===\n");
    
    // Try to allocate a very large amount of memory
    size_t huge_size = SIZE_MAX;
    void *huge_ptr = malloc(huge_size);
    
    if (huge_ptr == NULL) {
        printf("Large allocation failed (as expected)\n");
        printf("errno: %d (%s)\n", errno, strerror(errno));
    } else {
        printf("Unexpected: Large allocation succeeded\n");
        free(huge_ptr);
    }
    
    // Proper error handling pattern
    int *safe_array = malloc(100 * sizeof(int));
    if (safe_array == NULL) {
        fprintf(stderr, "Error: Cannot allocate memory for array\n");
        return;
    }
    
    printf("Safe allocation succeeded\n");
    
    // Use the memory
    for (int i = 0; i < 100; i++) {
        safe_array[i] = i * i;
    }
    
    printf("First 10 squares: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", safe_array[i]);
    }
    printf("\n");
    
    free(safe_array);
}

// Real-world example: Dynamic array with growth
typedef struct {
    int *data;
    size_t size;
    size_t capacity;
} DynamicArray;

DynamicArray* create_array(void) {
    DynamicArray *arr = malloc(sizeof(DynamicArray));
    if (arr == NULL) return NULL;
    
    arr->data = malloc(4 * sizeof(int));  // Initial capacity of 4
    if (arr->data == NULL) {
        free(arr);
        return NULL;
    }
    
    arr->size = 0;
    arr->capacity = 4;
    return arr;
}

int append_array(DynamicArray *arr, int value) {
    if (arr == NULL) return 0;
    
    // Check if we need to grow the array
    if (arr->size >= arr->capacity) {
        size_t new_capacity = arr->capacity * 2;
        int *new_data = realloc(arr->data, new_capacity * sizeof(int));
        if (new_data == NULL) {
            return 0;  // Allocation failed
        }
        
        arr->data = new_data;
        arr->capacity = new_capacity;
        printf("Array grown to capacity %zu\n", new_capacity);
    }
    
    arr->data[arr->size++] = value;
    return 1;  // Success
}

void print_array(const DynamicArray *arr) {
    if (arr == NULL) return;
    
    printf("Array (size: %zu, capacity: %zu): ", arr->size, arr->capacity);
    for (size_t i = 0; i < arr->size; i++) {
        printf("%d ", arr->data[i]);
    }
    printf("\n");
}

void destroy_array(DynamicArray *arr) {
    if (arr != NULL) {
        free(arr->data);
        free(arr);
    }
}

void dynamic_array_demo(void) {
    printf("\n=== Dynamic Array Demo ===\n");
    
    DynamicArray *arr = create_array();
    if (arr == NULL) {
        printf("Failed to create dynamic array\n");
        return;
    }
    
    printf("Created dynamic array\n");
    print_array(arr);
    
    // Add elements to trigger growth
    for (int i = 1; i <= 10; i++) {
        if (append_array(arr, i * 10)) {
            printf("Added %d\n", i * 10);
            print_array(arr);
        } else {
            printf("Failed to add %d\n", i * 10);
            break;
        }
    }
    
    destroy_array(arr);
    printf("Dynamic array destroyed\n");
}

// Memory leak detection and prevention
void demonstrate_memory_leaks(void) {
    printf("\n=== Memory Leak Prevention ===\n");
    
    // Example of potential memory leak
    void memory_leak_example(void) {
        int *ptr = malloc(100 * sizeof(int));
        if (ptr == NULL) return;
        
        // ... use ptr ...
        
        // Oops! Forgot to call free(ptr) - MEMORY LEAK!
        return;  // Memory is lost
    }
    
    // Correct version
    void correct_memory_usage(void) {
        int *ptr = malloc(100 * sizeof(int));
        if (ptr == NULL) return;
        
        // ... use ptr ...
        
        free(ptr);  // Always free allocated memory
        ptr = NULL; // Prevent accidental reuse
    }
    
    printf("Always pair malloc/calloc with free\n");
    printf("Set pointers to NULL after freeing\n");
    printf("Use tools like Valgrind to detect leaks\n");
    
    // Example with proper cleanup
    char *buffer1 = malloc(256);
    char *buffer2 = malloc(512);
    
    if (buffer1 == NULL || buffer2 == NULL) {
        printf("Allocation failed\n");
        free(buffer1);  // Safe to call on NULL
        free(buffer2);
        return;
    }
    
    // Use buffers
    strcpy(buffer1, "Buffer 1 content");
    strcpy(buffer2, "Buffer 2 has more content than buffer 1");
    
    printf("Buffer 1: %s\n", buffer1);
    printf("Buffer 2: %s\n", buffer2);
    
    // Cleanup
    free(buffer1);
    free(buffer2);
    buffer1 = buffer2 = NULL;
    
    printf("Buffers properly freed\n");
}

// Advanced: Memory pools for frequent allocations
typedef struct MemoryBlock {
    void *data;
    size_t size;
    int in_use;
    struct MemoryBlock *next;
} MemoryBlock;

typedef struct {
    MemoryBlock *blocks;
    size_t block_size;
    size_t num_blocks;
    size_t blocks_in_use;
} MemoryPool;

MemoryPool* create_memory_pool(size_t block_size, size_t num_blocks) {
    MemoryPool *pool = malloc(sizeof(MemoryPool));
    if (pool == NULL) return NULL;
    
    pool->block_size = block_size;
    pool->num_blocks = num_blocks;
    pool->blocks_in_use = 0;
    pool->blocks = NULL;
    
    // Create linked list of blocks
    for (size_t i = 0; i < num_blocks; i++) {
        MemoryBlock *block = malloc(sizeof(MemoryBlock));
        if (block == NULL) {
            // Cleanup on failure
            // ... cleanup code ...
            return NULL;
        }
        
        block->data = malloc(block_size);
        if (block->data == NULL) {
            free(block);
            // ... cleanup code ...
            return NULL;
        }
        
        block->size = block_size;
        block->in_use = 0;
        block->next = pool->blocks;
        pool->blocks = block;
    }
    
    return pool;
}

void* pool_allocate(MemoryPool *pool) {
    if (pool == NULL) return NULL;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (!current->in_use) {
            current->in_use = 1;
            pool->blocks_in_use++;
            return current->data;
        }
        current = current->next;
    }
    
    return NULL;  // No available blocks
}

void pool_deallocate(MemoryPool *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) return;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (current->data == ptr && current->in_use) {
            current->in_use = 0;
            pool->blocks_in_use--;
            return;
        }
        current = current->next;
    }
}

void destroy_memory_pool(MemoryPool *pool) {
    if (pool == NULL) return;
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        MemoryBlock *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
    
    free(pool);
}

void memory_pool_demo(void) {
    printf("\n=== Memory Pool Demo ===\n");
    
    MemoryPool *pool = create_memory_pool(256, 5);
    if (pool == NULL) {
        printf("Failed to create memory pool\n");
        return;
    }
    
    printf("Created memory pool: 5 blocks of 256 bytes each\n");
    
    // Allocate some blocks
    void *ptr1 = pool_allocate(pool);
    void *ptr2 = pool_allocate(pool);
    void *ptr3 = pool_allocate(pool);
    
    if (ptr1 && ptr2 && ptr3) {
        printf("Allocated 3 blocks from pool (in use: %zu/%zu)\n", 
               pool->blocks_in_use, pool->num_blocks);
        
        // Use the memory
        strcpy((char*)ptr1, "Block 1 data");
        strcpy((char*)ptr2, "Block 2 data");
        strcpy((char*)ptr3, "Block 3 data");
        
        printf("Block contents: '%s', '%s', '%s'\n", 
               (char*)ptr1, (char*)ptr2, (char*)ptr3);
    }
    
    // Deallocate middle block
    pool_deallocate(pool, ptr2);
    printf("Deallocated block 2 (in use: %zu/%zu)\n", 
           pool->blocks_in_use, pool->num_blocks);
    
    // Allocate again (should reuse the freed block)
    void *ptr4 = pool_allocate(pool);
    if (ptr4) {
        strcpy((char*)ptr4, "Block 4 data (reused)");
        printf("Allocated new block: '%s' (in use: %zu/%zu)\n", 
               (char*)ptr4, pool->blocks_in_use, pool->num_blocks);
    }
    
    destroy_memory_pool(pool);
    printf("Memory pool destroyed\n");
}

int main(void) {
    basic_malloc_demo();
    calloc_vs_malloc_demo();
    realloc_demo();
    dynamic_string_demo();
    allocation_error_handling();
    dynamic_array_demo();
    demonstrate_memory_leaks();
    memory_pool_demo();
    
    printf("\n=== Dynamic Memory Best Practices ===\n");
    printf("1. Always check for NULL return from malloc/calloc/realloc\n");
    printf("2. Free every allocated block exactly once\n");
    printf("3. Set pointers to NULL after freeing\n");
    printf("4. Use calloc when you need zero-initialized memory\n");
    printf("5. Be careful when using realloc (it may move memory)\n");
    printf("6. Consider memory pools for frequent allocations\n");
    printf("7. Use static analysis tools to detect memory issues\n");
    printf("8. Match every malloc with exactly one free\n");
    
    return 0;
}
```

### 13. Structures, Unions, and Enumerations {#structures-unions}

These user-defined data types allow you to create complex data structures and organize related data efficiently.

#### Structure Definition and Usage

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Basic structure definition
struct Point {
    double x;
    double y;
};

// Structure with different data types
struct Person {
    char name[50];
    int age;
    double height;
    char gender;
};

// Typedef for convenience
typedef struct {
    int day;
    int month;
    int year;
} Date;

// Self-referencing structure (for linked lists, trees, etc.)
typedef struct Employee {
    int id;
    char name[100];
    double salary;
    Date hire_date;
    struct Employee *manager;  // Self-reference
} Employee;

void basic_structures_demo(void) {
    printf("=== Basic Structures Demo ===\n");
    
    // Structure initialization methods
    struct Point p1 = {3.0, 4.0};              // Positional initialization
    struct Point p2 = {.x = 1.0, .y = 2.0};    // Designated initialization (C99)
    struct Point p3;                            // Uninitialized
    
    // Initialize p3
    p3.x = 5.0;
    p3.y = 12.0;
    
    printf("Point p1: (%.1f, %.1f)\n", p1.x, p1.y);
    printf("Point p2: (%.1f, %.1f)\n", p2.x, p2.y);
    printf("Point p3: (%.1f, %.1f)\n", p3.x, p3.y);
    
    // Calculate distance between points
    double distance = sqrt((p3.x - p1.x) * (p3.x - p1.x) + 
                          (p3.y - p1.y) * (p3.y - p1.y));
    printf("Distance between p1 and p3: %.2f\n", distance);
    
    // Person structure example
    struct Person person1 = {
        .name = "John Doe",
        .age = 30,
        .height = 5.9,
        .gender = 'M'
    };
    
    printf("\nPerson Information:\n");
    printf("Name: %s\n", person1.name);
    printf("Age: %d\n", person1.age);
    printf("Height: %.1f feet\n", person1.height);
    printf("Gender: %c\n", person1.gender);
    
    // Date structure with typedef
    Date today = {1, 9, 2025};  // September 1, 2025
    printf("\nToday's date: %02d/%02d/%04d\n", 
           today.day, today.month, today.year);
}

// Structure operations and functions
double calculate_distance(struct Point p1, struct Point p2) {
    double dx = p2.x - p1.x;
    double dy = p2.y - p1.y;
    return sqrt(dx * dx + dy * dy);
}

struct Point midpoint(struct Point p1, struct Point p2) {
    struct Point mid;
    mid.x = (p1.x + p2.x) / 2.0;
    mid.y = (p1.y + p2.y) / 2.0;
    return mid;
}

void print_point(const struct Point *p) {
    printf("Point: (%.2f, %.2f)\n", p->x, p->y);
}

void move_point(struct Point *p, double dx, double dy) {
    p->x += dx;
    p->y += dy;
}

void structure_functions_demo(void) {
    printf("\n=== Structure Functions Demo ===\n");
    
    struct Point a = {0.0, 0.0};
    struct Point b = {3.0, 4.0};
    
    printf("Initial points:\n");
    print_point(&a);
    print_point(&b);
    
    double dist = calculate_distance(a, b);
    printf("Distance: %.2f\n", dist);
    
    struct Point mid = midpoint(a, b);
    printf("Midpoint: ");
    print_point(&mid);
    
    // Modify point using pointer
    move_point(&a, 1.0, 1.0);
    printf("After moving point a by (1,1): ");
    print_point(&a);
}

// Nested structures
typedef struct {
    char street[100];
    char city[50];
    char state[20];
    char zip_code[10];
} Address;

typedef struct {
    char first_name[50];
    char last_name[50];
    int age;
    Address address;        // Nested structure
    char phone[15];
    char email[100];
} Contact;

void nested_structures_demo(void) {
    printf("\n=== Nested Structures Demo ===\n");
    
    Contact person = {
        .first_name = "Alice",
        .last_name = "Johnson",
        .age = 28,
        .address = {
            .street = "123 Main St",
            .city = "Springfield",
            .state = "IL",
            .zip_code = "62701"
        },
        .phone = "555-1234",
        .email = "alice.johnson@email.com"
    };
    
    printf("Contact Information:\n");
    printf("Name: %s %s\n", person.first_name, person.last_name);
    printf("Age: %d\n", person.age);
    printf("Address: %s\n", person.address.street);
    printf("         %s, %s %s\n", 
           person.address.city, person.address.state, person.address.zip_code);
    printf("Phone: %s\n", person.phone);
    printf("Email: %s\n", person.email);
}

// Arrays of structures
void structure_arrays_demo(void) {
    printf("\n=== Structure Arrays Demo ===\n");
    
    Employee employees[] = {
        {1, "John Smith", 75000.0, {15, 3, 2020}, NULL},
        {2, "Jane Doe", 82000.0, {22, 7, 2019}, NULL},
        {3, "Bob Wilson", 68000.0, {10, 11, 2021}, NULL},
        {4, "Carol Davis", 95000.0, {5, 1, 2018}, NULL},
        {5, "David Brown", 71000.0, {18, 9, 2020}, NULL}
    };
    
    int num_employees = sizeof(employees) / sizeof(employees[0]);
    
    // Set manager relationships
    employees[1].manager = &employees[3];  // Jane reports to Carol
    employees[2].manager = &employees[3];  // Bob reports to Carol
    employees[4].manager = &employees[1];  // David reports to Jane
    
    printf("Employee Database:\n");
    printf("%-3s %-15s %-10s %-12s %-15s\n", 
           "ID", "Name", "Salary", "Hire Date", "Manager");
    printf("%-3s %-15s %-10s %-12s %-15s\n", 
           "---", "---------------", "----------", "------------", "---------------");
    
    for (int i = 0; i < num_employees; i++) {
        printf("%-3d %-15s $%-9.0f %02d/%02d/%04d   %-15s\n",
               employees[i].id,
               employees[i].name,
               employees[i].salary,
               employees[i].hire_date.day,
               employees[i].hire_date.month,
               employees[i].hire_date.year,
               employees[i].manager ? employees[i].manager->name : "None");
    }
    
    // Calculate average salary
    double total_salary = 0;
    for (int i = 0; i < num_employees; i++) {
        total_salary += employees[i].salary;
    }
    
    printf("\nAverage salary: $%.2f\n", total_salary / num_employees);
    
    // Find highest paid employee
    Employee *highest_paid = &employees[0];
    for (int i = 1; i < num_employees; i++) {
        if (employees[i].salary > highest_paid->salary) {
            highest_paid = &employees[i];
        }
    }
    
    printf("Highest paid: %s ($%.0f)\n", 
           highest_paid->name, highest_paid->salary);
}

// Dynamic structures
typedef struct Node {
    int data;
    struct Node *next;
} Node;

typedef struct {
    Node *head;
    Node *tail;
    size_t size;
} LinkedList;

LinkedList* create_list(void) {
    LinkedList *list = malloc(sizeof(LinkedList));
    if (list != NULL) {
        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
    }
    return list;
}

void append_to_list(LinkedList *list, int value) {
    if (list == NULL) return;
    
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) return;
    
    new_node->data = value;
    new_node->next = NULL;
    
    if (list->head == NULL) {
        list->head = new_node;
        list->tail = new_node;
    } else {
        list->tail->next = new_node;
        list->tail = new_node;
    }
    
    list->size++;
}

void print_list(const LinkedList *list) {
    if (list == NULL || list->head == NULL) {
        printf("Empty list\n");
        return;
    }
    
    printf("List (size %zu): ", list->size);
    Node *current = list->head;
    while (current != NULL) {
        printf("%d", current->data);
        if (current->next != NULL) printf(" -> ");
        current = current->next;
    }
    printf(" -> NULL\n");
}

void destroy_list(LinkedList *list) {
    if (list == NULL) return;
    
    Node *current = list->head;
    while (current != NULL) {
        Node *next = current->next;
        free(current);
        current = next;
    }
    
    free(list);
}

void dynamic_structures_demo(void) {
    printf("\n=== Dynamic Structures Demo ===\n");
    
    LinkedList *list = create_list();
    if (list == NULL) {
        printf("Failed to create list\n");
        return;
    }
    
    printf("Created empty linked list\n");
    print_list(list);
    
    // Add elements
    for (int i = 1; i <= 5; i++) {
        append_to_list(list, i * 10);
        printf("Added %d: ", i * 10);
        print_list(list);
    }
    
    destroy_list(list);
    printf("List destroyed\n");
}

// Structure padding and alignment
void structure_memory_layout(void) {
    printf("\n=== Structure Memory Layout ===\n");
    
    typedef struct {
        char a;      // 1 byte
        int b;       // 4 bytes
        char c;      // 1 byte
        double d;    // 8 bytes
    } UnalignedStruct;
    
    typedef struct {
        double d;    // 8 bytes
        int b;       // 4 bytes
        char a;      // 1 byte
        char c;      // 1 byte
    } AlignedStruct;
    
    printf("Unaligned structure:\n");
    printf("  sizeof(UnalignedStruct): %zu bytes\n", sizeof(UnalignedStruct));
    printf("  Expected without padding: %zu bytes\n", 
           sizeof(char) + sizeof(int) + sizeof(char) + sizeof(double));
    
    printf("\nAligned structure:\n");
    printf("  sizeof(AlignedStruct): %zu bytes\n", sizeof(AlignedStruct));
    
    // Show member offsets
    UnalignedStruct unaligned;
    printf("\nUnaligned structure member offsets:\n");
    printf("  a: %zu\n", (char*)&unaligned.a - (char*)&unaligned);
    printf("  b: %zu\n", (char*)&unaligned.b - (char*)&unaligned);
    printf("  c: %zu\n", (char*)&unaligned.c - (char*)&unaligned);
    printf("  d: %zu\n", (char*)&unaligned.d - (char*)&unaligned);
    
    // Packed structure (compiler-specific)
    #ifdef __GNUC__
    typedef struct __attribute__((packed)) {
        char a;
        int b;
        char c;
        double d;
    } PackedStruct;
    
    printf("\nPacked structure (GCC):\n");
    printf("  sizeof(PackedStruct): %zu bytes\n", sizeof(PackedStruct));
    #endif
}

// Unions demonstration
union Data {
    int i;
    float f;
    char c[4];
};

void unions_demo(void) {
    printf("\n=== Unions Demo ===\n");
    
    union Data data;
    
    printf("sizeof(union Data): %zu bytes\n", sizeof(union Data));
    printf("All members share the same memory location\n\n");
    
    // Store integer
    data.i = 0x12345678;
    printf("Stored integer: 0x%X (%d)\n", data.i, data.i);
    printf("As float: %f\n", data.f);
    printf("As char array: [0x%02X, 0x%02X, 0x%02X, 0x%02X]\n",
           (unsigned char)data.c[0], (unsigned char)data.c[1], 
           (unsigned char)data.c[2], (unsigned char)data.c[3]);
    
    // Store float
    data.f = 3.14159f;
    printf("\nStored float: %f\n", data.f);
    printf("As integer: %d (0x%X)\n", data.i, data.i);
    printf("As char array: [0x%02X, 0x%02X, 0x%02X, 0x%02X]\n",
           (unsigned char)data.c[0], (unsigned char)data.c[1], 
           (unsigned char)data.c[2], (unsigned char)data.c[3]);
    
    // Tagged unions (discriminated unions)
    typedef enum {
        TYPE_INT,
        TYPE_FLOAT,
        TYPE_STRING
    } DataType;
    
    typedef struct {
        DataType type;
        union {
            int i;
            float f;
            char s[20];
        } value;
    } TaggedData;
    
    printf("\n=== Tagged Union Demo ===\n");
    
    TaggedData items[] = {
        {TYPE_INT, .value.i = 42},
        {TYPE_FLOAT, .value.f = 3.14159f},
        {TYPE_STRING, .value.s = "Hello"}
    };
    
    for (int i = 0; i < 3; i++) {
        switch (items[i].type) {
            case TYPE_INT:
                printf("Integer: %d\n", items[i].value.i);
                break;
            case TYPE_FLOAT:
                printf("Float: %.5f\n", items[i].value.f);
                break;
            case TYPE_STRING:
                printf("String: %s\n", items[i].value.s);
                break;
        }
    }
}

// Enumerations
enum Status {
    STATUS_PENDING = 1,    // Explicit value
    STATUS_PROCESSING,     // 2 (auto-increment)
    STATUS_COMPLETED,      // 3
    STATUS_FAILED = -1,    // Explicit negative value
    STATUS_CANCELLED = 100 // Explicit large value
};

typedef enum {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARNING,
    LEVEL_ERROR,
    LEVEL_CRITICAL
} LogLevel;

const char* status_to_string(enum Status status) {
    switch (status) {
        case STATUS_PENDING: return "Pending";
        case STATUS_PROCESSING: return "Processing";
        case STATUS_COMPLETED: return "Completed";
        case STATUS_FAILED: return "Failed";
        case STATUS_CANCELLED: return "Cancelled";
        default: return "Unknown";
    }
}

const char* level_to_string(LogLevel level) {
    static const char* level_names[] = {
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
    };
    
    if (level >= 0 && level <= LEVEL_CRITICAL) {
        return level_names[level];
    }
    return "UNKNOWN";
}

void enumerations_demo(void) {
    printf("\n=== Enumerations Demo ===\n");
    
    // Show enum values
    printf("Status enum values:\n");
    printf("  STATUS_PENDING: %d\n", STATUS_PENDING);
    printf("  STATUS_PROCESSING: %d\n", STATUS_PROCESSING);
    printf("  STATUS_COMPLETED: %d\n", STATUS_COMPLETED);
    printf("  STATUS_FAILED: %d\n", STATUS_FAILED);
    printf("  STATUS_CANCELLED: %d\n", STATUS_CANCELLED);
    
    // Using enums in practice
    enum Status task_status = STATUS_PENDING;
    printf("\nTask status: %s (%d)\n", 
           status_to_string(task_status), task_status);
    
    task_status = STATUS_PROCESSING;
    printf("Updated status: %s (%d)\n", 
           status_to_string(task_status), task_status);
    
    // Log level example
    printf("\nLog levels:\n");
    for (LogLevel level = LEVEL_DEBUG; level <= LEVEL_CRITICAL; level++) {
        printf("  %s: %d\n", level_to_string(level), level);
    }
    
    // Enum in switch statement
    LogLevel current_level = LEVEL_WARNING;
    printf("\nProcessing log level %s:\n", level_to_string(current_level));
    
    switch (current_level) {
        case LEVEL_DEBUG:
        case LEVEL_INFO:
            printf("  Information message\n");
            break;
        case LEVEL_WARNING:
            printf("  Warning: Something might be wrong\n");
            break;
        case LEVEL_ERROR:
        case LEVEL_CRITICAL:
            printf("  Error: Action required!\n");
            break;
    }
}

// Bit fields in structures
struct PackedData {
    unsigned int flag1 : 1;     // 1 bit
    unsigned int flag2 : 1;     // 1 bit
    unsigned int counter : 6;   // 6 bits (0-63)
    unsigned int type : 4;      // 4 bits (0-15)
    unsigned int reserved : 4;  // 4 bits unused
    // Total: 16 bits = 2 bytes
};

void bit_fields_demo(void) {
    printf("\n=== Bit Fields Demo ===\n");
    
    struct PackedData data = {0};
    printf("sizeof(struct PackedData): %zu bytes\n", sizeof(struct PackedData));
    
    // Set bit fields
    data.flag1 = 1;
    data.flag2 = 0;
    data.counter = 42;
    data.type = 7;
    
    printf("flag1: %u\n", data.flag1);
    printf("flag2: %u\n", data.flag2);
    printf("counter: %u\n", data.counter);
    printf("type: %u\n", data.type);
    printf("reserved: %u\n", data.reserved);
    
    // Show raw bytes
    unsigned char *bytes = (unsigned char*)&data;
    printf("Raw bytes: ");
    for (size_t i = 0; i < sizeof(data); i++) {
        printf("0x%02X ", bytes[i]);
    }
    printf("\n");
    
    // Bit field overflow (be careful!)
    data.counter = 70;  // Exceeds 6-bit range (0-63)
    printf("counter after overflow (70 -> %u): %u\n", 70, data.counter);
}

int main(void) {
    basic_structures_demo();
    structure_functions_demo();
    nested_structures_demo();
    structure_arrays_demo();
    dynamic_structures_demo();
    structure_memory_layout();
    unions_demo();
    enumerations_demo();
    bit_fields_demo();
    
    printf("\n=== Structures, Unions, Enums Best Practices ===\n");
    printf("Structures:\n");
    printf("1. Use meaningful names for structure members\n");
    printf("2. Consider memory alignment for performance\n");
    printf("3. Use const for read-only structure parameters\n");
    printf("4. Initialize structures to avoid garbage values\n");
    
    printf("\nUnions:\n");
    printf("1. Use tagged unions to track which member is active\n");
    printf("2. Be careful about endianness when interpreting bytes\n");
    printf("3. Understand that all members share the same memory\n");
    
    printf("\nEnumerations:\n");
    printf("1. Use enums for named constants and state machines\n");
    printf("2. Provide string conversion functions for debugging\n");
    printf("3. Consider using typedef for cleaner code\n");
    printf("4. Handle unknown values in switch statements\n");
    
    return 0;
}
```