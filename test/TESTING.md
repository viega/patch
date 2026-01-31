# Testing Overview

This document provides a comprehensive overview of the test suite for the `patch` runtime function hooking library.

## Test Suite Structure

```
test/
├── test_basic.c          # Basic functionality and platform detection
├── test_hooks.c          # Integration tests for hook callbacks
├── test_realworld.c      # Real-world libc function hooking
├── test_comprehensive.c  # Exhaustive feature coverage
└── TESTING.md            # This document
```

## Running Tests

### Native (macOS)

```bash
# Setup (first time only)
CC=/usr/local/bin/clang meson setup build

# Build and test
meson compile -C build
meson test -C build

# Verbose output
meson test -C build -v
```

### Docker (Linux ARM64 + x86-64)

```bash
# Test both architectures
./scripts/test-docker.sh

# Test specific architecture
./scripts/test-docker.sh arm64
./scripts/test-docker.sh amd64
```

## Test Files

### test_basic.c

**Purpose**: Verify core functionality works on the current platform.

| Test | Description |
|------|-------------|
| Basic function calls | Verify `PATCH_CALL` invokes hookable functions correctly |
| Unified hook interface | Install/remove hooks via `PATCH_HOOK_INSTALL/REMOVE` |
| Multiple hooks | Multiple functions hooked simultaneously |
| Hook method selection | `PATCH_METHOD_POINTER` vs `PATCH_METHOD_CODE` (Linux) |
| Low-level patch API | Direct use of `patch_install()` with callbacks |
| `patch_can_install` | Pattern recognition and error handling |

**Platform behavior**:
- macOS: Skips low-level API tests (hardware W^X prevents code patching)
- Linux: Full test coverage including code patching

---

### test_hooks.c

**Purpose**: Integration tests for prologue/epilogue callback system.

| Test | Description |
|------|-------------|
| Hook is called | Basic hook invocation verification |
| Multiple independent hooks | Several functions hooked at once |
| Hook calling original | Recursive safety when hook calls original |
| Re-hook after remove | Install → remove → reinstall cycle |

**Low-level API tests** (Linux only):

| Test | Description |
|------|-------------|
| Prologue receives arguments | `patch_context_get_arg()` returns correct values |
| Epilogue receives return value | `patch_context_get_return()` works correctly |
| Prologue can modify arguments | `patch_context_set_arg()` changes values |
| Epilogue can modify return | `patch_context_set_return()` changes result |
| Prologue can skip original | Returning `false` bypasses original function |
| Both callbacks | Prologue and epilogue work together |
| Disable and enable | `patch_disable()` / `patch_enable()` cycle |

---

### test_realworld.c

**Purpose**: Hook actual libc functions to verify real-world applicability.

| Test | Description |
|------|-------------|
| Inspect libc functions | Check which libc functions are hookable |
| Hook `strlen()` | Attempt to hook string length function |
| Hook `atoi()` | Hook string-to-integer conversion |
| Track allocations | Attempt to hook `malloc`/`free` |

**Expected results**:
- Many libc functions have NOP sleds and are hookable
- Some functions (optimized assembly) cannot be hooked
- Results vary by libc version and compiler flags

---

### test_comprehensive.c

**Purpose**: Exhaustive testing of all features and edge cases.

#### Section 1: API Validation

| Test | Description |
|------|-------------|
| Null argument validation | All APIs reject NULL pointers correctly |
| Config validation | Mutual exclusivity of replacement vs callbacks |

#### Section 2: Simple Replacement Mode

| Test | Description |
|------|-------------|
| Simple replacement mode | Direct function replacement without dispatcher |
| Disable/enable cycle | `patch_disable()` → verify original → `patch_enable()` |

**Key implementation detail**: Simple replacement mode stores the replacement function pointer and uses `patch_get_trampoline()` to call the original.

#### Section 3: PATCH_METHOD_CODE

| Test | Description |
|------|-------------|
| Basic functionality | Code patching works correctly |
| CODE vs POINTER | Both methods produce identical results |

**Key implementation detail**: `PATCH_HOOK_ORIGINAL()` automatically uses the trampoline when code patching is active.

#### Section 4: Edge Cases

| Test | Description |
|------|-------------|
| Rapid hook/unhook | 100 install/remove cycles without issues |
| Multiple functions | 4 functions hooked simultaneously |
| Hook calls original | Verify no infinite recursion |
| Identity function | Minimal function body handling |
| IS_INSTALLED macro | State tracking works correctly |
| Idempotent operations | Double disable/enable succeeds |

#### Section 5: Data Types

| Test | Description |
|------|-------------|
| 6 register arguments | All register args passed correctly |
| 64-bit return value | Large integers handled properly |
| Pointer return value | Address values preserved |

**Note**: Floating-point arguments/returns are not tested because the dispatcher only saves integer registers.

#### Section 6: Error Handling

| Test | Description |
|------|-------------|
| Error details API | `patch_get_error_details()` returns useful messages |

#### Section 7: Platform Detection

| Test | Description |
|------|-------------|
| Platform detection | Correct platform/arch macros defined |
| Pattern recognition | Test functions have expected NOP sleds |

---

## Platform-Specific Behavior

### macOS ARM64

- **Code patching**: Not available (hardware W^X enforcement)
- **Hook method**: Always uses pointer indirection
- **Test coverage**: ~50% of comprehensive tests run (others skipped)
- **Low-level API**: Stubbed to return `PATCH_ERR_MEMORY_PROTECTION`

### Linux ARM64

- **Code patching**: Full support via NOP sleds
- **Hook method**: Both POINTER and CODE available
- **NOP sled size**: 8 bytes (2 × 4-byte NOPs)
- **Register args**: 8 (x0-x7)

### Linux x86-64

- **Code patching**: Full support via NOP sleds
- **Hook method**: Both POINTER and CODE available
- **NOP sled size**: 8 bytes (8 × 1-byte NOPs)
- **Register args**: 6 (rdi, rsi, rdx, rcx, r8, r9)

---

## Test Macros

The test files use these macros for consistent output:

```c
#define TEST_PASS()      // Increment pass counter, print "PASSED"
#define TEST_FAIL(msg)   // Increment fail counter, print "FAILED: msg"
#define TEST_SKIP(msg)   // Increment skip counter, print "SKIPPED: msg"
```

---

## Coverage Matrix

| Feature | test_basic | test_hooks | test_realworld | test_comprehensive |
|---------|:----------:|:----------:|:--------------:|:------------------:|
| PATCH_DEFINE_HOOKABLE | ✓ | ✓ | | ✓ |
| PATCH_CALL | ✓ | ✓ | | ✓ |
| PATCH_HOOK_INSTALL | ✓ | ✓ | | ✓ |
| PATCH_HOOK_REMOVE | ✓ | ✓ | | ✓ |
| PATCH_CALL_ORIGINAL | ✓ | ✓ | | ✓ |
| PATCH_METHOD_POINTER | ✓ | | | ✓ |
| PATCH_METHOD_CODE | ✓ | | | ✓ |
| patch_install() | ✓ | ✓ | ✓ | ✓ |
| patch_remove() | ✓ | ✓ | ✓ | ✓ |
| patch_disable() | | ✓ | | ✓ |
| patch_enable() | | ✓ | | ✓ |
| patch_can_install() | ✓ | | ✓ | ✓ |
| patch_get_trampoline() | | | | ✓ |
| patch_get_error_details() | | | | ✓ |
| Prologue callbacks | ✓ | ✓ | ✓ | |
| Epilogue callbacks | | ✓ | | |
| Argument inspection | | ✓ | | |
| Argument modification | | ✓ | | |
| Return value modification | | ✓ | | |
| Skip original | | ✓ | | |
| External functions | | | ✓ | |
| Simple replacement | | | | ✓ |
| Multiple arguments | | | | ✓ |
| 64-bit values | | | | ✓ |
| Pointer values | | | | ✓ |

---

## Known Limitations

### Not Tested

1. **Floating-point arguments/returns**: The dispatcher only saves integer registers. Hooks on functions with float/double parameters may corrupt values.

2. **Stack arguments**: Only register arguments (6 on x86-64, 8 on ARM64) are accessible via `patch_context_get_arg()`.

3. **Variadic functions**: Functions like `printf` can be hooked, but accessing variable arguments requires manual parsing.

4. **Thread safety during install/remove**: Installing or removing hooks while other threads are executing the target function may cause crashes.

5. **Nested hooks**: Installing a hook from within a hook callback is not tested.

### Platform Limitations

1. **macOS**: Cannot hook functions without using pointer indirection due to hardware W^X.

2. **Functions without NOP sleds**: Only functions compiled with `patchable_function_entry` can be hooked via code patching.

3. **Optimized libc functions**: Hand-written assembly functions (memcpy, strlen, etc.) typically cannot be hooked.

---

## Adding New Tests

### Basic Test Template

```c
static void test_my_feature(void)
{
    printf("Test: My feature description...\n");

#ifndef PATCH_PLATFORM_DARWIN
    // Linux-only test code

    patch_error_t err = patch_can_install((void*)my_function);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    // Test implementation...

    assert(expected_condition);
    TEST_PASS();
#else
    TEST_SKIP("Not available on macOS");
#endif
}
```

### Hook Function Template

```c
// For unified macro interface
static int my_hook(int arg) {
    // Call original via macro
    int result = PATCH_CALL_ORIGINAL(my_function, arg);
    return result + 100;
}

// For low-level API with simple replacement
static patch_handle_t *g_my_handle = NULL;

static int my_replacement(int arg) {
    typedef int (*orig_fn)(int);
    orig_fn original = (orig_fn)patch_get_trampoline(g_my_handle);
    return original(arg) + 100;
}
```

### Running Individual Tests

```bash
# Run specific test
./build/test_comprehensive

# Run with verbose meson output
meson test -C build comprehensive -v

# Debug a failing test
lldb ./build/test_comprehensive
```

---

## Test Output Example

### Successful Run (Linux ARM64)

```
=== Comprehensive Patch Library Tests ===
Platform: Linux ARM64

--- Section 1: API Validation ---

Test: Null argument validation...
  PASSED
Test: Config validation (replacement vs callbacks)...
  PASSED

--- Section 2: Simple Replacement Mode ---

Test: Simple replacement mode...
  PASSED
Test: Simple replacement disable/enable...
  PASSED

[... more tests ...]

========================================
Tests Passed:  18
Tests Failed:  0
Tests Skipped: 0
========================================

=== All Comprehensive Tests Passed ===
```

### macOS Run (Some Tests Skipped)

```
=== Comprehensive Patch Library Tests ===
Platform: macOS ARM64 (pointer indirection only)

--- Section 1: API Validation ---

Test: Null argument validation...
  PASSED
Test: Config validation (replacement vs callbacks)...
  SKIPPED: Low-level API not available on macOS

[... more tests ...]

========================================
Tests Passed:  10
Tests Failed:  0
Tests Skipped: 8
========================================

=== All Comprehensive Tests Passed ===
```

---

## Continuous Integration

The test suite is designed to run in CI environments:

1. **Exit codes**: Return 0 on success, 1 on any failure
2. **Unbuffered output**: `setvbuf(stdout, NULL, _IONBF, 0)` ensures output on crash
3. **Docker support**: Multi-arch testing via `./scripts/test-docker.sh`
4. **Meson integration**: Standard `meson test` interface

### CI Configuration Example

```yaml
test:
  script:
    - CC=/usr/local/bin/clang meson setup build
    - meson compile -C build
    - meson test -C build

test-linux:
  script:
    - ./scripts/test-docker.sh
```
