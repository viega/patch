project('patch', 'c',
    version: '0.1.0',
    default_options: [
        'c_std=gnu23',
        'warning_level=3',
        'werror=true',
    ]
)

cc = meson.get_compiler('c')

# Detect architecture
arch = host_machine.cpu_family()
if arch == 'x86_64'
    arch_sources = ['src/arch/x86_64.c']
    pattern_sources = ['src/pattern/x86_64_common.c']
elif arch == 'aarch64'
    arch_sources = ['src/arch/arm64.c']
    pattern_sources = ['src/pattern/arm64_common.c']
else
    error('Unsupported architecture: ' + arch)
endif

# Detect platform
os = host_machine.system()
if os == 'darwin'
    platform_sources = ['src/platform/darwin.c']
elif os == 'linux'
    platform_sources = ['src/platform/linux.c']
else
    error('Unsupported platform: ' + os)
endif

# Include directories
inc = include_directories('include', 'src')

# Source files
lib_sources = [
    'src/patch.c',
    'src/trampoline.c',
    'src/pattern/registry.c',
] + arch_sources + pattern_sources + platform_sources

# Build the library
patch_lib = static_library('patch',
    lib_sources,
    include_directories: inc,
    install: true,
)

# Declare dependency for other projects
patch_dep = declare_dependency(
    include_directories: include_directories('include'),
    link_with: patch_lib,
)

# Install headers
install_headers(
    'include/patch/patch.h',
    'include/patch/patch_arch.h',
    subdir: 'patch',
)

# Tests
test_basic = executable('test_basic',
    'test/test_basic.c',
    include_directories: inc,
    link_with: patch_lib,
)

test('basic', test_basic)
