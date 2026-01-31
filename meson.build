project('patch', 'c',
    version: '0.1.0',
    default_options: [
        'c_std=gnu23',
        'warning_level=3',
        'werror=true',
    ]
)

cc = meson.get_compiler('c')

# Optional libffi dependency for full argument forwarding
libffi_opt = get_option('use_libffi')
if libffi_opt
    libffi_dep = dependency('libffi', required: true)
    add_project_arguments('-DPATCH_HAVE_LIBFFI=1', language: 'c')
else
    libffi_dep = dependency('libffi', required: false)
    if libffi_dep.found()
        add_project_arguments('-DPATCH_HAVE_LIBFFI=1', language: 'c')
    endif
endif

# Detect architecture
# Pattern recognition is merged into the arch files
arch = host_machine.cpu_family()
if arch == 'x86_64'
    arch_sources = ['src/arch/x86_64.c']
elif arch == 'aarch64'
    arch_sources = ['src/arch/arm64.c']
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
    'src/dispatcher.c',
    'src/breakpoint.c',
    'src/watchpoint.c',
    'src/pattern/registry.c',
] + arch_sources + platform_sources

# Build the library
patch_lib = static_library('patch',
    lib_sources,
    include_directories: inc,
    dependencies: libffi_dep.found() ? [libffi_dep] : [],
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

# Tests - all need libffi if available since patch.h includes ffi.h
test_deps = libffi_dep.found() ? [libffi_dep] : []

test_basic = executable('test_basic',
    'test/test_basic.c',
    include_directories: inc,
    link_with: patch_lib,
    dependencies: test_deps,
)

test_hooks = executable('test_hooks',
    'test/test_hooks.c',
    include_directories: inc,
    link_with: patch_lib,
    dependencies: test_deps,
)

test_realworld = executable('test_realworld',
    'test/test_realworld.c',
    include_directories: inc,
    link_with: patch_lib,
    dependencies: test_deps + [cc.find_library('dl', required: false)],
)

test_comprehensive = executable('test_comprehensive',
    'test/test_comprehensive.c',
    include_directories: inc,
    link_with: patch_lib,
    dependencies: test_deps,
)

test('basic', test_basic)
test('hooks', test_hooks)
test('realworld', test_realworld)
test('comprehensive', test_comprehensive)

# Examples (optional, not built by default)
subdir('examples')
