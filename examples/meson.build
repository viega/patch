# Examples - build with: meson compile -C build examples
# These are not built by default since they're for demonstration

examples = [
    'basic_hook',
    'function_trace',
    'argument_modify',
    'malloc_tracker',
    'api_mock',
]

foreach example : examples
    executable(
        example,
        example + '.c',
        include_directories: include_directories('../include'),
        link_with: patch_lib,
        dependencies: test_deps,
        build_by_default: false,
    )
endforeach
