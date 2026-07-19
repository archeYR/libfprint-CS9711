
sigfm_sources = ['sigfm.cpp']

opencv = dependency('opencv4', required: true)
doctest_dep = dependency('doctest', required: true)
doctest = doctest_dep.partial_dependency(compile_args: true, includes: true)

libsigfm = static_library('sigfm',
        sigfm_sources,
        dependencies: [opencv],
)

sigfm_tests = executable('sigfm-tests', ['./tests.cpp'], dependencies: [doctest, opencv], link_with: [libsigfm])
