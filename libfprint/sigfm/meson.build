
sigfm_sources = ['sigfm.cpp']

opencv = dependency('opencv4', required: false)
if not opencv.found()
  opencv = dependency('opencv5', required: false)
endif
if not opencv.found()
  opencv = dependency('opencv', required: false)
endif
if not opencv.found()
  opencv = dependency('OpenCV', method: 'cmake', required: true)
endif
doctest = dependency('doctest', required: false)

libsigfm = static_library('sigfm',
        sigfm_sources,
        dependencies: [opencv],
)
if doctest.found()
sigfm_tests = executable('sigfm-tests', ['./tests.cpp'], dependencies: [doctest, opencv], link_with: [libsigfm])
endif
