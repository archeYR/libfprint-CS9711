envs = environment()
# Enable debug messages and abort on warnings
envs.set('G_DEBUG', 'fatal-warnings')
envs.set('G_MESSAGES_DEBUG', 'all')

# Setup paths
envs.set('MESON_SOURCE_ROOT', meson.project_source_root())
envs.set('MESON_BUILD_ROOT', meson.project_build_root())
envs.set('G_TEST_SRCDIR', meson.current_source_dir())
envs.set('G_TEST_BUILDDIR', meson.current_build_dir())
envs.prepend('LD_LIBRARY_PATH', meson.project_build_root() / 'libfprint')

# Set fp_device_emulation_env_var so that drivers can adapt (e.g. to use fixed
# random numbers rather than proper ones)
fp_device_emulation_env_var = 'FP_DEVICE_EMULATION'
envs.set(fp_device_emulation_env_var, '1')

# Set a colon-separated list of native drivers we enable in tests
envs.set('FP_DRIVERS_ALLOWLIST', ':'.join([
    'virtual_image',
    'virtual_device',
    'virtual_device_storage',
]))

envs.set('FP_PRINTS_PATH', meson.project_source_root() / 'examples' / 'prints')

envs.set('NO_AT_BRIDGE', '1')

installed_tests = get_option('installed-tests')
installed_tests_execdir = libexecdir / 'installed-tests' / versioned_libname
installed_tests_testdir = datadir / 'installed-tests' / versioned_libname
installed_tests_libdir = libdir

drivers_tests = {
    'aes2501': { 'timeout': 20 },
    'aes2550': {},
    'aes3500': {},
    'elan': {},
    'elan-cobo': {},
    'elanmoc': {},
    'elanspi': { 'timeout': 30 },
    'synaptics': {},
    'upektc_img': {},
    'upektc_img-tcs1s': {},
    'uru4000-msv2': {},
    'uru4000-4500': {},
    'vfs0050': {},
    'vfs301': {},
    'vfs5011': {},
    'vfs7552': {},
    'goodixmoc': {},
    'nb1010': {},
    'egis0570': {},
    'egismoc': {},
    'egis_etu905': {},
    'egismoc-05a1': {},
    'egismoc-0586': {},
    'egismoc-0587': {},
    'fpcmoc': {},
	'realtek': {},
	'realtek-5816': {},
    'focaltech_moc': { 'timeout': 30 },
    'focaltech_moc-6553': {},
    'mafpmoc': {},
    'secugen': {},
}

if get_option('introspection')
  conf = configuration_data()
  conf.set('SRCDIR', meson.project_source_root())
  conf.set('BUILDDIR', meson.project_build_root())
  configure_file(configuration: conf,
      input: 'create-driver-test.py.in',
      output: 'create-driver-test.py')
endif

test_emulation_lib = shared_library('fprint-test-emulation',
    'test-emulation.c',
    dependencies: libfprint_private_dep,
    install: installed_tests,
    install_dir: installed_tests_execdir,
)

# Paths where the test-emulation helper may be loaded via dlopen
test_emulation = configuration_data()
test_emulation.set_quoted('FPI_EMULATION_ENV_VAR',
  fp_device_emulation_env_var)
test_emulation.set_quoted('FPI_EMULATION_HELPER_BUILDDIR',
  meson.project_build_root() / 'tests')
test_emulation.set_quoted('FPI_EMULATION_HELPER_INSTALLDIR',
  libexecdir / 'installed-tests' / versioned_libname)
test_emulation.set_quoted('FPI_EMULATION_HELPER_MODULE',
  fs.name(test_emulation_lib.full_path()))
configure_file(output: 'fpi-test-emulation.h', configuration: test_emulation)

env_parser_cmd = '''
import os;
print(" ".join([f"{k}={v}" for k, v in os.environ.items()
    if k.startswith("FP_") or k.startswith("G_")]))
'''

envs_str = run_command(python3, '-c', env_parser_cmd,
    env: envs,
    check: installed_tests).stdout().strip()

envs_str = ' '.join([
    envs_str,
    'G_TEST_SRCDIR=' + installed_tests_testdir,
    'G_TEST_BUILDDIR=' + installed_tests_execdir,
])

if get_option('introspection')
    envs.prepend('GI_TYPELIB_PATH', meson.project_build_root() / 'libfprint')
    virtual_devices_tests = [
        'virtual-image',
        'virtual-device',
    ]

    unittest_inspector = find_program('unittest_inspector.py')
    umockdev_test_name = 'umockdev-test.py'
    umockdev_test = find_program(umockdev_test_name)

    foreach vdtest: virtual_devices_tests
        driver_name = '_'.join(vdtest.split('-'))
        if driver_name in drivers
            base_args = files(vdtest + '.py')
            suite = ['virtual-driver']

            r = run_command(unittest_inspector, files(vdtest + '.py'), check: false)
            unit_tests = r.stdout().strip().split('\n')

            if r.returncode() == 0 and unit_tests.length() > 0
                suite += vdtest
            elif r.returncode() == 77
                test(vdtest,
                    sh,
                    args: ['-c', 'exit 77']
                )
                continue
            else
                unit_tests = [vdtest]
            endif

            foreach ut: unit_tests
                ut_suite = suite
                ut_args = base_args
                if unit_tests.length() > 1
                    ut_args += ut
                    ut_suite += ut.split('.')[0]
                endif
                test(ut,
                    python3,
                    args: ut_args,
                    suite: ut_suite,
                    depends: [
                        libfprint_typelib,
                        test_emulation_lib,
                    ],
                    env: envs,
                )
            endforeach

            if installed_tests
                install_data(base_args,
                    install_dir: installed_tests_execdir,
                    install_mode: 'rwxr-xr-x',
                )

                configure_file(
                    input: 'test.in',
                    output: vdtest + '.test',
                    install_dir: installed_tests_testdir,
                    configuration: {
                        'exec': installed_tests_execdir / fs.name(base_args[0]),
                        'env': ' '.join([
                            envs_str,
                            'LD_LIBRARY_PATH=' + installed_tests_libdir,
                            'FP_PRINTS_PATH=' + installed_tests_testdir / 'prints',
                            # FIXME: Adding this requires gnome-desktop-testing!12
                            # 'GI_TYPELIB_PATH=' + installed_tests_libdir / 'girepository-1.0',
                        ]),
                        'extra_content': '',
                    },
                )
            endif
        else
            test(vdtest,
                sh,
                args: ['-c', 'exit 77']
            )
        endif
    endforeach

    driver_tests_enabled = false
    foreach driver_test, args: drivers_tests
        driver_name = driver_test.split('-')[0]
        driver_envs = envs
        driver_envs.set('FP_DRIVERS_ALLOWLIST', driver_name)

        if (driver_name in supported_drivers and
            gusb_dep.version().version_compare('>= 0.3.0'))

            test_types = []
            foreach test_type: args.get('test_types', ['custom', 'capture'])
                test_file_prefix = meson.current_source_dir() / driver_test / test_type
                if fs.exists(test_file_prefix + '.py')
                    test_types += [test_type]
                elif fs.exists(test_file_prefix + '.png')
                    test_types += [test_type]
                elif fs.exists(test_file_prefix + '.ioctl')
                    test_types += [test_type]
                elif fs.exists(test_file_prefix + '.pcapng')
                    test_types += [test_type]
                endif
            endforeach

            assert(test_types.length() > 0,
                'No test types found for driver ' + driver_test)

            foreach test_type: test_types
                driver_tests_enabled = true
                test_name = driver_test + (test_types.length() > 1 ? '-' + test_type : '')
                test(test_name,
                    python3,
                    args: [
                        umockdev_test.full_path(),
                        meson.current_source_dir() / driver_test,
                        '--test', test_type,
                    ],
                    env: driver_envs,
                    is_parallel: args.get('is_parallel', true),
                    priority: args.get('priority', 0),
                    protocol: args.get('protocol', 'exitcode'),
                    should_fail: args.get('should_fail', false),
                    suite: ['drivers', test_type] + args.get('suite', []),
                    timeout: args.get('timeout', 15),
                    verbose: args.get('verbose', false),
                    depends: [
                        libfprint_typelib,
                        test_emulation_lib,
                    ],
                )
            endforeach

            if installed_tests
                driver_envs_str = run_command(python3, '-c', env_parser_cmd,
                    env: driver_envs,
                    check: true).stdout().strip()

                configure_file(
                    input: 'driver.test.in',
                    output: 'driver-' + driver_test + '.test',
                    install_dir: installed_tests_testdir,
                    configuration: {
                        'installed_tests_execdir': installed_tests_execdir,
                        'installed_tests_testdir': installed_tests_testdir,
                        'umockdev_test_name': umockdev_test_name,
                        'driver_test': driver_test,
                        'driver_env': ' '.join([
                            driver_envs_str,
                            'LD_LIBRARY_PATH=' + installed_tests_libdir,
                            # FIXME: Adding this requires gnome-desktop-testing!12
                            # 'GI_TYPELIB_PATH=' + installed_tests_libdir / 'girepository-1.0',
                        ]),
                    },
                )

                install_subdir(driver_test, install_dir: installed_tests_testdir)
            endif
        else
            test(driver_test,
                sh,
                args: ['-c', 'exit 77']
            )
        endif
    endforeach

    if  installed_tests and driver_tests_enabled
        install_data(umockdev_test.full_path(),
            install_dir: installed_tests_execdir,
            install_mode: 'rwxr-xr-x',
        )
        install_data('capture.py',
            install_dir: installed_tests_execdir,
            install_mode: 'rwxr-xr-x',
        )
    endif
else
    warning('Skipping all driver tests as introspection bindings are missing')
    test('virtual-image',
        sh,
        args: ['-c', 'exit 77']
    )

    foreach driver_test: drivers_tests
        test(driver_test,
            sh,
            args: ['-c', 'exit 77']
        )
    endforeach
endif

test_utils = static_library('fprint-test-utils',
    sources: [
        'test-utils.c',
        'test-device-fake.c',
    ],
    dependencies: libfprint_private_dep,
    install: false)

unit_tests = [
    'fpi-device',
    'fpi-ssm',
    'fpi-assembling',
]

if 'cs9711' in supported_drivers
    unit_tests += ['cs9711']
endif

if 'virtual_image' in drivers
    unit_tests += [
        'fp-context',
        'fp-device',
    ]
endif

unit_tests_deps = { 'fpi-assembling' : [cairo_dep] }

foreach test_name: unit_tests
    if unit_tests_deps.has_key(test_name)
        missing_deps = false
        foreach dep: unit_tests_deps[test_name]
            if not dep.found()
                missing_deps = true
                break
            endif
        endforeach

        if missing_deps
            # Create a dummy test that always skips instead
            warning('Test @0@ cannot be compiled due to missing dependencies'.format(test_name))
            test(test_name,
                sh,
                suite: ['unit-tests'],
                args: ['-c', 'exit 77'],
            )
            continue
        endif
        extra_deps = unit_tests_deps[test_name]
    else
        extra_deps = []
    endif

    basename = 'test-' + test_name
    extra_link_with = []
    if test_name == 'cs9711'
        extra_link_with += libfprint_drivers
    endif
    test_exe = executable(basename,
        sources: basename + '.c',
        dependencies: [ libfprint_private_dep ] + extra_deps,
        c_args: common_cflags,
        link_with: extra_link_with,
        link_whole: test_utils,
        install: installed_tests,
        install_dir: installed_tests_execdir,
    )
    test(test_name,
        test_exe,
        suite: ['unit-tests'],
        env: envs,
    )

    configure_file(
        input: 'test.in',
        output: test_name + '.test',
        install: installed_tests,
        install_dir: installed_tests_testdir,
        configuration: {
            'exec': installed_tests_execdir / basename,
            'env': envs_str,
            'extra_content': 'TestEnvironment=LD_LIBRARY_PATH=' +
                installed_tests_libdir,
        },
    )
endforeach

# Run udev rule generator with fatal warnings
hwdb_envs = envs
hwdb_envs.set('UDEV_HWDB', udev_hwdb.full_path())
hwdb_envs.set('UDEV_HWDB_CHECK_CONTENTS', default_drivers_are_enabled ? '1' : '0')
hwdb_envs.set('G_MESSAGES_DEBUG', '')
test('udev-hwdb',
     find_program('test-generated-hwdb.sh'),
     depends: udev_hwdb,
     suite: ['data', 'no-valgrind'],
     env: hwdb_envs,
)

appstreamcli = find_program('appstreamcli', required: false)
if appstreamcli.found()
    test('metainfo-validate',
        appstreamcli,
        args: ['validate', metainfo_generator],
        depends: metainfo_generator,
        suite: ['data', 'no-valgrind'],
    )
endif

gdb = find_program('gdb', required: false)
if gdb.found() and libfprint_sanitizers.length() == 0
    libfprint_wrapper = [
        gdb.full_path(),
        '-batch',
        '-ex', 'run',
        '--args',
    ]
    add_test_setup('gdb',
        timeout_multiplier: 1000,
        exe_wrapper: libfprint_wrapper,
        env: [
            'LIBFPRINT_TEST_WRAPPER=' + ' '.join(libfprint_wrapper),
        ])
endif

if ('address' in libfprint_sanitizers or
    'undefined' in libfprint_sanitizers or
    'leak' in libfprint_sanitizers)
    add_test_setup('sanitizers',
        is_default: true,
        timeout_multiplier: 3,
        env: [
            'ASAN_OPTIONS=verify_asan_link_order=0',
        ])
endif

valgrind = find_program('valgrind', required: false)
if valgrind.found() and libfprint_sanitizers.length() == 0
    glib_share = glib_dep.get_variable(pkgconfig: 'prefix') / 'share' / glib_dep.name()
    glib_suppressions = glib_share + '/valgrind/glib.supp'
    libfprint_suppressions = files('libfprint.supp')[0]
    python_suppressions = files('valgrind-python.supp')[0]

    if meson.version().version_compare('>=1.4')
        libfprint_suppressions = libfprint_suppressions.full_path()
        python_suppressions = python_suppressions.full_path()
    else
        libfprint_suppressions = meson.project_source_root() / '@0@'.format(libfprint_suppressions)
        python_suppressions = meson.project_source_root() / '@0@'.format(python_suppressions)
    endif

    libfprint_wrapper = [
        valgrind.full_path(),
        '--tool=memcheck',
        '--leak-check=full',
        '--leak-resolution=high',
        '--error-exitcode=1',
        '--errors-for-leak-kinds=definite',
        '--track-origins=yes',
        '--show-leak-kinds=definite,possible',
        '--show-error-list=yes',
        '--gen-suppressions=all',
        '--suppressions=' + libfprint_suppressions,
        '--suppressions=' + glib_suppressions,
        '--suppressions=' + python_suppressions,
    ]
    add_test_setup('valgrind',
        timeout_multiplier: 20,
        exe_wrapper: libfprint_wrapper,
        exclude_suites: ['no-valgrind'],
        env: [
            'G_SLICE=always-malloc',
            'UNDER_VALGRIND=1',
            'FP_VIRTUAL_IMAGE_HOT_SECONDS=-1',
            'FP_VIRTUAL_DEVICE_HOT_SECONDS=-1',
            'LIBFPRINT_TEST_WRAPPER=' + ' '.join(libfprint_wrapper),
        ])
endif
