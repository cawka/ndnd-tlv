# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.3~dev0'
NAME="ndnd-tlv"

from waflib import Build, Logs, Utils, Task, TaskGen, Configure
import os

def options(opt):
    opt.load('compiler_c compiler_cxx gnu_dirs')
    opt.load('ndnx boost', tooldir=['waf-tools'])

    opt = opt.add_option_group('NDN TLV Daemon Options')
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--with-c++11', action='store_true', default=False, dest='use_cxx11',
                   help='''Enable C++11 compiler features''')
    opt.add_option('--with-tests', action='store_true',default=False,dest='with_tests',
                   help='''build unit tests''')
    
def configure(conf):
    conf.load("compiler_c compiler_cxx gnu_dirs ndnx boost")

    conf.find_program('sh')

    if conf.options.with_tests:
        conf.env['WITH_TESTS'] = True
    
    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        flags = ['-O0',
                 '-Wall',
                 '-Wno-unused-variable',
                 '-g3',
                 '-Wno-unused-private-field', # only clang supports
                 '-fcolor-diagnostics',       # only clang supports
                 '-Qunused-arguments',        # only clang supports
                 '-Wno-deprecated-declarations',
                 ]

        conf.add_supported_cxxflags (cxxflags = flags)
        conf.add_supported_cflags (cflags = flags + ['-std=gnu99'])
    else:
        flags = ['-O3', '-g', '-Wno-tautological-compare', '-Wno-unused-function', '-Wno-deprecated-declarations']
        conf.add_supported_cxxflags (cxxflags = flags)
        conf.add_supported_cflags (cflags = flags + ['-std=gnu99'])

    if conf.options.use_cxx11:
        conf.add_supported_cxxflags(cxxflags = ['-std=c++11', '-std=c++0x'])

    conf.define ("PACKAGE_BUGREPORT", "ndn-lib@lists.cs.ucla.edu")
    conf.define ("PACKAGE_NAME", NAME)
    conf.define ("PACKAGE_VERSION", VERSION)
    conf.define ("PACKAGE_URL", "https://github.com/named-data/ndnd-tlv")

    conf.check_ndnx()
    conf.check_openssl()

    conf.check_cfg(package='libndn-cpp-dev', args=['--cflags', '--libs'], uselib_store='NDN_CPP', mandatory=True)
        
    conf.check_cxx(lib='resolv',  uselib_store='RESOLV',  mandatory=True)
    conf.check_cxx(lib='dl', uselib_store='DL', mandatory=False)

    USED_BOOST_LIBS = 'system iostreams'
    if conf.env['WITH_TESTS']:
        USED_BOOST_LIBS += " unit_test_framework"
    conf.check_boost(lib=USED_BOOST_LIBS)

def build (bld):
    bld (target = 'ndn-tlv',
         name = 'ndn-tlv',
         features=['c', 'cxx', 'cxxstlib', 'cstlib'],
         source = bld.path.ant_glob(['lib/**/*.c', 'lib/**/*.cpp', 'tlv-hack/**/*.cpp']),
         use = 'SSL BOOST NDN_CPP DL',
         includes = "include",
         export_includes = "include",
         )

    bld (target="bin/ndnd-tlv",
         features=['c', 'cxx', 'cxxprogram'],
         source = bld.path.ant_glob(['ndnd/**/*.c', 'ndnd/**/*.cpp']),
         use = 'ndn-tlv',
        )

    for app in bld.path.ant_glob('tools/*', dir=True):
        if os.path.isdir(app.abspath()):
            bld(features=['c', 'cxx', 'cxxprogram'],
                target = 'bin/%s' % (str(app)),
                source = app.ant_glob(['**/*.c', '**/*.cpp']),
                use = 'ndn-tlv RESOLV',
                )

    for app in bld.path.ant_glob('tools/*.c'):
        bld(features=['c', 'cxxprogram'],
            target = 'bin/%s' % (str(app.change_ext('','.c'))),
            source = app,
            use = 'ndn-tlv',
            includes = "include",
            )

    bld (features = "subst",
         source = bld.path.ant_glob(['tools/**/*.sh']),
         target = ['bin/%s' % node.change_ext('', '.sh') for node in bld.path.ant_glob(['tools/**/*.sh'])],
         install_path = "${BINDIR}",
         chmod = 0755,
        )

    bld.install_files(bld.env['INCLUDEDIR'], bld.path.ant_glob(['include/**/*.h']), 
                      relative_trick=True, cwd=bld.path.find_node('include'))
    
    bld.install_files('%s/ndn-tlv' % bld.env['INCLUDEDIR'], bld.path.ant_glob(['tlv-hack/**/*.h', 'tlv-hack/**/*.hpp']), 
                      relative_trick=True, cwd=bld.path.find_node('tlv-hack'))
    
    # Unit tests
    if bld.env['WITH_TESTS']:
        bld.recurse('tests')

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags

@Configure.conf
def add_supported_cflags(self, cflags):
    """
    Check which cflags are supported by compiler and add them to env.CFLAGS variable
    """
    self.start_msg('Checking allowed flags for c compiler')

    supportedFlags = []
    for flag in cflags:
        if self.check_cc (cflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CFLAGS += supportedFlags
