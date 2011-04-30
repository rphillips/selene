#
# Licensed to Selene developers ('Selene') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# Selene licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

EnsureSConsVersion(1, 1, 0)

import os, sys
from site_scons import ac
from os.path import join as pjoin

opts = Variables('build.py')

opts.Add(PathVariable('with_openssl',
                      'Prefix to OpenSSL installation', None))

opts.Add(EnumVariable('profile', 'build profile', 'debug', ['debug', 'gcov', 'release'], {}, True))

opts.Add('enable_openssl_threaded', default=False, help='Enable Threaded OpenSSL backend')
opts.Add('enable_native', default=True, help='Enable Native TLS, using OpenSSL for crytpo operations')

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

conf = Configure(env, custom_tests = {'CheckUname': ac.CheckUname})

conf.env['PYTHON'] = env.WhereIs('python')
if not conf.env['PYTHON']:
  conf.env['PYTHON'] = sys.executable

conf.env['CLANG'] = env.WhereIs('clang')
conf.env['CLANGXX'] = env.WhereIs('clang++')

if conf.env['CLANG']:
  conf.env['CC'] = conf.env['CLANG']

if conf.env['CLANGXX']:
  conf.env['CXX'] = conf.env['CLANGXX']

if os.environ.has_key('CC'):
  conf.env['CC'] = os.environ['CC']

if os.environ.has_key('CXX'):
  conf.env['CXX'] = os.environ['CXX']

(st, platform) = conf.CheckUname("-sm")

conf.env['SELENE_PLATFORM'] = platform[:platform.find(' ')].upper()
conf.env['SELENE_ARCH'] = platform[platform.find(' ')+1:].replace(" ", "_")

conf.env['WANT_OPENSSL'] = False

if conf.env['enable_native']:
  conf.env['WANT_OPENSSL'] = True
  conf.env.AppendUnique(CPPDEFINES=['WANT_NATIVE'])

if conf.env['enable_openssl_threaded']:
  conf.env['WANT_OPENSSL'] = True
  conf.env.AppendUnique(CPPDEFINES=['WANT_OPENSSL_THREADED'])
  if conf.CheckLibWithHeader('libpthread', 'pthread.h', 'C', '', True):
    conf.env.AppendUnique(CPPDEFINES=['WANT_PTHREADS'])

if conf.env['WANT_OPENSSL']:
  if conf.env.get('with_openssl'):
    conf.env.AppendUnique(LIBPATH=["${with_openssl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_openssl}/include"])
  conf.env['HAVE_OPENSSL'] = conf.CheckLibWithHeader('libssl', 'openssl/ssl.h', 'C', 'SSL_library_init();', True)
  if not conf.env['HAVE_OPENSSL']:
    print 'Unable to use OpenSSL development enviroment: with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(-1)
  conf.env['HAVE_CRYPTO'] = conf.CheckLibWithHeader('libcrypto', 'openssl/err.h', 'C', 'ERR_load_crypto_strings();', True)
  if not conf.env['HAVE_OPENSSL']:
    print 'Unable to use OpenSSL development enviroment (missing libcrypto?): with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(-1)

env = conf.Finish()

options = {
  'PLATFORM': {
    'DARWIN': {
      'CPPDEFINES': ['DARWIN'],
    },
    'LINUX': {
      'CPPDEFINES': ['LINUX', '_XOPEN_SOURCE'],
    },
    'FREEBSD': {
      'CPPDEFINES': ['FREEBSD'],
    },
  },
  'PROFILE': {
    'DEBUG': {
      'CCFLAGS': ['-Wall', '-O0', '-ggdb'],
      'CPPDEFINES': ['DEBUG'],
    },
    'GCOV': {
      'CC': 'gcc',
      'CCFLAGS': ['-Wall', '-O0', '-ggdb', '-fPIC', '-fprofile-arcs', '-ftest-coverage'],
      'CPPDEFINES': ['DEBUG'],
      'LIBS': 'gcov'
    },
    'RELEASE': {
      'CCFLAGS': ['-Wall', '-O2'],
      'CPPDEFINES': ['NODEBUG'],
    },
  },
}

variants = []
for platform in [env['SELENE_PLATFORM']]:
  profiles = [env['profile'].upper()]
  if 'coverage' in COMMAND_LINE_TARGETS:
    profiles.append('GCOV')
  for profile in set(profiles):
    for build in ['STATIC', 'SHARED']:
      variants.append({'PLATFORM': platform, 'PROFILE': profile, 'BUILD': build})

append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES', 'LIBS']
replace_types = ['CC']
test_targets = []

# defaults for all platforms
# TODO: non-gcc/clang platforms
env.AppendUnique(CPPPATH=['#/include'],
                 CCFLAGS=['-pedantic', '-std=c99'])
all_targets = {}

coverage_test_targets = []
for vari in variants:
  targets = []
  platform = vari['PLATFORM']
  profile =  vari['PROFILE']
  build = vari['BUILD']
  variant = '%s-%s-%s' % (platform.lower(), profile.lower(), build.lower())
  vdir = pjoin('build', variant)
  venv = env.Clone()
  venv['SELEN_LIB_TYPE'] = build

  for k in sorted(options.keys()):
    ty = vari.get(k)
    if options[k].has_key(ty):
      for key,value in options[k][ty].iteritems():
        if key in append_types:
          p = {key: value}
          venv.AppendUnique(**p)
        elif key in replace_types:
          venv[key] = value
        else:
          print('Fix the SConsscript, its missing support for %s' % (key))
          Exit(1)

  lib = venv.SConscript('lib/SConscript', variant_dir=pjoin(vdir, 'lib'), duplicate=0, exports='venv')
  targets.append(lib)
  venv['libselene'] = lib[0]

  tests = venv.SConscript('tests/SConscript', variant_dir=pjoin(vdir, 'tests'), duplicate=0, exports='venv')
  for t in tests[0]:
    run = venv.Command(str(t) + ".testrun", t,
      [
      ""+str(t)
      ])
    venv.AlwaysBuild(run)
    test_targets.append(run)
    if ty == "GCOV":
      coverage_test_targets.append(run)

  tools = venv.SConscript('tools/SConscript', variant_dir=pjoin(vdir, 'tools'), duplicate=0, exports='venv')
  targets.append(tools)

  all_targets[variant] = targets

denv = env.Clone()
denv['DOXYGEN'] = 'doxygen'
doxy = denv.Command(env.Dir('#/api-docs'), all_targets.values(),
                   ['rm -rf api-docs',
                    '$DOXYGEN'])

cov = env.Command(env.File('#/build/coverage.txt'), coverage_test_targets,
          ['$PYTHON ./tests/gcovr -b -r lib -o build/coverage.txt',
           'cat build/coverage.txt'])
env.AlwaysBuild(cov)

denv.AlwaysBuild(doxy)
env.Alias('docs', doxy)
env.Alias('test', test_targets)
env.Alias('coverage', cov)
if not env.GetOption('clean'):
  env.Default(all_targets.values())
else:
  env.Default([all_targets.values(), 'test'])
