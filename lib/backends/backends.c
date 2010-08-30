/*
 * Licensed to Selene developers ('Selene') under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * Selene licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sln_backends.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

static selene_error_t*
sln_openssl_initilize()
{
  /* TODO: is this correct? */
  // CRYPTO_malloc_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();

  /* TOOD: Crytpo Mutex init? */

  return SELENE_SUCCESS;
}

static void
sln_openssl_terminate()
{
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
}

selene_error_t*
sln_backend_initialize()
{
#if defined(WANT_OPENSSL_THREADED)
  return sln_openssl_initilize();
#endif
  return SELENE_SUCCESS;
}

void
sln_backend_terminate()
{
#if defined(WANT_OPENSSL_THREADED)
  sln_openssl_terminate();
#endif
}

selene_error_t*
sln_backend_create(selene_t *s)
{
#if defined(WANT_OPENSSL_THREADED)
  s->backend.name = "openssl_threaded";
  s->backend.init = sln_openssl_threaded_init;
  s->backend.destroy = sln_openssl_threaded_destroy;
#else
  return selene_error_createf(SELENE_EINVAL, "no backend available");
#endif
  return SELENE_SUCCESS;
}
