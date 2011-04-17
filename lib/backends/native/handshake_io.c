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

#include "sln_brigades.h"
#include "native.h"
#include <time.h>
#include <string.h>

/* RFC 4346, Section 7.4. Handshake Protocol
 *
 * enum {
 *          hello_request(0), client_hello(1), server_hello(2),
 *          certificate(11), server_key_exchange (12),
 *          certificate_request(13), server_hello_done(14),
 *          certificate_verify(15), client_key_exchange(16),
 *          finished(20), (255)
 *      } HandshakeType;
 */

selene_error_t*
sln_native_io_handshake_client_hello(selene_t *s, sln_native_baton_t *baton)
{
  sln_native_msg_client_hello_t ch;
  sln_native_msg_tls_t tls;
  sln_bucket_t *btls = NULL;
  sln_bucket_t *bhs = NULL;

  ch.version_major = 3;
  ch.version_minor = 2;
  ch.utc_unix_time = time(NULL);
  memset(&ch.random_bytes[0], 0xFF, sizeof(ch.random_bytes));
  ch.session_id_len = 0;
  ch.ciphers = &s->conf->ciphers;
  ch.server_name = NULL;
  ch.have_npn = 0;
  ch.have_ocsp_stapling = 0;
  SELENE_ERR(sln_native_msg_handshake_client_hello_to_bucket(&ch, &bhs));

  slnDbg(s, "client hello bucket= %p", bhs);

  tls.content_type = SLN_NATIVE_CONTENT_TYPE_HANDSHAKE;
  tls.version_major = 3;
  tls.version_minor = 2;
  tls.length = bhs->size;

  SELENE_ERR(sln_native_msg_tls_to_bucket(&tls, &btls));


  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bhs);

  return SELENE_SUCCESS;
}
