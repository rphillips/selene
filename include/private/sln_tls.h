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

#ifndef _sln_tls_h_
#define _sln_tls_h_

#include "selene_error.h"
#include "sln_types.h"

#define SLN_TLS_RECORD_MAX_LENGTH         (16384)
#define SLN_TLS_RECORD_CHANGE_CIPHER_SPEC (0x14)
#define SLN_TLS_RECORD_ALERT              (0x15)
#define SLN_TLS_RECORD_HANDSHAKE          (0x16)
#define SLN_TLS_RECORD_APPLICATION_DATA   (0x17)

selene_error_t* sln_tls_write(selene_t *s, sln_tls_record_t *r);

#endif
