#include "sln_ring.h"
#include "sln_buckets.h"
#include "sln_brigades.h"
#include "sln_tls.h"

selene_error_t* 
sln_tls_write(selene_t *s, sln_tls_record_t *r)
{
  sln_bucket_t *e = NULL;
  unsigned char header[5];

  /* setup the content type */
  switch (r->content_type) {
  case SLN_TLS_CTYPE_CHANGE_CIPHER_SPEC:
    header[0] = SLN_TLS_RECORD_CHANGE_CIPHER_SPEC;
    break;
  case SLN_TLS_CTYPE_ALERT:
    header[0] = SLN_TLS_RECORD_ALERT;
    break;
  case SLN_TLS_CTYPE_HANDSHAKE:
    header[0] = SLN_TLS_RECORD_HANDSHAKE;
    break;
  case SLN_TLS_CTYPE_APPLICTION_DATA:
    header[0] = SLN_TLS_RECORD_APPLICATION_DATA;
    break;
  case SLN_TLS_CTYPE__UNUSED0:
  case SLN_TLS_CTYPE__MAX:
  default:
    return selene_error_create(SELENE_EINVAL, "invalid switch paramter");
  }

  /* setup the TLS version
   *   3,0 == sslv3
   *   3,1 == tls 1.0
   *   3,2 == tls 1.1
   *   3,3 == tls 1.2
   */
  switch (r->version) {
  case SLN_TLS_VERSION_SSL30:
    header[1] = 3;
    header[2] = 0;
    break;
  case SLN_TLS_VERSION_TLS10:
    header[1] = 3;
    header[2] = 1;
    break;
  case SLN_TLS_VERSION_TLS11:
    header[1] = 3;
    header[2] = 2;
    break;
  case SLN_TLS_VERSION_TLS12:
    header[1] = 3;
    header[2] = 3;
    break;
  case SLN_TLS_VERSION__UNUSED0:
  case SLN_TLS_VERSION__MAX:
  default:
    return selene_error_create(SELENE_EINVAL, "invalid switch paramter");
  }

  /* encode the packet length */
  header[3] = (unsigned char)( r->protocol_size >> 8 );
  header[4] = (unsigned char)( r->protocol_size );

  /* setup the protocol message */
  SELENE_ERR(sln_bucket_create_copy_bytes(&e, (char*)header, 5));
  SLN_BRIGADE_INSERT_TAIL(s->bb_out_enc, e);
  SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_ENC));

  SELENE_ERR(sln_bucket_create_copy_bytes(&e, r->protocol_data, r->protocol_size));
  SLN_BRIGADE_INSERT_TAIL(s->bb_out_enc, e);
  SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_ENC));

  return SELENE_SUCCESS;
}
