#pragma once

//! @file
//!
//! Copyright (c) Memfault, Inc.
//! See License.txt for details
//!

#include <stddef.h>

typedef enum {
  // arbitrarily high base so as not to conflict with id used for other certs in use by the system
  kMemfaultRootCert_Base = 1000,
  kMemfaultRootCert_DstCaX3,
  kMemfaultRootCert_DigicertRootCa,
  kMemfaultRootCert_DigicertRootG2,
  kMemfaultRootCert_CyberTrustRoot,
  kMemfaultRootCert_AmazonRootCa1,
  // Must be last, used to track number of root certs in use
  kMemfaultRootCert_MaxIndex,
} eMemfaultRootCert;

//! Adds specified certificate to cert store
//!
//! @param cert_id Identifier to be used for certificate
//! @param cert PEM encoded cert
//! @param cert_length Length of PEM certificate
//!
//! @return 0 on success or error code
int memfault_root_cert_storage_add(eMemfaultRootCert cert_id, const char *cert, size_t cert_length);
