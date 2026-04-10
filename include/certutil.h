/*
 * Prototypes for our certificate utility functions
 */

/*
 * Returns "true" if successful, CFDataRef return pointers must be released.
 */

extern bool get_certificate_info(CFDataRef, CFDataRef *, CFDataRef *,
				 CFDataRef *);

/*
 * Find common name in an encoded X.509 Name
 *
 * Will always return an allocated string that must be free()d.
 */

extern char *get_common_name(unsigned char *, unsigned int);

/*
 * Decode modulus and public exponent from an encoded RSAPublicKey
 */

extern bool get_pubkey_info(CFDataRef, CFDataRef *, CFDataRef *);

/*
 * Build CKA_EC_PARAMS (DER curve OID) and CKA_EC_POINT (DER OCTET STRING
 * wrapping the X9.62 uncompressed public key point) from the raw external
 * representation of an EC public key and its field-element size in bytes.
 * Returns true on success; caller must release the returned CFDataRefs.
 */

extern bool get_ec_pubkey_info(CFDataRef, size_t, CFDataRef *, CFDataRef *);

/*
 * Extract CKA_EC_PARAMS and CKA_EC_POINT directly from the DER-encoded
 * certificate.  Used as a fallback when SecKeyCopyExternalRepresentation
 * fails for CTK-backed (hardware token) public keys.
 * Returns true on success; caller must release the returned CFDataRefs.
 */

extern bool get_ec_pubkey_from_cert(SecCertificateRef, CFDataRef *, CFDataRef *);

/*
 * Return 'true' if the given certificate is a CA
 */

extern bool is_cert_ca(SecCertificateRef);
