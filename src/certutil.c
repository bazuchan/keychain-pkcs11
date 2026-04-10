/*
 * Utility routines for dealing with various things about certificates
 */

/*
 * We intentionally use the deprecated SecAsn1 APIs here; there is no
 * modern replacement that provides the same low-level DER decoding
 * capabilities we need for parsing certificate fields.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/SecCertificate.h>
#include <Security/SecCertificateOIDs.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecDigestTransform.h>

#include "certutil.h"
#include "keychain_pkcs11.h"
#include "config.h"

/*
 * These are the arrays we need to feed into the Security framework
 * DER decoder so we can extract out the information we need.
 *
 * It turns out that we can't use the Security framework functions like
 * SecCertificateCopyNormalizedSubjectSequence(), because THOSE return
 * "normalized" DER sequence (hence the name) which are really designed
 * for searching using SecItemCopyMatching; specifically, the ASCII
 * characters in those DER sequences have been converted to upper case.
 * And as it turns out, that messes up some applications (Firefox) because
 * they look up the certificate public and private key objects based on
 * the subject from the certificate, AND since the normalized subject
 * doesn't match the ACTUAL subject, the certificate will never be selected
 * as valid client certificates.
 *
 * I spun my wheels for a while on the problem; I thought about parsing the
 * ASN.1 sequence by hand (ugh) or constructing the encoded name based
 * on info returned by SecCertificateCopyValues (that doesn't preserve the
 * string information).  But then I realized that the Security framework
 * decoder routines could stash the DER encoded Name in a buffer, and
 * that seemed the more robust solution.  It was just a pain to figure out
 * how the DER routines work.
 */

/*
 * Our ASN.1 template array; each entry in the template corresponds to
 * another field in the ASN.1 structure.
 *
 * Since all we care about is the issuer and subject, we skip the actual
 * decoding of most fields with SEC_ASN1_SKIP.  The version is a bit weird,
 * so we have to specify the explict tag and use kSecAsn1SkipTemplate.
 *
 * Using SEC_ASN1_SAVE saves the raw DER bytes into a SecAsn1Item structure.
 * But because of the way the ASN.1 decoder works, you need to still run it
 * through the parser, so you need the SEC_ASN1_SKIP after SEC_ASN1_SAVE.
 * SEC_ASN1_SKIP_REST terminates the decoding immediately.
 *
 * The fields of SecAsn1Template are, in order:
 *
 * kind		- The tag of this field.  We use SEQUENCE to indicate the start
 *		  of a new sequence, SKIP to skip over this field (this will
 *		  prevent any data from being decoded/saved) and SAVE (which
 *		  saves the raw DER bytes without decoding).
 * offset	- Offset into the passed-in structure to store this data.
 * sub		- A sub-template for nested structures; we don't use this
 *		  (except for the version, because it was the easiest way
 *		  to make it work).
 * size		- For some cases (SEC_ASN1_GROUP, SEC_ASN1_INLINE, and a few
 *		  others) the ASN.1 decoder can allocate a sub-structure for
 *		  you; this is how big it would be.
 *
 * We don't do much verification of the fields of the certificate, but I
 * figure that the Security framework probably wouldn't have it available
 * if it was unparseable.
 */

struct certinfo {
	SecAsn1Item	serialnumber;	/* Certificate serial number */
	SecAsn1Item	issuer;		/* Certificate issuer */
	SecAsn1Item	subject;	/* Certificate subject */
};

/*
 * This is where the magic happens!  Basically a description of an X.509
 * certificate, with most of the fields skipped
 */

static const SecAsn1Template cert_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, 0 },	/* Certificate sequence */
	{ SEC_ASN1_SEQUENCE, 0, NULL, 0 },	/* TBCertificate sequence */
	{ SEC_ASN1_EXPLICIT | SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 0, 0, kSecAsn1SkipTemplate, 0 },
					/* Version (explicit tag 0) */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, serialnumber), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* CertificateSerialNumber */
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* AlgorithmIdentifier */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, issuer), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Issuer */
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Validity */
	{ SEC_ASN1_SAVE, offsetof(struct certinfo, subject), NULL, 0 },
	{ SEC_ASN1_SKIP, 0, NULL, 0 },		/* Subject */
	{ SEC_ASN1_SKIP_REST, 0, NULL, 0 },	/* Stop decoding here */
	{ 0, 0, NULL, 0 }		/* Dunno if needed, but just in case */
};

/*
 * More code to extract out the common name from an DER-encoded Name
 * field; we need this for dumping out things like a CKA_ISSUER when it
 * is passed down in FindObject search parameters
 *
 * A Name is a (ignoring first CHOICE, which is invisible to us):
 *
 * SEQUENCE OF RelativeDistinguisedNames
 *
 * RelativeDistinguishedNames are a SET OF ATVs (Attribute Type and Values)
 *
 * ATVs are a SEQUENCE { OID, VALUE } where VALUE is a CHOICE of String types.
 */

struct atv {
	SecAsn1Oid	oid;	/* AttributeType */
	SecAsn1Item	value;	/* AttributeValue */
};

struct rdn {
	struct atv	**atvs;	/* AttributeTypeAndValue */
};

struct name {
	struct rdn	**rdns;	/* RelativeDistinguishedName */
};

static const SecAsn1Template atv_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct atv) },
	{ SEC_ASN1_OBJECT_ID, offsetof(struct atv, oid), NULL, 0 },
	{ SEC_ASN1_ANY_CONTENTS, offsetof(struct atv, value), NULL, 0 },
	{ 0, 0, NULL, 0 },
};

static const SecAsn1Template rdn_template[] = {
	{ SEC_ASN1_SET_OF, offsetof(struct rdn, atvs), atv_template,
							sizeof(struct rdn) },
};

/*
 * We probably don't need the sizeof(struct name) at the end of this one,
 * but we included it in case we ever nest it in something else
 */

static const SecAsn1Template name_template[] = {
	{ SEC_ASN1_SEQUENCE_OF, offsetof(struct name, rdns), rdn_template,
						sizeof(struct name) },
};

/*
 * The encoded OID for a commonName
 */

static const unsigned char cn_oid[] = { 0x55, 0x04, 0x03 };	/* 2.5.4.3 */

/*
 * A decoding template to extract the modulus and public exponent from
 * RSAPublicKey encoded data.  Again, we don't need the size in the first
 * template marking the sequence, but we include it just in case we embed
 * that in something else later.
 *
 * A RSAPublicKey is a SEQUENCE of
 *
 * INTEGER (modulus)
 * INTEGER (publicExponent)
 */

struct rsa_pubkey {
	SecAsn1Item	modulus;
	SecAsn1Item	public_exponent;
};

static const SecAsn1Template rsapubkey_template[] = {
	{ SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct rsa_pubkey) },
	{ SEC_ASN1_INTEGER, offsetof(struct rsa_pubkey, modulus), NULL, 0 },
	{ SEC_ASN1_INTEGER, offsetof(struct rsa_pubkey, public_exponent),
								NULL, 0 },
	{ 0, 0, NULL, 0 },
};

/*
 * Extract out the DER-encoded certificate subject
 */

bool
get_certificate_info(CFDataRef certdata, CFDataRef *serialnumber,
		     CFDataRef *issuer, CFDataRef *subject)
{
	SecAsn1CoderRef coder;
	struct certinfo cinfo;
	OSStatus ret;

	/*
	 * We have to allocate a SecAsn1CoderRef before we call the decoder
	 * function; when we free it, it will release all of the allocated
	 * memory from the ASN.1 decoder, so make sure we copied everything.
	 */

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		return false;
	}

	memset(&cinfo, 0, sizeof(cinfo));

	/*
	 * Perform the actual decoding, based on our template.  The
	 * DER bytes should end up in our cinfo structure.
	 */

	ret = SecAsn1Decode(coder, CFDataGetBytePtr(certdata),
			    CFDataGetLength(certdata), cert_template, &cinfo);

	if (ret) {
		SecAsn1CoderRelease(coder);
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		return false;
	}

	/*
	 * Looks like it all worked!  Return those in CFData structures
	 */

	*serialnumber = CFDataCreate(kCFAllocatorDefault,
				     cinfo.serialnumber.Data,
				     cinfo.serialnumber.Length);
	*issuer = CFDataCreate(kCFAllocatorDefault, cinfo.issuer.Data,
			       cinfo.issuer.Length);
	*subject = CFDataCreate(kCFAllocatorDefault, cinfo.subject.Data,
				cinfo.subject.Length);

	SecAsn1CoderRelease(coder);

	return true;
}

/*
 * Find the commonName out of a full DER-encoded Name
 */

char *
get_common_name(unsigned char *name, unsigned int namelen)
{
	SecAsn1CoderRef coder = NULL;
	struct name cname;
	OSStatus ret;
	int i, j;
	char *str;

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		str = strdup("Unknown Name");
		goto out;
	}

	memset(&cname, 0, sizeof(cname));

	ret = SecAsn1Decode(coder, name, namelen, name_template, &cname);

	if (ret) {
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		str = strdup("Unparsable Name");
		goto out;
	}

	/*
	 * Look through each rdns/atv for the first common name we find
	 */

	for (i = 0; cname.rdns[i] != NULL; i++) {
		struct rdn *rdn = cname.rdns[i];

		for (j = 0; rdn->atvs[j] != NULL; j++) {
			struct atv *atv = rdn->atvs[j];

			if (atv->oid.Length == sizeof(cn_oid) &&
			    memcmp(atv->oid.Data, cn_oid,
				   sizeof(cn_oid)) == 0) {
				/*
				 * A match!
				 */

				size_t len = atv->value.Length;

				str = malloc(len + 1);

				strncpy(str, (char *) atv->value.Data, len);
				str[len] = '\0';
				goto out;
			}
		}
	}

	str = strdup("No Common Name Found");

out:
	if (coder)
		SecAsn1CoderRelease(coder);

	return str;
}

/*
 * Extract out the modulus and public exponent from a RSAPublicKey
 */

bool
get_pubkey_info(CFDataRef pubkeydata, CFDataRef *modulus, CFDataRef *exponent)
{
	SecAsn1CoderRef coder = NULL;
	struct rsa_pubkey pubkey;
	OSStatus ret;

	ret = SecAsn1CoderCreate(&coder);

	if (ret) {
		LOG_SEC_ERR("SecAsn1CreateCoder failed: %{public}@", ret);
		return false;
	}

	memset(&pubkey, 0, sizeof(pubkey));

	ret = SecAsn1Decode(coder, CFDataGetBytePtr(pubkeydata),
			    CFDataGetLength(pubkeydata),
			    rsapubkey_template, &pubkey);

	if (ret) {
		SecAsn1CoderRelease(coder);
		LOG_SEC_ERR("SecAsn1Decode failed: %{public}@", ret);
		return false;
	}

	/*
	 * Looks like it all worked!  Return those in CFData structures
	 */

	*modulus = CFDataCreate(kCFAllocatorDefault, pubkey.modulus.Data,
				pubkey.modulus.Length);

	*exponent = CFDataCreate(kCFAllocatorDefault,
				 pubkey.public_exponent.Data,
				 pubkey.public_exponent.Length);

	SecAsn1CoderRelease(coder);

	return true;
}

/*
 * Minimal DER helpers used by get_ec_pubkey_from_cert().
 *
 * der_skip_tlv: skip one complete TLV, return pointer to the next TLV.
 * der_enter_tlv: verify tag, return pointer to the VALUE, set *lenp.
 * Both return NULL on any error.
 */

static const uint8_t *
der_skip_tlv(const uint8_t *p, const uint8_t *end)
{
	if (p >= end) return NULL;
	p++;			/* tag */
	if (p >= end) return NULL;
	size_t len;
	if (*p & 0x80) {
		int nb = *p++ & 0x7f;
		if (nb == 0 || nb > 4 || p + nb > end) return NULL;
		len = 0;
		for (int i = 0; i < nb; i++) len = (len << 8) | *p++;
	} else {
		len = *p++;
	}
	if (p + len > end) return NULL;
	return p + len;
}

static const uint8_t *
der_enter_tlv(const uint8_t *p, const uint8_t *end, uint8_t tag, size_t *lenp)
{
	if (p >= end || *p != tag) return NULL;
	p++;
	if (p >= end) return NULL;
	size_t len;
	if (*p & 0x80) {
		int nb = *p++ & 0x7f;
		if (nb == 0 || nb > 4 || p + nb > end) return NULL;
		len = 0;
		for (int i = 0; i < nb; i++) len = (len << 8) | *p++;
	} else {
		len = *p++;
	}
	if (p + len > end) return NULL;
	if (lenp) *lenp = len;
	return p;
}

/*
 * Extract CKA_EC_PARAMS and CKA_EC_POINT directly from the DER-encoded
 * certificate by walking the SubjectPublicKeyInfo field.
 *
 * Used as a fallback when SecKeyCopyExternalRepresentation fails for
 * CTK-backed (hardware token) public keys.
 *
 * The SubjectPublicKeyInfo for an EC key looks like:
 *
 *   SEQUENCE {
 *     SEQUENCE {                          -- AlgorithmIdentifier
 *       OID 1.2.840.10045.2.1            -- id-ecPublicKey
 *       OID <curve>                       -- named curve (CKA_EC_PARAMS)
 *     }
 *     BIT STRING { 00 04 X Y... }        -- uncompressed point
 *   }
 *
 * Returns true on success; caller must CFRelease the returned CFDataRefs.
 */

bool
get_ec_pubkey_from_cert(SecCertificateRef cert, CFDataRef *ec_params,
			CFDataRef *ec_point)
{
	CFDataRef certdata = SecCertificateCopyData(cert);
	if (!certdata) {
		os_log_error(logsys, "get_ec_pubkey_from_cert: "
			     "SecCertificateCopyData failed");
		return false;
	}

	const uint8_t *p   = CFDataGetBytePtr(certdata);
	const uint8_t *end = p + CFDataGetLength(certdata);
	size_t len;
	bool result = false;
	uint8_t *der = NULL;

	/* Enter Certificate SEQUENCE */
	p = der_enter_tlv(p, end, 0x30, &len);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed at Certificate SEQUENCE"); goto out; }
	end = p + len;

	/* Enter TBSCertificate SEQUENCE */
	p = der_enter_tlv(p, end, 0x30, &len);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed at TBSCertificate SEQUENCE"); goto out; }
	const uint8_t *tbs_end = p + len;

	/* Skip optional version [0] EXPLICIT */
	if (p < tbs_end && *p == 0xA0) {
		p = der_skip_tlv(p, tbs_end);
		if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
			  "failed skipping version"); goto out; }
	}

	/* Skip serialNumber, signature AlgorithmIdentifier, issuer, validity,
	 * subject — five consecutive TLVs. */
	for (int i = 0; i < 5; i++) {
		p = der_skip_tlv(p, tbs_end);
		if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
			  "failed skipping TLV %d", i); goto out; }
	}

	/* Now at SubjectPublicKeyInfo SEQUENCE */
	p = der_enter_tlv(p, tbs_end, 0x30, &len);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed at SPKI SEQUENCE (tag=0x%02x)", p ? *p : 0);
		  goto out; }
	const uint8_t *spki_end = p + len;

	/* Enter AlgorithmIdentifier SEQUENCE */
	p = der_enter_tlv(p, spki_end, 0x30, &len);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed at AlgorithmIdentifier"); goto out; }
	const uint8_t *alg_end = p + len;	/* also = start of BIT STRING TLV */

	/* Skip algorithm OID (id-ecPublicKey 1.2.840.10045.2.1) */
	p = der_skip_tlv(p, alg_end);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed skipping algorithm OID"); goto out; }

	/* parameters = curve OID TLV; we want the full TLV for CKA_EC_PARAMS */
	if (p >= alg_end || *p != 0x06) {
		os_log_error(logsys, "get_ec_pubkey_from_cert: "
			     "expected curve OID (0x06) but got 0x%02x",
			     (p < alg_end) ? *p : 0xff);
		goto out;
	}
	const uint8_t *curve_oid_tlv = p;
	size_t oid_val_len;
	p = der_enter_tlv(p, alg_end, 0x06, &oid_val_len);
	if (!p) { os_log_error(logsys, "get_ec_pubkey_from_cert: "
		  "failed entering curve OID"); goto out; }
	/* full OID TLV = curve_oid_tlv .. (p + oid_val_len) */
	*ec_params = CFDataCreate(kCFAllocatorDefault, curve_oid_tlv,
				  (p + oid_val_len) - curve_oid_tlv);
	if (!*ec_params) goto out;

	/* BIT STRING starts at alg_end */
	p = der_enter_tlv(alg_end, spki_end, 0x03, &len);
	if (!p || len < 2) {
		os_log_error(logsys, "get_ec_pubkey_from_cert: "
			     "failed at BIT STRING");
		goto rel_params;
	}

	/* First byte of BIT STRING value = unused-bits count; must be 0 */
	if (*p != 0x00) {
		os_log_error(logsys, "get_ec_pubkey_from_cert: "
			     "unexpected unused-bits byte 0x%02x", *p);
		goto rel_params;
	}
	p++;
	len--;

	/* Remaining bytes = X9.62 uncompressed point: 04 X Y ... */
	if (len < 2 || *p != 0x04) {
		os_log_error(logsys, "get_ec_pubkey_from_cert: "
			     "expected uncompressed point (0x04) but got "
			     "0x%02x len=%ld", *p, (long) len);
		goto rel_params;
	}

	/* Wrap in DER OCTET STRING for CKA_EC_POINT */
	{
		size_t der_len;
		if (len < 128) {
			der_len = 2 + len;
			der = malloc(der_len);
			if (!der) goto rel_params;
			der[0] = 0x04;
			der[1] = (uint8_t) len;
			memcpy(der + 2, p, len);
		} else {
			der_len = 3 + len;
			der = malloc(der_len);
			if (!der) goto rel_params;
			der[0] = 0x04;
			der[1] = 0x81;
			der[2] = (uint8_t) len;
			memcpy(der + 3, p, len);
		}

		*ec_point = CFDataCreate(kCFAllocatorDefault, der, der_len);
		free(der);
		der = NULL;

		if (!*ec_point) goto rel_params;
	}

	os_log_error(logsys, "get_ec_pubkey_from_cert: success, "
		     "point len=%ld", (long) len);
	result = true;
	goto out;

rel_params:
	CFRelease(*ec_params);
	*ec_params = NULL;

out:
	CFRelease(certdata);
	return result;
}

/*
 * Build CKA_EC_PARAMS and CKA_EC_POINT for an EC public key.
 *
 * Apple's SecKeyCopyExternalRepresentation() for EC public keys returns the
 * raw uncompressed X9.62 point: 0x04 || X || Y.  blocksize is the value
 * returned by SecKeyGetBlockSize() for the key (the field element size in
 * bytes: 32 for P-256, 48 for P-384, 66 for P-521).
 *
 * CKA_EC_PARAMS is set to the DER-encoded OID of the named curve.
 * CKA_EC_POINT is set to a DER OCTET STRING wrapping the X9.62 point.
 */

bool
get_ec_pubkey_info(CFDataRef pubkeydata, size_t blocksize,
		   CFDataRef *ec_params, CFDataRef *ec_point)
{
	/* DER-encoded OIDs for NIST named curves */
	static const unsigned char p256_oid[] = {	/* 1.2.840.10045.3.1.7 */
		0x06, 0x08,
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
	};
	static const unsigned char p384_oid[] = {	/* 1.3.132.0.34 */
		0x06, 0x05,
		0x2B, 0x81, 0x04, 0x00, 0x22
	};
	static const unsigned char p521_oid[] = {	/* 1.3.132.0.35 */
		0x06, 0x05,
		0x2B, 0x81, 0x04, 0x00, 0x23
	};

	const unsigned char *oid;
	size_t oid_len;
	const uint8_t *point;
	size_t point_len;
	uint8_t *der;
	size_t der_len;

	/*
	 * Detect the curve from the external representation data length.
	 * SecKeyCopyExternalRepresentation returns the X9.62 uncompressed
	 * point: 04 || X || Y.  Lengths: P-256=65, P-384=97, P-521=133.
	 *
	 * We prefer data-length detection over blocksize because for CTK
	 * (smartcard) keys SecKeyGetBlockSize may return the max DER
	 * signature size rather than the field-element size.
	 */
	point_len = (size_t) CFDataGetLength(pubkeydata);

	switch (point_len) {
	case 65:	/* P-256: 1 + 2*32 */
		oid = p256_oid;
		oid_len = sizeof(p256_oid);
		break;
	case 97:	/* P-384: 1 + 2*48 */
		oid = p384_oid;
		oid_len = sizeof(p384_oid);
		break;
	case 133:	/* P-521: 1 + 2*66 */
		oid = p521_oid;
		oid_len = sizeof(p521_oid);
		break;
	default:
		/*
		 * Fall back to blocksize-based detection for non-standard
		 * representations.
		 */
		switch (blocksize) {
		case 32:
			oid = p256_oid;
			oid_len = sizeof(p256_oid);
			break;
		case 48:
			oid = p384_oid;
			oid_len = sizeof(p384_oid);
			break;
		case 66:
			oid = p521_oid;
			oid_len = sizeof(p521_oid);
			break;
		default:
			return false;
		}
		break;
	}

	*ec_params = CFDataCreate(kCFAllocatorDefault, oid, oid_len);
	if (! *ec_params)
		return false;

	/* Wrap the raw X9.62 point in a DER OCTET STRING (tag 0x04) */
	point = CFDataGetBytePtr(pubkeydata);
	point_len = (size_t) CFDataGetLength(pubkeydata);

	if (point_len < 128) {
		der_len = 2 + point_len;
		der = malloc(der_len);
		if (! der) {
			CFRelease(*ec_params);
			*ec_params = NULL;
			return false;
		}
		der[0] = 0x04;			/* OCTET STRING tag */
		der[1] = (uint8_t) point_len;
		memcpy(der + 2, point, point_len);
	} else {
		der_len = 3 + point_len;
		der = malloc(der_len);
		if (! der) {
			CFRelease(*ec_params);
			*ec_params = NULL;
			return false;
		}
		der[0] = 0x04;			/* OCTET STRING tag */
		der[1] = 0x81;			/* long-form length, 1 byte */
		der[2] = (uint8_t) point_len;
		memcpy(der + 3, point, point_len);
	}

	*ec_point = CFDataCreate(kCFAllocatorDefault, der, der_len);
	free(der);

	if (! *ec_point) {
		CFRelease(*ec_params);
		*ec_params = NULL;
		return false;
	}

	return true;
}

/*
 * Return 'true' if the given certificate is a CA.
 *
 * The following things have to be true for a cert to be a CA:
 *
 * - It has to have a Basic Constraints section (OID - 2.5.29.19)
 * - It has to have the cA boolean field set to TRUE
 *
 * Because right now we are only dealing with SecCertificateRefs, we
 * can get away with not having to parse the ASN.1 ourselves.  Just call
 * SecCertificateCopyValues() with the correct OIDs.
 */

bool
is_cert_ca(SecCertificateRef cert)
{
	CFDictionaryRef mdict = NULL, valdict;
	CFArrayRef query = NULL, valarray;
	CFErrorRef err = NULL;
	CFTypeRef result;
	bool is_ca = false;
	CFIndex i;

	/*
	 * Create a (single) array with our Basic Constraints OID.
	 */

	const void *keys[] = {
		kSecOIDBasicConstraints,
	};

	query = CFArrayCreate(kCFAllocatorDefault, keys,
			      sizeof(keys)/sizeof(keys[0]),
			      &kCFTypeArrayCallBacks);

	if (! query) {
		os_log_debug(logsys, "Unable to create cert query array");
		goto out;
	}

	mdict = SecCertificateCopyValues(cert, query, &err);

	/*
	 * The dictionary should always be returned, even if it is empty;
	 * report an error if it is not.
	 */

	if (! mdict) {
		os_log_debug(logsys, "SecCertificateCopyValues failed: "
			     "%{public}@", err);
		goto out;
	}

	/*
	 * Make sure that our key exists in the dictionary; if it does
	 * not we can exit early (NULL is not valid for this entry).
	 */

	valdict = CFDictionaryGetValue(mdict, kSecOIDBasicConstraints);

	if (! valdict)
		goto out;

	/*
	 * The TYPE should be a "section" (which should mean an array).
	 * Make sure that is correct.
	 */

	result = CFDictionaryGetValue(valdict, kSecPropertyKeyType);

	if (! result) {
		os_log_debug(logsys, "Unable to find kSecPropertyKeyType "
			     "in certificate dictionary");
		goto out;
	}

	if (! CFEqual(result, kSecPropertyTypeSection)) {
		os_log_debug(logsys, "Expected a value of TypeSection, but "
			     "instead got: %{public}@", result);
		goto out;
	}

	valarray = CFDictionaryGetValue(valdict, kSecPropertyKeyValue);

	if (! valarray) {
		os_log_debug(logsys, "Unable to retrieve value for "
			     "Basic Constraints extenstion");
		goto out;
	}

	if (CFGetTypeID(valarray) != CFArrayGetTypeID()) {
		logtype("Was expecting a CFArray for Basic Constraints, "
			"but got", valarray);
		goto out;
	}

	/*
	 * Iterate through the list of array elements until we hit one
	 * that has the label, "Certificate Authority".
	 */

	for (i = 0; i < CFArrayGetCount(valarray); i++) {
		valdict = CFArrayGetValueAtIndex(valarray, i);

		if (CFGetTypeID(valdict) != CFDictionaryGetTypeID()) {
			logtype("Was expecting CFDict for Basic Constraints "
				"element, but got", valdict);
			continue;
		}

		result = CFDictionaryGetValue(valdict, kSecPropertyKeyLabel);

		if (! result) {
			os_log_debug(logsys, "Cannot find label for Basic "
				     "Constraints array element");
			continue;
		}

		if (CFStringCompare(result, CFSTR("Certificate Authority"),
				    kCFCompareCaseInsensitive) ==
							kCFCompareEqualTo) {
			/*
			 * This is the cA Boolean field.  I guess the way
			 * this works is that if it is true, it is set to
			 * the string "Yes" ... so I guess we'll go with that?
			 * At least do a case insensitive match.
			 */

			result = CFDictionaryGetValue(valdict,
						      kSecPropertyKeyValue);

			if (! result) {
				os_log_debug(logsys, "Unable to find value "
					     "for cA boolean");
				goto out;
			}

			if (CFGetTypeID(result) != CFStringGetTypeID()) {
				logtype("Expected a CFString, but got", result);
				goto out;
			}

			if (CFStringCompare(result, CFSTR("Yes"),
					    kCFCompareCaseInsensitive) ==
							kCFCompareEqualTo) {
				is_ca = true;
			}

			break;
		}
	}

out:
	if (query)
		CFRelease(query);
	if (mdict)
		CFRelease(mdict);
	if (err)
		CFRelease(err);

	return is_ca;
}

#pragma clang diagnostic pop
