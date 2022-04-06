/*
 * jCastle language object - english 
 * =================================
 *
 * Copyright (C) 2015-2022 Jacob Lee <letsgolee@naver.com>. All rights reserved.
 */

var jCastle = require('../jCastle');

jCastle.lang.i18n.en = {
	LOCATION:					"Location",
	UNKNOWN:					"An unknown error occurred",
	FATAL_ERROR:				"Fatal error occurred",

	// library

	BIGINTEGER_REQUIRED:		"BigInteger library is required.",	
	UTF8_REQUIRED:				"jCastle.UTF8 library is required. Make sure utils.js is included.",
	INT64_REQUIRED:				"INT64 library is required.",
	UINT32_REQUIRED:			"UINT32 library is required.",
	UINT64_REQUIRED:			"UINT64 library is required.",
	MAC_REQUIRED:				"jCastle.Mac library is required.",
	EC_REQUIRED:				"jCastle.EC library is required.",
	UINT8ARRAY_NOT_SUPPORTED:	"Uint8Array is not supported in this browser",
	RSA_REQUIRED:				"jCastle.RSA library is required.",

	// common

	INVALID_KEYSIZE:			"Invalid key size given.",
	INVALID_ROUNDS:				"Invalid number of rounds.",
	INVALID_COUNTER:			"Invalid number of counter.",
	INVALID_BLOCKSIZE:			"Invalid block size.",
	FAIL_CREATING:				"An error occurred while creating an object.",
	DATA_TOO_SHORT:				"Data too short.",
	DATA_TOO_SHORT_FOR_MODE:    "Data too short for the current mode",
	KEY_NOT_SET:				"Key is not given.",
	OBJ_CANNOT_COPY:			"Unable to copy object! Its type isn't supported.",
	PARAMS_NOT_SET:				"Parameters are not set.",
	INVALID_PARAMS:				"Invalid parameters given.",
	LITE_VERSION_LIMIT:			"The function or method is not supported in the lite version.",
	UNSUPPORTED_FUNC:			"Unsupported function method.",
	MSG_NO_EXIST:				"Cannot find any message to work.",
	UNSUPPORTED_ALGO:			"Unsupported algorithm",

	// mcrypt

	INVALID_IV:					"Invalid size of initial vector(IV) or IV is not set.",
	INVALID_NONCE:				"Invalid size of nonce or nonce is not set,",
	IV_REQUIRED:				"Initial vector(IV) is required.",
	UNSUPPORTED_MODE:			"Unsupported operation mode.",
	ALGORITHM_NOT_SET:			"Algorithm for encryption is not set.",
	UNKNOWN_ALGORITHM:			"Unknown algorithm name. Make sure the name or the required JS file is included.",
	INVALID_PADDING_METHOD:		"Invalid padding name.",
	INVALID_PADDING:			"Invalid padding.",
	INVALID_KEY_PADDING:		"Invalid decryption. might be wrong key or padding method.",
	UNSUPPORTED_PADDING:		"Unsupported padding method given",
	NOT_BLOCK_CIPHER:			"Stream cipher allows only ECB mode",
	INVALID_DIRECTION:			"Unknown direction value."+
									"\nIt should be enc/encrypt/encryption/true or dec/decrypt/decryption/false.",
	INVALID_INPUT_SIZE:			"Invalid input data size",
	GCTR_NOT_GOST:				"GCTR/GOFB mode works only with GOST-28147 algorithm.",
	MODE_INVALID_BLOCKSIZE:		"Invalid block size for the mode.",
	MAC_CHECK_FAIL:				"Mac check failed.",
	MODE_INVALID_TAGSIZE:		"Invalid tag size given.",
	POLY1305_NOT_CHACHA20:		"Poly1305-AEAD requires Chacha20 algorithm.",
	MAC_NOT_FOUND:				"Mac not found",

//	CHACHA20_INVALID_IV:		"Chacha20 requires 96-bit length of IV(12 bytes)",
//	VMPC_INVALID_IV:			"VMPC requires 16 to 64 bytes of IV",
	INVALID_TWEAK_SIZE:			"Invalid tweak size",
	INVALID_CTS_TYPE:			"Invalid CTS type given",

	XTS_DATAUNIT_NOT_GIVEN:		"Data unit serial number is not given.",
	INVALID_DATAUNIT_SERIAL:	"Invalid data unit serial value.",
	INVALID_DATAUNIT_LENGTH:	"Invalid data unit bit length. the bit length must be multiple of 8, and should be bigger than or equal to 128.",
	INVALID_DATAUNIT_LENGTH_2:	"Invalid data unit bit length. the bit length should not bigger than the bit length of the data.",
	INVALID_DATAUNIT_LENGTH_3:  "Invalid data unit bit length. the bit difference should not bigger than 7.",
	DATA_SHORT_FOR_LENGTH:		"Data is smaller than the data unit length.",
	NOT_MULTIPLE_OF_BLOCKSIZE:	"The data size is not multiple of the block size.",

	// mac

	UNSUPPORTED_MAC:			"Unsupported Mac.",
	ALGORITHM_NOT_SET:			"Algorithm not set.",
	GOST28147_REQUIRED:			"Gost28147 algorithm required.",
	DES_REQUIRED:				"DES algorithm required.",
//	VMPCMAC_INVALID_IV:			"VMPC-Mac requires 1 to 768 bytes of IV.",
	
	// digest

	UNSUPPORTED_HASHER:			"Unsupported hash name given.",
	UNKNOWN_FORMAT:				"Unsupported format given.",
	NOT_INITIALIZED:			"Cipher/Hasher is not initialized yet.",
	INVALID_OUTPUT_BITS:		"Output bits should be a multiple of 8.",
	DERIVED_KEY_TOO_LONG:		"Derived key length too long.",
	TRHREEFISH_REQUIRED:		"Threefish algorithm required.",
	OUTPUT_BITS_TOO_SMALL:		"The output bit length is too small",

	// pki

	MSG_TOO_LONG:				"Message too long for PKI.",
	UNSUPPORTED_PKI_FUNC:		"Unsupported PKI function.",
	INVALID_PUBKEY:				"Invalid public key.",
	INVALID_PRIVKEY:			"Invalid private key.",
	INVALID_BIT_LENGTH:			"Invalid bit length given.",
	PUBKEY_NOT_SET:				"Public key not set.",
	PRIVKEY_NOT_SET:			"Private key not set.",
	RSA_INVALID_PUB_EXP:		"Invalid public exponent value for RSA.",
	CIPHERTEXT_TOO_SHORT:		"Ciphertext is too short.",
	HASH_MISMATCH:				"Hash match failed.",
	MALFORMED_DATA:				"Malformed data.",
	INVALID_SALT_LENGTH:		"Invalid salt length.",
	UNSUPPORTED_PKI:			"Unsupported pki name given.",
	PARAMS_NOT_SET:				"Parameters are not set",
	UNSUPPORTED_EC_TYPE:		"Unsupported EC binary type. Only primary type allowed now",
	PKI_NOT_SET:				"PKI is not set",
	INVALID_BITLENGTH:			"illegal bit length.",
	UNFIT_HASH:					"The given hash name is not fit for work.",
	INVALID_BLOCK_TYPE:			"Invalid block type given.",
	INVALID_SALT:				"Invalid salt given.",
	NOT_SEQUENCE:				"The object is not a ASN1 sequence.",

	// ASN1

	INVALID_DATA_LENGTH:		"Malformed data or the data length is not matched.",
	INVALID_TAG_LENGTH:			"Malformed data or the tag length is not right.",
	TOO_BIG_TAG_LENGTH:			"The Tag length value is too big for javascript.",
	UNKNOWN_TAG_TYPE:			"Unknown tag type given.",
	UNKNOWN_TAG_CLASS:			"Unknown tag class given.",
	UNRECOGIZED_TIME:			"Unrecognized time string.",
	INVALID_OID:				"Invalid object id.",
	EOC_REACHED:				"End of content reached.",
	INVALID_ASN1:				"Invalid ASN1 string",
	NEGATIVE_NOT_SUPPORTED:		"Negative integers not supported.",

	// KDF
	UNSUPPORTED_KDF:			"Unsupported key derivation function.",
	UNKNOWN_KDF_TYPE:			"Unknown key derivation function type",
	SALT_NOT_SET:				"Salt value is invalid or not given.",

	// PEM

	INVALID_PEM_FORMAT:			"Invalid PEM format.",
	PEM_NOT_MATCH_WITH_PKI:		"PEM is not matched with the given pki.",
	NO_PKCS5_PEM_SUPPORTED:		"PKCS#5 PEM format not supported.",
	INVALID_ENCRYPTION_METHOD:	"Invalid encryption method used.",
	UNKNOWN_ECDSA_CURVE:		"Unknown ECDSA curve object id or name given.",
	UNKNOWN_ECDSA_FIELD:		"Unknown ECDSA field type given.",
	NO_PASSPHRASE:				"no passphrase is given for encryption/decryption.",
	UNSUPPORTED_MGF:			"Unsupported PKCS#1 MGF function.",
	UNSUPPORTED_ALGO_OID:		"Unsupported algorithm object ID.",
	INCORRECT_PASSPHRASE:		"Incorrect passphrase or malformed data.",
	UNSUPPORTED_PEM_VERSION:	"Unsupported PEM version.",
	UNSUPPORTED_PRF:			"Unsupported PRF hash function or object id.",
	PUBKEY_INFO_FAIL:			"Cannot get publick key information.",
	UNSUPPORTED_PKI_METHOD:		"Unsupported PKI method",
	UNSUPPORTED_PEM_FORMAT:		"Unsupported PEM format.",
	PARAMETERS_DISMATCH:		"Parameters dismatch.",
	INVALID_SEED:				"Seed is invalid or the length is not right.",

	// CERTIFICATE
	SIGNATURE_GET_FAIL:			"Cannot get signature from the given certificate.",
	INVALID_SIGN_ALGO:			"Invalid signature algorithm given.",
	INVALID_HASH_ALGO:			"Invalid signature hash algorithm given.",
	HASH_NAME_MISMATCH:			"Hash name mismatch.",
	INVALID_CERT_INFO:			"Invalid certificate information data given.",
	SIGN_ALGO_MISMATCH:			"Sign algorithm mismatch.",
	NOT_CSR:					"The PEM is not a Certificate Signing Request format.",
	UNSUPPORTED_EXTENSION:		"The certificate contains one or more unsupported extensions.",
	PKI_NOT_MATCH:				"The PKI is not match",
	VERIFICATION_FAIL:			"Verfication process failed",
	PUBKEYINFO_NOT_SET:			"Cannot find public key information.",
	UNSUPPORTED_CERT_TYPE:		"Unsupported certificate type given",
	SERIAL_NOT_GIVEN:			"Serial number is not given",
	UNSUPPORTED_OID:			"Unsupported Object ID",

	// EC
	NOT_DONE_YET:				"Not done yet",
	INVALID_F2M_PARAMS:			"Invalid parameter values for F2m",
	NOT_FIELDELEMENT:			"Field elements are not both instances of ECElement.F2m",
	NEGATIVE_VALUE:				"Got a negative value or zero.",
	NOT_SAME_CURVE:				"Not on the same curve",
	CURVE_NOT_LOADED:			"EC curve not loaded",
	DIFFERENT_REPRESENTATION:	"One of the field elements has incorrect representation.",
	NOT_IMPLEMENTED:			"Not implemented",
	INVALID_POINT_VALUE:		"Invalid point value(infinity or etc)",
	ONE_IS_NULL:				"Exactly one of the field element is null",
	INVALID_ENCODING:			"Invalid point encoding.",
	INVALID_COMPRESSION:		"Invalid point compression.",
	ECDSA_NOT_LOADED:			"ECDSA library is not loaded.",
	X_VALUE_TOO_LARGE:			"x value too large in field element.",

	// KeyWrap
	IV_CHECK_FAIL:				"Initial vector check failed",
	ICV_CHECK_FAIL:				"ICV check failed",
	INVALID_WRAPPED_KEYSIZE:	"Invalid size of the wrapped key",

	// config
	INVALID_CONFIG:				"There are one or more errors in config setting.",

	FILE_API_SUPPORT_FAIL:		"Your browser does not support any file api. A new browser is recommended.",
	NOT_RECOMMENDED:			"The option is not recommended.",
	TOO_SHORT_VALUE:			"The given value length is smaller than the minimum.",
	TOO_LONGER_VALUE:			"The given value length is longer than the maximum.",
	VALUE_NOT_SUPPLIED:			"There are one or more values not supplied.",
	NOT_SECTION_LINK:			"A section link must come after SEQUENCE | SEQ | SET | EXPLICIT | EXP.",
	NO_TAG_TYPE_GIVEN:			"A tag type must be given after EXPLICIT | EXP | IMPLICIT | IMP.",
	UNKNOWN_OID:				"An unknown object id name is given.",

	// pfx
	INVALID_PFX_FORMAT:			"Invalid PFX or P12 format.",
	UNSUPPORTED_PFX_STRUCTURE:	"Unsupported PFX file or string structure.",
	SALT_LENGTH_TOO_SHORT:		"Salt length is too short. minimum is 8.",
	INVALID_ITERATIONS:			"Invalid iterations.",
	NO_SAFEBAG_CONTENT:			"SafeBag content is not given or invalid",
	INVALID_CERT_TYPE:			"SafeBag has invalid certificate type",
	WRONG_PASSPHRASE:			"Unable to decrypt. Maybe wrong passphrase?",
	INVALID_PFX_INFO:			"Invalid PFX Info structure",

	// jwt
	NOT_JWT:					"Not a JSON Web Token(JWT)",
	KEYLEN_TOO_LARGE:			"Keydata length is too large",
	KEY_DERIVATION_FAIL:		"Key derivation failed",
	KEYS_COUNT_NOT_MATCH:		"The count of keys are not match with that of the signatures",

	// oid
	OID_NOT_LOADED:				"Cannot find jCastle.OID object.",

	// cms
	INVALID_DATA_TYPE:			"Invalid data-type given",
	INVALID_CMS_FORMAT:			"Invalid CMS format",
	UNSUPPORTED_CMS_STRUCTURE:	"Unsupported CMS data type or structure",
	INVALID_CMS_STRUCTURE:		"Invalid CMS data structure",
	INVALID_CMS_VERSION:		"Invalid CMS version",
	UNSUPPORTED_ENCRYPTION_ALGO:"Unsupported CMS Key Encryption Algorithm",
	INVALID_CMS_INFO:			"Invalid CMS info structure",
	PKI_ISNT_ECDSA:				"PKI should be ECDSA",
	RECIPIENTS_CERT_NOT_GIVEN:	"Recipient's certificate not given",
	NO_CERT_GIVEN:				"Any certficiate is not given",
	NO_RID:						"RecipientIdentifier value is not given.",
	ORIGINTOR_CERT_NOT_GIVEN:	"Originator's certificate is not given.",
	MODE_NOT_SUPPORT_MAC:		"Algorithm mode does not support MAC",

	// jose
	CONFLICT_EACH_OPTION:		"protectContentOnly and protectHeader cannot be given both.",
	COMPACT_AAD_NOT_ALLOWED:	"compact serialization does not allow any aad."

};
