/*
 * jCAstle language object - korean 
 * ================================
 *
 * Copyright (C) 2015-2022 Jacob Lee <letsgolee@naver.com>. All rights reserved.
 */


var jCastle = require('../jCastle');

/*
사용하려면 jCastle.lang._default_language 값을 'ko'로 설정하거나
jCastle.lang.set('ko')를 실행하세요.
*/

jCastle.lang.i18n.ko = {
	LOCATION:					"위치",
	UNKNOWN:					"알지못하는 에러가 발생했습니다.",

	// library

	BIGINTEGER_REQUIRED:		"BigInteger 라이브러리가 필요합니다.",	
	UTF8_REQUIRED:				"jCastle.UTF8 라이브러리가 필요합니다. utils.js가 로딩되었는지 확인하세요.",
	INT64_REQUIRED:				"INT64 라이브러리가 필요합니다.",
	UINT32_REQUIRED:			"UINT32 라이브러리가 필요합니다.",
	UINT64_REQUIRED:			"UINT64 라이브러리가 필요합니다.",
	MAC_REQUIRED:				"jCastle.Mac 라이브러리가 필요합니다.",
	EC_REQUIRED:				"jCastle.EC 라이브러리가 필요합니다.",
	UINT8ARRAY_NOT_SUPPORTED:	"이 브라우져에서는 Uint8Array가 지원되지 않습니다. 최신 브라우져를 사용하세요.",
	RSA_REQUIRED:				"jCastle.RSA 라이브러리가 필요합니다.",

	// common

	INVALID_KEYSIZE:			"유효하지 않은 키 사이즈입니다.",
	INVALID_ROUNDS:				"유효하지 않은 라운드 값입니다.",
	INVALID_COUNTER:			"유효하지 않은 카운터 값입니다.",
	INVALID_BLOCKSIZE:			"유효하지 않은 블럭 사이즈입니다.",
	FAIL_CREATING:				"오브젝트를 생성하는 과정에서 에러가 발생했습니다.",
	DATA_TOO_SHORT:				"주어진 데이터 사이즈가 너무 짧습니다.",
	DATA_TOO_SHORT_FOR_MODE:    "모드 설정에 비추어 주어진 데이터 사이즈가 짧습니다.",
	KEY_NOT_SET:				"키가 주어지지 않았습니다.",
	OBJ_CANNOT_COPY:			"오브젝트 복사에 실패했습니다. 타입이 지원되지 않습니다.",
	PARAMS_NOT_SET:				"파라미터가 설정되지 않았습니다.",
	INVALID_PARAMS:				"유효하지 않은 파라미터 값입니다.",
	LITE_VERSION_LIMIT:			"해당하는 함수나 메소드는 라이트 버젼에서는 지원되지 않습니다.",
	UNSUPPORTED_FUNC:			"지원되지 아니하는 함수 혹은 메소드입니다.",
	MSG_NO_EXIST:				"메시지가 주어지지 않았습니다.",
	UNSUPPORTED_ALGO:			"지원하지 않는 알고리즘입니다.",

	// mcrypt

	INVALID_IV:					"유효하지 않은 IV값이거나 값이 주어지지 않았습니다.",
	INVALID_NONCE:				"유효하지 않은 Nonce값이거나 값이 주어지지 않았습니다.",
	IV_REQUIRED:				"IV가 필요합니다.",
	UNSUPPORTED_MODE:			"지원되지 않는 모드 입니다.",
	ALGORITHM_NOT_SET:			"알고리즘이 설정되지 않았습니다.",
	UNKNOWN_ALGORITHM:			"알지 못하는 알고리즘 이름입니다. 이름을 다시 확인하세요. 혹 필요한 js 파일이 로딩되었는지 확인하세요.",
	INVALID_PADDING_METHOD:		"유효하지 않은 패딩 방법입니다.",
	INVALID_PADDING:			"유효하지 않은 패딩입니다.",
	INVALID_KEY_PADDING:		"복호화에 실패했습니다. 아마도 키가 잘못되었거나 패딩방법이 잘못되었습니다.",
	UNSUPPORTED_PADDING:		"지원하지 않는 패딩 방법입니다.",
	NOT_BLOCK_CIPHER:			"스트림 사이퍼로는 오직 ECB 모드만 지원합니다.",
	INVALID_DIRECTION:			"유효하지 않은 direction 값입니다."+
									"\n값은 다음 중 하나이어야 합니다: enc/encrypt/encryption/true or dec/decrypt/decryption/false.",
	INVALID_INPUT_SIZE:			"유효하지 않은 데이터 사이즈입니다.",
	GCTR_NOT_GOST:				"GCTR/GOFB 모드는 오직 GOST-28147 알고리즘에만 해당됩니다.",
	MODE_INVALID_BLOCKSIZE:		"알고리즘의 블럭 사이즈가 모드에 필요한 블럭 사이즈가 아닙니다.",
	MAC_CHECK_FAIL:				"맥 체크에 실패했습니다.",
	MODE_INVALID_TAGSIZE:		"맥 태그 사이즈가 잘못되었습니다.",
	POLY1305_NOT_CHACHA20:		"Poly1305-AEAD 모드는 오직 Chacha20 알고리즘과 사용됩니다.",
	MAC_NOT_FOUND:				"맥을 찾을 수 없습니다.",

//	CHACHA20_INVALID_IV:		"Chacha20 알고리즘은 96 비트 길이의 IV를 필요로 합니다(12 bytes)",
//	VMPC_INVALID_IV:			"VMPC 알고리즘은 16에서 64 바이트의 IV를 필요로 합니다.",
	INVALID_TWEAK_SIZE:			"유효하지 않은 트윅(Tweak) 사이즈입니다.",
	INVALID_CTS_TYPE:			"잘못된 CTS 타입 값이 주어졌습니다.",

	XTS_DATAUNIT_NOT_GIVEN:		"데이터 유닛 일련번호가 주어지지 않았습니다.",
	INVALID_DATAUNIT_SERIAL:	"잘못된 데이터 유닛 일련번호 값입니다.",
	INVALID_DATAUNIT_LENGTH:	"잘못된 데이터 유닛 비트 사이즈 값입니다. 비트 사이즈는 8의 배수값이어야 하며 128보다 큰 수이어야 합니다.",
	INVALID_DATAUNIT_LENGTH_2:	"잘못된 데이터 유닛 비트 사이즈 값입니다. 비트 사이즈는 데이터의 비트 사이즈보다 작아야 합니다.",
	INVALID_DATAUNIT_LENGTH_3:  "잘못된 데이터 유닛 비트 사이즈 값입니다. 데이터의 비트 사이즈와 비교시 7이상으로 차이가 나서는 안됩니다.",
	DATA_SHORT_FOR_LENGTH:		"데이터 사이즈가 데이터 유닛 비트 사이즈 값보다 작습니다.",
	NOT_MULTIPLE_OF_BLOCKSIZE:	"데이터 사이즈가 블럭 사이즈의 배수 값이 아닙니다.",

	// mac

	UNSUPPORTED_MAC:			"지원하지 않는 맥 알고리즘입니다.",
	ALGORITHM_NOT_SET:			"알고리즘이 설정되지 않았습니다.",
	GOST28147_REQUIRED:			"Gost28147 알고리즘이 필요합니다.",
	DES_REQUIRED:				"DES 알고리즘이 필요합니다.",
//	VMPCMAC_INVALID_IV:			"VMPC-Mac 알고리즘은 1에서 768 사이의 IV를 필요로 합니다.",
	
	// digest

	UNSUPPORTED_HASHER:			"지원하지 않는 해쉬 알고리즘 값입니다.",
	UNKNOWN_FORMAT:				"지원하지 않는 포맷 값입니다.",
	NOT_INITIALIZED:			"알고리즘이 초기화가 진행되지 않았습니다.",
	INVALID_OUTPUT_BITS:		"outputBits 값은 8의 배수이어야 합니다.",
	DERIVED_KEY_TOO_LONG:		"추출하려는 키 사이즈가 너무 깁니다.",
	TRHREEFISH_REQUIRED:		"Threefish 알고리즘이 필요합니다.",
	OUTPUT_BITS_TOO_SMALL:		"출력 자료 사이즈 값이 너무 작습니다.",

	// pki

	MSG_TOO_LONG:				"메시지 사이즈가 너무 커서 PKI가 다룰 수 없습니다.",
	UNSUPPORTED_PKI_FUNC:		"해당 PKI에서 지원하지 않는 함수입니다.",
	INVALID_PUBKEY:				"공개키가 유효하지 않습니다.",
	INVALID_PRIVKEY:			"개인키가 유효하지 않습니다.",
	INVALID_BIT_LENGTH:			"잘못된 비트 사이즈 값입니다.",
	PUBKEY_NOT_SET:				"공개키가 설정되지 않았습니다.",
	PRIVKEY_NOT_SET:			"개인키가 설정되지 않았습니다.",
	RSA_INVALID_PUB_EXP:		"RSA 설정에 필요한 public exponent 값이 유효하지 않습니다.",
	CIPHERTEXT_TOO_SHORT:		"복호화할 메시지 사이즈가 작습니다.",
	HASH_MISMATCH:				"해쉬 값이 일치하지 않습니다.",
	MALFORMED_DATA:				"데이터가 깨진 값입니다.",
	INVALID_SALT_LENGTH:		"Salt 사이즈(saltLength) 값이 잘못되었습니다.",
	UNSUPPORTED_PKI:			"지원되지 않는 PKI 이름입니다.",
	PARAMS_NOT_SET:				"파라미터가 설정되지 않았습니다.",
	UNSUPPORTED_EC_TYPE:		"지원되지 않는 EC 타입입니다. 라이트 버젼의 경우 지원하지 않습니다.",
	PKI_NOT_SET:				"PKI가 설정되지 않았습니다.",
	INVALID_BITLENGTH:			"비트 사이즈가 잘못되었습니다.",
	UNFIT_HASH:					"해쉬 알고리즘이 해당 작업에 적합하지 않습니다.",
	INVALID_BLOCK_TYPE:			"잘못된 블럭 타입이 주어졌습니다.",
	INVALID_SALT:				"잘못된 salt 값이 주어졌습니다.",
	NOT_SEQUENCE:				"주어진 오브젝트가 ASN1 sequence가 아닙니다.",

	// ASN1

	INVALID_DATA_LENGTH:		"깨진 데이터이거나 데이터 사이즈가 일치하지 않습니다.",
	INVALID_TAG_LENGTH:			"깨진 데이터이거나 태그 사이즈가 올바르지 않습니다.",
	TOO_BIG_TAG_LENGTH:			"태그 사이즈 값이 자바스크립트에서 다루기에 너무 큽니다.",
	UNKNOWN_TAG_TYPE:			"알지 못하는 태그입니다.",
	UNKNOWN_TAG_CLASS:			"알지 못하는 태그 클래스입니다.",
	UNRECOGIZED_TIME:			"인식할 수 없는 시간 값입니다.",
	INVALID_OID:				"오브젝트 아이디 값이 잘못되었습니다.",
	EOC_REACHED:				"데이터 컨텐츠 끝에 도달했습니다.",
	INVALID_ASN1:				"올바른 ASN1 스트링이 아닙니다.",
	NEGATIVE_NOT_SUPPORTED:		"음수는 지원하지 않습니다.",

	// KDF
	UNSUPPORTED_KDF:			"지원하지 않는 키 도출 함수입니다.",
	UNKNOWN_KDF_TYPE:			"알지 못하는 키 도출 타입입니다.",
	SALT_NOT_SET:				"Salt값이 올바르지 않거나 주어지지 않았습니다.",
	FATAL_ERROR:				"치명적인 오류 발생으로 더 이상 진행할 수 없습니다.",

	// PEM

	INVALID_PEM_FORMAT:			"잘못된 PEM 포맷입니다.",
	PEM_NOT_MATCH_WITH_PKI:		"PEM이 주어진 PKI와 일치하지 않습니다.",
	NO_PKCS5_PEM_SUPPORTED:		"PKCS#5 PEM 포맷이 지원되지 않습니다.",
	INVALID_ENCRYPTION_METHOD:	"잘못된 암호화 방식이 사용되었거나 지원하지 않습니다.",
	UNKNOWN_ECDSA_CURVE:		"알지 못하는 ECDSA 커브 오브젝트 아이디 값 혹은 이름입니다.",
	UNKNOWN_ECDSA_FIELD:		"알지 못하는 ECDSA 필드 타입입니다.",
	NO_PASSPHRASE:				"암/복호화에 필요한 비밀번호 값이 없습니다.",
	UNSUPPORTED_MGF:			"지원하지 않는 PKCS#1 MGF 함수입니다.",
	UNSUPPORTED_ALGO_OID:		"지원하지 않는 알고리즘 오브젝트 아이디 값입니다.",
	INCORRECT_PASSPHRASE:		"잘못된 비밀번호이거나 데이터가 깨졌을 수 있습니다.",
	UNSUPPORTED_PEM_VERSION:	"지원하지 않는 PEM 버젼입니다.",
	UNSUPPORTED_PRF:			"지원하지 않는 PRF 해쉬 알고리즘이거나 오브젝트 아이디입니다.",
	PUBKEY_INFO_FAIL:			"공개키정보를 가져올 수 없습니다.",
	UNSUPPORTED_PKI_METHOD:		"지원하지 않는 PKI 메소드입니다.",
	UNSUPPORTED_PEM_FORMAT:		"지원하지 않는 PEM 포맷입니다.",
	PARAMETERS_DISMATCH:		"파라미터가 일치하지 않습니다.",
	INVALID_SEED:				"시드 값이 올바르지 않거나 길이가 잘못되었습니다.",

	// CERTIFICATE
	SIGNATURE_GET_FAIL:			"인증서에서 서명을 가져올 수 없습니다.",
	INVALID_SIGN_ALGO:			"잘못된 서명 알고리즘입니다.",
	INVALID_HASH_ALGO:			"잘못된 서명 해쉬 알고리즘입니다.",
	HASH_NAME_MISMATCH:			"해쉬 이름이 일치하지 않습니다.",
	INVALID_CERT_INFO:			"잘못된 인증서 정보 데이터입니다.",
	SIGN_ALGO_MISMATCH:			"서명 알고리즘이 일치하지 않습니다.",
	NOT_CSR:					"주어진 PEM은 CSR(Certificate Signing Request) 포맷이 아닙니다.",
	UNSUPPORTED_EXTENSION:		"인증서에 지원하지 않는 extensions가 있습니다.",
	PKI_NOT_MATCH:				"PKI가 일치하지 않습니다.",
	VERIFICATION_FAIL:			"검증에 실패했습니다.",
	PUBKEYINFO_NOT_SET:			"개인키 정보를 찾을 수 없습니다.",
	UNSUPPORTED_CERT_TYPE:		"지원하지 않는 인증서 타입입니다.",
	SERIAL_NOT_GIVEN:			"일련번호가 주어지지 않았습니다.",
	UNSUPPORTED_OID:			"지원되지 아니하는 오브젝트 ID가 주어졌습니다.",

	// EC
	NOT_DONE_YET:				"아직 지원하지 않습니다.",
	INVALID_F2M_PARAMS:			"F2m 필드 타입에 필요한 파라미터 값이 잘못되었습니다.",
	NOT_FIELDELEMENT:			"필드 엘러먼트가 jCatle.EC.FieldElement.F2m 오브젝트가 아닙니다.",
	NEGATIVE_VALUE:				"음수 혹은 0의 값이 주어졌습니다.",
	CURVE_NOT_LOADED:			"EC 커브가 로드되지 않았습니다.",
	NOT_SAME_CURVE:				"동일 커브 상에 있지 않습니다.",
	DIFFERENT_REPRESENTATION:	"필드 엘러먼트 하나가 잘못된 값입니다.",
	NOT_IMPLEMENTED:			"아직 지원하지 않습니다.",
	INVALID_POINT_VALUE:		"유효하지 않은 포인트 값입니다(무한 등)",
	ONE_IS_NULL:				"필드 엘러먼트 하나가 Null값입니다.",
	INVALID_ENCODING:			"유효하지 않은 포인트 인코딩 값입니다.",
	INVALID_COMPRESSION:		"잘못된 포인트 압축 값입니다.",
	ECDSA_NOT_LOADED:			"ECDSA 라이브러리가 로드되지 않았습니다.",
	X_VALUE_TOO_LARGE:			"x값이 Field Element에 비해 너무 큽니다.",

	// KeyWrap
	IV_CHECK_FAIL:				"IV 검증에 실패했습니다.",
	ICV_CHECK_FAIL:				"ICV 검증에 실패했습니다.",
	INVALID_WRAPPED_KEYSIZE:	"감싸기 된 키의 사이즈가 올바르지 않습니다.",

	// config
	INVALID_CONFIG:				"Config 설정에 한 가지 이상의 에러가 있습니다.",

	FILE_API_SUPPORT_FAIL:		"사용하는 브라우져에서는 File API를 지원하지 않습니다. 최신 브라우져로 업데이트 하거나 설치하기를 추천합니다.",
	NOT_RECOMMENDED:			"설정한 값은 추천하지 않습니다.",
	TOO_SHORT_VALUE:			"최소값 보다 더 길이가 작은 값이 주어졌습니다.",
	TOO_LONGER_VALUE:			"최대값 보다 더 길이가 큰 값이 주어졌습니다.",
	VALUE_NOT_SUPPLIED:			"주어지지 않은 값들이 있습니다.",
	NOT_SECTION_LINK:			"섹션은 반드시 다음 뒤에 와야 합니다: SEQUENCE | SEQ | SET | EXPLICIT | EXP.",
	NO_TAG_TYPE_GIVEN:			"태그 타입이 반드시 다음 뒤에 와야 합니다: EXPLICIT | EXP | IMPLICIT | IMP.",
	UNKNOWN_OID:				"알지 못하는 오브젝트 아이디 값이 주어졌습니다.",

	// pfx
	INVALID_PFX_FORMAT:			"잘못된 PFX 혹은 P12 포맷입니다.",
	UNSUPPORTED_PFX_STRUCTURE:	"지원하지 않는 PFX 파일 혹은 스트링 값입니다.",
	SALT_LENGTH_TOO_SHORT:		"Salt 길이가 너무 작습니다. 최소 길이는 8입니다..",
	INVALID_ITERATIONS:			"잘못된 iterations 값입니다.",
	NO_SAFEBAG_CONTENT:			"SafeBag.content 값이 주어지지 않았거나 잘못되었습니다.",
	INVALID_CERT_TYPE:			"SafeBag.content 값이 잘못된 인증서 타입입니다.",
	WRONG_PASSPHRASE:			"복호화 할 수 없습니다. 비밀번호가 잘못되었을 수 있습니다.",
	INVALID_PFX_INFO:			"잘못된 PFX Info 구조입니다.",

	// jwt
	NOT_JWT:					"JSON Web Token(JWT) 형식의 스트링이 아닙니다.",
	KEYLEN_TOO_LARGE:			"Keydata 길이 값이 너무 큽니다.",
	KEY_DERIVATION_FAIL:		"키 생성에 실패했습니다.",
	KEYS_COUNT_NOT_MATCH:		"키 갯수와 서명 갯수가 일치하지 않습니다.",

	// oid
	OID_NOT_LOADED:				"OID 라이브러리가 로드되지 않았습니다.",

	// cms
	INVALID_DATA_TYPE:			"유효하지 않은 데이터 타입입니다.",
	INVALID_CMS_FORMAT:			"잘못된 CMS 포맷입니다.",
	UNSUPPORTED_CMS_STRUCTURE:	"지원하지 않는 CMS 데이터 타입이거나 구조입니다.",
	INVALID_CMS_STRUCTURE:		"잘못된 CMS 데이터 구조입니다.",
	INVALID_CMS_VERSION:		"잘못된 CMS 버젼입니다.",
	UNSUPPORTED_ENCRYPTION_ALGO:"지원하지 않는 CMS 키 암호화 알고리즘입니다.",
	INVALID_CMS_INFO:			"잘못된 CMS Info 구조입니다.",
	PKI_ISNT_ECDSA:				"PKI가 ECDSA가 아닙니다.",
	RECIPIENTS_CERT_NOT_GIVEN:	"수취인의 인증서가 주어지지 않았습니다.",
	NO_CERT_GIVEN:				"인증서가 주어지지 않았습니다.",
	NO_RID:						"RecipientIdentifier 값이 주어지지 않았습니다.",
	ORIGINTOR_CERT_NOT_GIVEN:	"발행자의 인증서가 주어지지 않았습니다.",
	MODE_NOT_SUPPORT_MAC:		"알고리듬 모드가 MAC을 지원하지 않습니다.",

	// jose
	CONFLICT_EACH_OPTION:		"protectContentOnly와 protectHeader는 동시에 옵션으로 주어질 수 없습니다.",
	COMPACT_AAD_NOT_ALLOWED: 	"compact 시리얼모드에서는 AAD를 허용하지 않습니다."

};
