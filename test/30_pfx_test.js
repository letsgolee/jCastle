const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('PFX');
QUnit.test('Basic Test', function(assert) {

	var enc_priv_key_pem = `
	-----BEGIN ENCRYPTED PRIVATE KEY-----
	MIIFLDBWBgkqhkiG9w0BBQ0wSTApBgkqhkiG9w0BBQwwHAQICOOtqCPzODkCAggA
	MAwGCCqGSIb3DQIJBQAwHAYIKoMajJpEAQQEEJ7IEWELxKhpmbtUKJu63rYEggTQ
	oquhw9Jlj9lqWzl7FHp/wmC5WagTChuhfT6KOvFk0Fcz1G4Zy0osvOnvsUA3zw+V
	3zyTHEHT/ajrojScZgc6D2vCYH+NjiQKRHCxBEUI5KdZbz9+epS2jHyTwPlJzJP4
	hCOb6oXo2fPL/nc9U7Cyb5oqr5mGIE19BNKJdJWwbTt1kjN753cqGWLM6GaP3eKx
	m0axdNZ6fgZJ9scdvb3rnnKw5OjiCp3b+8zSHCaq5W1LqF1kABt1sWCZBnxKwY8y
	B2IfiK3JnUG5DLdvUtZotfNHeGNweu0LDgH4ZH8c/i3yB/TwBYbK4VNPiYkxoXT7
	1YUGQqbQwFQ6EwWpfGFxnUPTTDjG3GkWFYrs8Tm6EDWkoi8Bqd8CMLelNs+suF7g
	KWZ33j+E4Fp45d39IowNWdf2R4kaGsvW3FCkNaa1E+o4zZHTWv9+69K3dZV5Pt4/
	JMneSbfuumvgOSPsJmD0KWVfqOVJs59wyVLrYHieQ34xKx1A3qWpdzTJHwdPyK7q
	Ra5fPR7j4bT7ncYqML5KQb5Uqz9BZLGZD5fqFzVgjwyALDdYNxoHQccb6NhOq1e5
	yKCGhZ9guRfp6Hy6F8LMJV2e9rHHI4gPCUvZkMk/SjXV2Vy9xxKvdAWAcInN4dEp
	/yiLqy8zpy0q85hydOU/ItaCEhv0a5ttHQV0yXVWvf5WcF+snzW/4y0WboRB/IRC
	LN/WpGSaVr8uqYE3NLRa80nLZF2Xvnmu3BEccKtsF3C71qlNi31Ksqq3pv0gTL+7
	vWhOhwYlVfpvH5e0OINYhpvXHdqzeCbueUJ6u1T2vT5p4Q7E59jK6myNTEE0VeLf
	SgwnLBThXiZM53NtWcS6gPJ8y+QZyosBwOLcsM9ojnkNrfa4tZet4vMutzMONoQq
	nnIR5sHd9T4m96/032CSPePsknViIer7JiCq0bNFXpgWMjDJQZuVjmomOepT3aob
	yQcPcYgKeG5l9TWaVb0sm4pYjQv+aqzmYo8ZJGfnwUUOmW9BdbZPEdIx8lE1yir6
	1FRDPLz3B94NXS9G8u2DzxvnKJ87pZDI9yeU4zGUd6pW5biMe4GeCJDxrvoizwIA
	qcqtejJu816SBQGQ4yyJa39EX2wUOJI23oSqRFSQ0mdxfds5BC6y9i4+2ZekbU9b
	tToWFMMqiOgFcrzgy4N5olQxbiM+wYAAZdN0fN/mXDYRTzZxlfoo9oHRpKyAm105
	Z7sDG5DSD60SUnCYkg2iVHTk+5OV1nW8pfAcrWYSbi+g4rXl2bNBB/fShzKLOSMh
	zoZ6C+5ZkuFPl5C57g5xZyy4sK4tU2nAQutF73zNTCipx2O4jl4pGpqwiDrcuD6O
	p7KVQbVe/P5jHC4s9cNb1Hb2J6bVvnH2oXU2tta5FPAVah9936fEn6I97nZi9+7S
	UKTG0US9Im87pIzt4gfJqMxCPZgulHvV8pBNzZFAY/F424hV1EHizaInhaoUDSj0
	crXvZpIAUZzO3HpuI/ysMywqOd2NqxWRQNVYobo2ur2FVOTCNO/RQarr9BvYT1GX
	85cefe+APXCbzOUL+7JAzVNDLYkqDsMykz8QrtksUmOdyG/fznH/3gyDfzi3Lson
	PPHRqlwvjJwaoX356aZBx+majfTWvPLRsmUhQdTwldE=
	-----END ENCRYPTED PRIVATE KEY-----`;


	var cert_pem = `
	-----BEGIN CERTIFICATE-----
	MIID6zCCAtOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJrcjER
	MA8GA1UEChMIZGVtb3NpZ24xDzANBgNVBAsTBmRlbW9DQTEXMBUGA1UEAxMOZGVt
	b0NBIENsYXNzIDEwHhcNMTkxMjExMTQwMTI0WhcNMjAxMjExMTQwMTI0WjB/MQsw
	CQYDVQQGEwJrcjERMA8GA1UECgwIZGVtb3NpZ24xFDASBgNVBAsMC3BlcnNvbmFs
	NElTMREwDwYDVQQLDAhEZW1vQmFuazE0MDIGA1UEAwwrw63CmcKNw6rCuMK4w6vC
	j8KZKCkwMDk5MDMzMjAxOTEyMTExMTA0MTE4MDCCASIwDQYJKoZIhvcNAQEBBQAD
	ggEPADCCAQoCggEBANNX9DPTDRpp/QBx4O6h7k6YrSAqys4d8nE7BrtqYTsyiPg4
	0u+wPYYqZdYzLHyt4FhoT5u64XmvTgf98e67LjX2VUvZzK5r6kocSqa978t7Ievf
	uww4Hq6qr1rNdzfmNIcOdwj6Npn8Lz7sDef6UIXZPj8/Ary6kugmEE+otrU7zmQl
	yrZugGTjOAOutq3qA6Z7FWHfYIrBMGc7JMouehvOFSu+EB7PVhwKUcaxbRS4x3+e
	UB4JMG9+5f0z5DLMf6SdckxDQtzkCOYjq8zd7ufhANxeOtSbjKKojnJfovAQqj4W
	vvyv6tBJrg9MF+ZZhQWzBi4rbppwtJ0gTfMOsr8CAwEAAaOBpjCBozAMBgNVHRME
	BTADAQEAMB0GA1UdDgQWBBQ5wMqSqxM/Bxrssawz73W+7FJEgzB0BgNVHSMEbTBr
	oWWkYzBhMQswCQYDVQQGEwJLUjENMAsGA1UECgwERElTQTErMCkGA1UECwwiRGVt
	byBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudHJhbDEWMBQGA1UEAwwNRElTQSBS
	b290Q0EgMYICEAMwDQYJKoZIhvcNAQELBQADggEBAGn4j78ZNBoUYrTOrpRPuRRE
	px/wqULne4mrYEB5RUe1B6KEI1W78kD8cFGvsPc2JJi0fo0aTeW7BUPM6Oh6vKtf
	fpbW9wxzT5VB/3w4klwoug0qaBYguskd1AZsxrxHg1zAUDdtgzWKRIKj6hp1VN9w
	7lQE5nIrBYwR78eGBeTIRqxc/zaviVYNTdnZFAoBCTBYJI5wmZaMmSoYzNnO/UQY
	ZccHTjW4TkJb0GuDuX7hRI7y0g45mbasuzpD2u5N2VYZH38kHc0eFMDLJOcRl5MV
	tcB1Tuc/oM+1QS6ZfFePQfNpKSx3+wQPc5CKfRE6zGhM58LMJ6TqjXON7Ebe+PI=
	-----END CERTIFICATE-----`;

	var password = '1111aaaa!!!!';

	var pfx = new jCastle.pfx.create();
	pfx_der = pfx.exportCertificateAndPrivateKey({
		certificate: cert_pem,
		privateKey: enc_priv_key_pem,
		password: password
	});

	//console.log('pfx der: ', pfx_der.toString('hex'));
	assert.ok(pfx_der, 'pfx creation test');

	var pfx_info = pfx.parse(pfx_der, {
		password: password
	});

	// var pptable = prettyPrint(jCastle.PFX.rasterizeSchema(pfx_info));
	// document.getElementById('printarea1').appendChild(pptable);

	//console.log('pfx_info: ', pfx_info);
	assert.ok(pfx_info, 'pfx parsing test');

});