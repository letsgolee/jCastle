const jCastle = require('../lib/index');
const BigInteger = require('../lib/biginteger');
const QUnit = require('qunit');

QUnit.module("Certificate");
QUnit.test("Step Test", function(assert) {
    var private_pem = `-----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
    UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
    OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
    LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
    oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
    583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
    ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
    +NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
    lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
    PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
    OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
    3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
    pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
    uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
    GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
    bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
    sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
    QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
    qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
    EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
    MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
    30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
    MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
    o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
    QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
    YTdgkw8sWi3fZ9kH06PUPKs=
    -----END PRIVATE KEY-----`;



    var rsa = jCastle.pki.create().parse(private_pem);

    var t = rsa.validateKeypair(rsa.getPrivateKey());
    assert.ok(t, 'validate rsa keypair');


    var tbsCertBuf = `
    3082038ba00302010202024fb5300d06092a864886f70d01010b050030819b310
    b3009060355040613024a50310e300c06035504080c05546f6b796f3110300e06
    035504070c074368756f2d6b753111300f060355040a0c084672616e6b3444443
    1183016060355040b0c0f5765624365727420537570706f727431183016060355
    04030c0f4672616e6b344444205765622043413123302106092a864886f70d010
    9011614737570706f7274406672616e6b3464642e636f6d301e170d3232303330
    343031333835305a170d3234303330333031333835305a306d310b30090603550
    4061302435a310d300b0603550408130442726e6f310d300b0603550407130442
    726e6f3110300e060355040a1307526564204861743110300e060355040b13075
    2656420486174311c301a06035504031313636c69656e74312e6578616d706c65
    2e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0
    282010100ebb7525fd92ac2e6d334113b47842beaf38f95d6668363a4c56086fe
    8d54b51198bdd167fd171b6eb4a3a59703db312c8fd721575d15c81e18755f838
    d09892c67543019d0a5c0fe75b41c6bfd1cece018e2e3002e48de59ea794a1fe2
    f7dab4262eee8e89bd69d9629c9245a4a0b129961294367566e1fd2d5656746a7
    9d83707049c57f0cfa579c5f4ede91ccfaec940e40cffcf1ee786807a42478499
    6f87a5657e9303fbc66445fb05a3c40983a8a3dbbe522129529a349b891875dd9
    003da8c67da6b6d3db00a739a98409e76e6245f3656446b83cac6f07a54b92ed8
    b514813fd806d09dc6ee865b0af85804f193713fc0e7a3a48bc41b20a23d39993
    10203010001a382011c30820118300c0603551d1304053003010100302c060960
    86480186f842010d041f161d4f70656e53534c2047656e6572617465642043657
    27469666963617465301d0603551d0e0416041412c244feada980cf8ab94536f4
    3eea183ab736db301f0603551d230418301680145906268c24433684503d0bed6
    77b74bc056fd971307b06082b06010505070101046f306d302006082b06010505
    0730018614687474703a2f2f6f6373702e6d792e686f73742f302006082b06010
    5050730028614687474703a2f2f6d792e63612f63612e68746d6c302706082b06
    010505073001861b687474703a2f2f6f6373702e6d792e7365636f6e642e686f7
    3742f301d0603551d11041630148212636c69656e742e6578616d706c652e636f
    6d`;

    tbsCertBuf = Buffer.from(tbsCertBuf.replace(/[^0-9A-F]/ig, ''), 'hex');
    // console.log('tbsCertBuf.length: ', tbsCertBuf.length);

    var hashAlgo = 'sha-256';

    var sig = rsa.sign(tbsCertBuf, {
        hashAlgo: hashAlgo
    });

    var v = rsa.verify(tbsCertBuf, sig, {
        hashAlgo
    });

    assert.ok(v, 'verify signature');
});


QUnit.test("Parsing & Verifying Test 1", function(assert) {
    
    var req_pem = `-----BEGIN CERTIFICATE REQUEST-----
    MIIC4jCCAcoCAQAwbTELMAkGA1UEBhMCQ1oxDTALBgNVBAgTBEJybm8xDTALBgNV
    BAcTBEJybm8xEDAOBgNVBAoTB1JlZCBIYXQxEDAOBgNVBAsTB1JlZCBIYXQxHDAa
    BgNVBAMTE2NsaWVudDEuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
    DwAwggEKAoIBAQDrt1Jf2SrC5tM0ETtHhCvq84+V1maDY6TFYIb+jVS1EZi90Wf9
    FxtutKOllwPbMSyP1yFXXRXIHhh1X4ONCYksZ1QwGdClwP51tBxr/Rzs4Bji4wAu
    SN5Z6nlKH+L32rQmLu6Oib1p2WKckkWkoLEplhKUNnVm4f0tVlZ0annYNwcEnFfw
    z6V5xfTt6RzPrslA5Az/zx7nhoB6QkeEmW+HpWV+kwP7xmRF+wWjxAmDqKPbvlIh
    KVKaNJuJGHXdkAPajGfaa209sApzmphAnnbmJF82VkRrg8rG8HpUuS7YtRSBP9gG
    0J3G7oZbCvhYBPGTcT/A56Oki8QbIKI9OZkxAgMBAAGgMDAuBgkqhkiG9w0BCQ4x
    ITAfMB0GA1UdEQQWMBSCEmNsaWVudC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQUF
    AAOCAQEAJC8byzLDAk7lX8kg6kWWMPfmpMEU+ACAVzQL8DJNlVCLUB+IWQPdHI+K
    HZDsB4NPY6vaqiujibNwcl4n4196Rsxbnc1Q0xIvJ3JViEiI/2oxW+bdgWCmjuLf
    JEqp/KMIcDdtvJ+U9JA6IplexAns/tkRJ3FVbPYtZpKw5FOFixH1WeHjF8J0wOCv
    7RNHI4E+7LeeLv5w8+QB9fc4xk0LYLz9ajoQf/4em5bhaidRDAyp6rh88zNdWM5u
    ZpWOyngW0yt6r8xMBCM8CJAql+lrUT1I/IuhnyjK1PKgI6qr/2a/qlo7KJpAjwxU
    85gGMt/+QPtaKfMJSUkyjXidXU5eeA==
    -----END CERTIFICATE REQUEST-----`;
    
    
            
        var private_pem = `-----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
    UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
    OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
    LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
    oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
    583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
    ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
    +NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
    lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
    PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
    OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
    3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
    pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
    uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
    GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
    bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
    sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
    QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
    qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
    EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
    MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
    30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
    MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
    o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
    QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
    YTdgkw8sWi3fZ9kH06PUPKs=
    -----END PRIVATE KEY-----`;
    
    
    
    var config_contents = `
    #
    # OpenSSL example configuration file.
    # This is mostly being used for generation of certificate requests.
    #
    
    # This definition stops the following lines choking if HOME isn't
    # defined.
    HOME			= .
    RANDFILE		= $HOME/.rnd
    
    # Extra OBJECT IDENTIFIER info:
    #oid_file		= $HOME/.oid
    oid_section		= new_oids
    
    # To use this configuration file with the "-extfile" option of the
    # "openssl x509" utility, name here the section containing the
    # X.509v3 extensions to use:
    # extensions		= 
    # (Alternatively, use a configuration file that has only
    # X.509v3 extensions in its main [= default] section.)
    
    [ new_oids ]
    
    # We can add new OIDs in here for use by 'ca' and 'req'.
    # Add a simple OID like this:
    # testoid1=1.2.3.4
    # Or use config file substitution like this:
    # testoid2= $ {testoid1}.5.6
    
    streetAddress = 2.5.4.9
    postalCode = 2.5.4.17
    POBox = 2.5.4.18
    
    ####################################################################
    [ ca ]
    default_ca	= CA_default		# The default ca section
    
    ####################################################################
    [ CA_default ]
    
    dir		= ./demoCA		# Where everything is kept
    certs		= $dir/certs		# Where the issued certs are kept
    crl_dir		= $dir/crl		# Where the issued crl are kept
    database	= $dir/index.txt	# database index file.
    new_certs_dir	= $dir/newcerts		# default place for new certs.
    
    certificate	= $dir/cacert.pem 	# The CA certificate
    serial		= $dir/serial 		# The current serial number
    crl		= $dir/crl.pem 		# The current CRL
    private_key	= $dir/private/cakey.pem# The private key
    RANDFILE	= $dir/private/.rand	# private random number file
    
    x509_extensions	= usr_cert		# The extentions to add to the cert
    
    # Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
    # so this is commented out by default to leave a V1 CRL.
    # crl_extensions	= crl_ext
    
    default_days	= 365			# how long to certify for
    default_crl_days= 30			# how long before next CRL
    default_md 	= sha1			# which md to use
    preserve	= no			# keep passed DN ordering
    
    # A few difference way of specifying how similar the request should look
    # For type CA, the listed attributes must be the same, and the optional
    # and supplied fields are just that :-)
    policy		= policy_match
    
    # For the CA policy
    [ policy_match ]
    countryName		= match
    stateOrProvinceName	= match
    organizationName	= match
    organizationalUnitName	= optional
    commonName		= supplied
    emailAddress		= optional
    
    # For the 'anything' policy
    # At this point in time, you must list all acceptable 'object'
    # types.
    [ policy_anything ]
    countryName		= optional
    stateOrProvinceName	= optional
    localityName		= optional
    organizationName	= optional
    organizationalUnitName	= optional
    commonName		= supplied
    emailAddress		= optional
    
    ####################################################################
    [ req ]
    default_bits		= 2048
    default_keyfile 	= privkey.pem
    default_md 		= sha1
    distinguished_name	= req_distinguished_name
    #attributes		= req_attributes
    x509_extensions	= v3_ca	# The extentions to add to the self signed cert
    
    # Passwords for private keys if not present they will be prompted for
    # input_password = secret
    # output_password = secret
    
    # This sets a mask for permitted string types. There are several options. 
    # default: PrintableString, T61String, BMPString.
    # pkix	 : PrintableString, BMPString.
    # utf8only: only UTF8Strings.
    # nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
    # MASK:XXXX a literal mask value.
    # WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
    # so use this option with caution!
    string_mask = nombstr
    
    req_extensions = v3_req # The extensions to add to a certificate request
    
    [ req_distinguished_name ]
    countryName			= Country Name (code ISO a 2 lettres)
    countryName_default		= FR
    countryName_min			= 2
    countryName_max			= 2
    
    stateOrProvinceName		= State or Province Name
    stateOrProvinceName_default	= Alpes Maritimes
    stateOrProvinceName_max         = 64
    
    localityName			= Locality Name
    localityName_default		= Nice
    localityName_max                = 64
    
    organizationName		= Organization Name
    organizationName_default	= Michel Durand SA
    organizationName_max            = 64
    
    # we can do this but it is not needed normally :-)
    #1.organizationName		= Second Organization Name (eg, company)
    #1.organizationName_default	= World Wide Web Pty Ltd
    
    organizationalUnitName		= Organizational Unit Name (optional)
    organizationalUnitName_default	= Fourni par TBS internet
    organizationalUnitName_max      = 64
    
    commonName			= Common Name (eg, YOUR name or site name)
    commonName_default		= www.monsitessl.fr
    commonName_max			= 64
    
    emailAddress		= Email Address
    emailAddress_default	= your.mail.com
    emailAddress_max		= 64
    
    # SET-ex3			= SET extension number 3
    
    [ req_attributes ]
    challengePassword		= A challenge password
    challengePassword_min		= 4
    challengePassword_max		= 20
    
    unstructuredName		= An optional company name
    
    [ usr_cert ]
    
    # These extensions are added when 'ca' signs a request.
    
    # This goes against PKIX guidelines but some CAs do it and some software
    # requires this to avoid interpreting an end user certificate as a CA.
    
    basicConstraints=CA:FALSE
    
    # Here are some examples of the usage of nsCertType. If it is omitted
    # the certificate can be used for anything *except* object signing.
    
    # This is OK for an SSL server.
    # nsCertType			= server
    
    # For an object signing certificate this would be used.
    # nsCertType = objsign
    
    # For normal client use this is typical
    # nsCertType = client, email
    
    # and for everything including object signing:
    # nsCertType = client, email, objsign
    
    # This is typical in keyUsage for a client certificate.
    # keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    
    # This will be displayed in Netscape's comment listbox.
    nsComment			= "OpenSSL Generated Certificate"
    
    # PKIX recommendations harmless if included in all certificates.
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always,issuer
    
    # This stuff is for subjectAltName and issuerAltname.
    # Import the email address.
    # subjectAltName=email:copy
    
    # Copy subject details
    # issuerAltName=issuer:copy
    
    #nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
    #nsBaseUrl
    #nsRevocationUrl
    #nsRenewalUrl
    #nsCaPolicyUrl
    #nsSslServerName
    
    authorityInfoAccess = aia_section
    
    [ v3_req ]
    
    # Extensions to add to a certificate request
    
    subjectKeyIdentifier        = hash
    
    #basicConstraints = critical,CA:FALSE,pathlen:1
    basicConstraints = critical,bs_section
    
    keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, decipherOnly
    
    authorityKeyIdentifier = keyid,issuer
    
    #subjectAltName=email:copy,email:my@other.address.ma,IP:192.168.7.1,URI:http://my.url.here/
    #subjectAltName=email:copy,email:my@other.address.ma,IP:2013::bf05:17,RID:1.2.3.4,URI:http://my.url.here/
    subjectAltName=email:copy,email:my@other.address.ma,IP:2013::bf05:17,RID:1.2.3.4,URI:http://my.url.here/,otherName:1.2.3.4;UTF8:some other identifier
    
    issuerAltName=issuer_alt_sec
    
    issuingDistributionPoint=critical, idp_section
    
    authorityInfoAccess = OCSP;URI:http://ocsp.my.host/, aia_section
    
    
    crlDistributionPoints=crldp1_section,URI:http://myhost.com/myca.crl,URI:http://oth.com/my.crl
    
    inhibitAnyPolicy = 2
    
    noCheck = ignored
    
    certificatePolicies=ia5org,1.2.3.4,1.5.7.8,polsect
    
    policyConstraints=requireExplicitPolicy:3
    
    nameConstraints=permitted;IP:192.168.0.0/255.255.0.0
    nameConstraints=excluded;DNS:.east.corp.contoso.com
    
    extendedKeyUsage=critical,codeSigning,msCTLSign,emailProtection,1.2.3.4
    
    nsCertType = client, email, objsign
    nsComment = "Some Random Comment"
    nsBaseUrl  = https://www.sopac.org/ssl/
    nsCaRevocationUrl = https://www.sopac.org/ssl/sopac-ca.crl
    nsRevocationUrl  = https://www.sopac.org/ssl/revocation.html? 
    nsRenewalUrl  = https://www.sopac.org/ssl/renewal.html? 
    nsCaPolicyUrl  = https://www.sopac.org/ssl/policy.html 
    nsSslServerName  = $ENV::SSL_FQDN
    
    
    [aia_section]
    
    OCSP;URI.0 = http://ocsp.my.host/
    caIssuers;URI.0 = http://my.ca/ca.html
    OCSP;URI.1 = http://ocsp.my.second.host/
    
    
    
    [bs_section]
    
    CA=true
    pathlen =1
    
    [polsect]
    
    policyIdentifier=1.3.5.8
    CPS.1="http://my.host.name/"
    CPS.2="http://my.your.name/"
    userNotice=notice
    
    [notice]
    explicitText="Explicit Text here"
    organization="organisation Name"
    noticeNumbers=1,2,3,4
    
    
    [crldp1_section]
    
    fullname=URI:http://myhost.com/myca.crl
    CRLissuer=dirName:issuer_sect
    #reasons=keyCompromise, CACompromise
    reasons=keyCompromise
    
    [issuer_sect]
    
    C=UK
    O=My Organisation
    CN=some Name
    
    [idp_section]
    
    fullname=URI:http://myhost.com/myca.crl
    onlyCA=TRUE
    onlyAA=TRUE
    indirectCRL=TRUE
    onlysomereasons=keyCompromise, CACompromise
    
    
    [issuer_alt_sec]
    
    DNS.1   = www.foo.com
    DNS.2   = www.bar.org
    IP.1    = 192.168.1.1
    IP.2    = 192.168.69.144
    email = email@me
    
    otherName = 1.3.6.1.4.1.1;UTF8:some other identifier
    
    [ v3_ca ]
    
    
    # Extensions for a typical CA
    
    
    # PKIX recommendation.
    
    subjectKeyIdentifier=hash
    
    authorityKeyIdentifier=keyid:always,issuer:always
    
    # This is what PKIX recommends but some broken software chokes on critical
    # extensions.
    #basicConstraints = critical,CA:true
    # So we do this instead.
    basicConstraints = CA:true
    
    # Key usage: this is typical for a CA certificate. However since it will
    # prevent it being used as an test self-signed certificate it is best
    # left out by default.
    # keyUsage = cRLSign, keyCertSign
    
    # Some might want this also
    # nsCertType = sslCA, emailCA
    
    # Include email address in subject alt name: another PKIX recommendation
    # subjectAltName=email:copy
    # Copy issuer details
    # issuerAltName=issuer:copy
    
    # DER hex encoding of an extension: beware experts only!
    # obj=DER:02:03
    # Where 'obj' is a standard or added object
    # You can even override a supported extension:
    # basicConstraints= critical, DER:30:03:01:01:FF
    
    [ crl_ext ]
    
    # CRL extensions.
    # Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.
    
    # issuerAltName=issuer:copy
    authorityKeyIdentifier=keyid:always,issuer:always
    `;
    
    
    var sign_pki = new jCastle.pki('RSA');
    sign_pki.parsePrivateKey(private_pem);

    var serial = 20405;

    var issuer = [{
        name: 'countryName',
        value: 'JP',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Tokyo'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'localityName',
        value: 'Chuo-ku'
    }, {
        name: 'organizationName',
        value: 'Frank4DD'
    }, {
        name: 'organizationalUnitName',
        value: 'WebCert Support'
    }, {
        name: 'commonName',
        value: 'Frank4DD Web CA'
    }, {
        name: 'emailAddress',
        value: 'support@frank4dd.com'
    }];

    var algo = {
        signHash: 'SHA-256',
        signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'ECDSA', 'DSA'
    };


    var cert_info = new jCastle.certificate().parse(req_pem);
    // console.log('req pubkey: ', cert_info.tbs.subjectPublicKeyInfo.publicKey.n.toString(16));
    // console.log('req_pem info: ', cert_info);
    // console.log('subjectAltName: ', cert_info.tbs.extensionRequest.subjectAltName);


    var config = new jCastle.certConfig().parse(config_contents);
    // console.log('cert-config: ', config)

    var cert_pem = new jCastle.certificate().setConfig(config)
        .setSignKey(sign_pki)
        .issue(req_pem, {
            serialNumber: serial,
            issuer: issuer,
            validity: {
                days: 365 * 2
            },
            algo: algo
        });


    //console.log('cert pem: ', cert_pem);

    var cert_info = new jCastle.certificate().parse(cert_pem);

    assert.ok(cert_info.tbs.extensions.authorityInfoAccess.accessDescription[1].accessLocation.value == 'http://my.ca/ca.html', 'authorityInfoAccess equal test');

	assert.ok(cert_info.tbs.extensions.subjectAltName[0].value == 'client.example.com', 'subjectAltName equal test');

	assert.ok(jCastle.pki.createPublicKeyIdentifier(
		jCastle.pki.createFromPublicKeyInfo(cert_info.tbs.subjectPublicKeyInfo)
	).equals(cert_info.tbs.extensions.subjectKeyIdentifier), 'subjectKeyIdentifier equal test');

    //console.log(new jCastle.certificate().verify(cert_pem, sign_pki));
    assert.ok(new jCastle.certificate().verify(cert_pem, sign_pki), 'signature verification test');

    // this should be false for it is not self-signed certificate!
    //console.log(new jCastle.certificate().verify(cert_pem, null));       
    
    
    //
    // test 2    
    //
    
    var cert_pem = `-----BEGIN CERTIFICATE-----
    MIIDiDCCAnACCQDSrKC48NUWNDANBgkqhkiG9w0BAQsFADCBhTELMAkGA1UEBhMC
    S1IxFTATBgNVBAgMDENodW5nLWNoZW9uZzESMBAGA1UEBwwJQ2hlb25nLWp1MRIw
    EAYDVQQKDAljam1pbm9sdGExEzARBgNVBAMMCm1pbm9sdGEtY2oxIjAgBgkqhkiG
    9w0BCQEWE2xldHNnb2xlZUBuYXZlci5jb20wHhcNMTUwNTIyMDYyMTM4WhcNMTYw
    NTIxMDYyMTM4WjCBhTELMAkGA1UEBhMCS1IxFTATBgNVBAgMDENodW5nLWNoZW9u
    ZzESMBAGA1UEBwwJQ2hlb25nLWp1MRIwEAYDVQQKDAljam1pbm9sdGExEzARBgNV
    BAMMCm1pbm9sdGEtY2oxIjAgBgkqhkiG9w0BCQEWE2xldHNnb2xlZUBuYXZlci5j
    b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbR7MPA/rFOYolVI1c
    CnqQCFWrxLcH5XygKuQojx3Mw3hjD/Mi8z1NASx+YyN0iC/akzdBwb0VDnN938rc
    qvzTni0+g3cOUftM8CVzcNtcbmGKSP8lb5CmNtUcEbQruw+8lFpGFAi3kSh39/Ti
    GgDlzU7YUMImfXtGzFnGHLrIGs6g74TsOd+gxFUyTJ8Gz6IGyAN7vabRVXpykskn
    aQgPg+Ohi5TJhFKQEcW8AG0wjcves5WN+k3q75Oh8B+pX37iNofms/D3X6VKp1wf
    R8gBIFZRVWJFS+RQ1hoKyTmt4W/wMg3FF8dray//TL6bB/l6fGYW7uyIHAGiiqfZ
    vr11AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAH5VCAr7c/JYRZPOY4rJ+DV7Kx8i
    JdLVVHUsCiNUublJQYRVMbVg6egrUq1DZ2S+mVB1+8bMoHXybLCuzHrnfxdSskr8
    Mbqqy+4nAzuL5FVUXqoUdPd1zxENlMFCw1ncN54AzKswoBxLymvqkXi1b2uKIM8L
    tA5tt6R8QvlUIBwU4g8gw7C/U2HktBz45CWPVus/9Myqbmuv+bBdk40BBAoM+4mp
    KAQkUY9CTjC6Tg8obT1Y5WOmnXiNxw7dlFAxbdIU9NDYQyKVr+XekyUNKeFJxmHf
    w5K3KG6qHy+9J+ywTnGPMMYan+5BZ5zbLbdBHK3r2jUUC7nCFqq9b9yvzwo=
    -----END CERTIFICATE-----`;
    
    
    var cert_info = new jCastle.certificate().parse(cert_pem);
    
    //console.log(cert_info);
    
    //var cert_pem2 = new jCastle.certificate().exportCertificate(certInfo, 'pem', true);
    var cert_pem2 = new jCastle.certificate().export(cert_info, 'pem', true); // reuse signature so to see making certificate work well.
    // console.log(cert_pem2);
    // console.log(cert_pem == cert_pem2);
    assert.equal(cert_pem.replace(/[ \t\r\n]/g, ''), cert_pem2.replace(/[ \t\r\n]/g, ''), 'reusing signature to make the same certificate test');
});

QUnit.test("DEMO Test 1", function(assert) {

    var subject_priv_pem = `-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA20ezDwP6xTmKJVSNXAp6kAhVq8S3B+V8oCrkKI8dzMN4Yw/z
    IvM9TQEsfmMjdIgv2pM3QcG9FQ5zfd/K3Kr8054tPoN3DlH7TPAlc3DbXG5hikj/
    JW+QpjbVHBG0K7sPvJRaRhQIt5Eod/f04hoA5c1O2FDCJn17RsxZxhy6yBrOoO+E
    7DnfoMRVMkyfBs+iBsgDe72m0VV6cpLJJ2kID4PjoYuUyYRSkBHFvABtMI3L3rOV
    jfpN6u+TofAfqV9+4jaH5rPw91+lSqdcH0fIASBWUVViRUvkUNYaCsk5reFv8DIN
    xRfHa2sv/0y+mwf5enxmFu7siBwBooqn2b69dQIDAQABAoIBADgqCzDjYg22CS46
    k+JpRK8zk03lmsPJAby8f6fr0EQsJN+qrCndh2v7yvusRN6KK0eewV50UwvbobUx
    5vHSUeOZ9hi2732ZffZc5BrHY0gvdYhH3iImizQngzonRrCUvxkcHmsoonryER15
    Qx3Ob0Bs7670MGZPaY3etXfK0ASEb9zrEoOskUV1Ywx9Gn1FSyFA9YRR53yhb1eM
    966ypKoxznUIcInvzRUUk71fNF451niBU92AfkWPhMf2DcDu6ToOyYlnXnt58IhS
    ZDh7VtrR0/TMSxEM0DEvCPfwXqtwdEgYNjr8k757nhO0QEBYjJysk3AcrlUlMm8f
    /Nl6ZgECgYEA7ds4i+LdtlycF78pE307IpMv7LA9qCHxyteFs1UhGUILdtqPyqjn
    QmI1pSwzExN+K17oivj8b/2qjIfA/wfaLwpiuhDJsIsYe0Pp8pJYipw8XHp8MCW1
    x7YYcvLqI6ZXEwPp5yA6vifVmadM8+wZ+Vb2mzqGpXshjln/QK56aLUCgYEA7AG6
    Ro9ttzhnbn+M+WYEvNfKX9t2DeWy3ll/mZftK3UhbKR4+YVqiXh41PrBw+6qOp5b
    23mQtIE8c5q8UuHuFRzaL2B4VHMameb5P4lXkMCo0kyz7MXSbMsRMb0b1gJt+GGd
    LzooDxqpMPd8sk2tqHVe7oHBNqS7IqmnvUh/ucECgYEAwV08RQxzrbLv+qYfIIbo
    Mh1yEnrcRPkDdiFrwfRs6fm1FDRuPRS+nEr2zYZ3JwTrxxpq9b+giPKxWXlrPmkF
    yMQqqpTHQkxx5JO7dsXeUSDeOVgh6YpekzLIAXrVOZIaq4y89HZRCxGbJkTJ3GqO
    WxOFe4BCwfituOoVBmJRhRkCgYBMQs6naEdishYyDYNHP6D+SJh7WxYNrZCb6r2h
    qwcXSNURHyB8OJFRdJ1O7OxZ3LAjGvLBu8l3ml8nV/PMsHbXWahjMMARQdRxsMIP
    ttiVzLuAoQpu0wmI4CFhOiNZhxVz8k7xaNBy+QF88ivYDeO0kKCpX0JI3vgdXkb2
    kgu7wQKBgBXxBjofpwwsgAWKjKJ1X7RUCKBuYSkjzJzDK6smn6L9RxMcx4gvtHob
    XbvcbPY2FCqrc91Dba6jzuZb/7qPJnWC2g7f5vJaETH2zOcZjita2mUUHfA/a/VZ
    Pp8UvQVmr+oDa4tzxNQLTeHcIRifzkCVdegzPJQpcq7h1XIOZE/V
    -----END RSA PRIVATE KEY-----`;

	var issuer_priv_pem = `-----BEGIN PRIVATE KEY-----
	MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
	UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
	OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
	LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
	oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
	583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
	ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
	+NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
	lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
	PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
	OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
	3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
	pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
	uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
	GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
	bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
	sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
	QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
	qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
	EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
	MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
	30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
	MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
	o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
	QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
	YTdgkw8sWi3fZ9kH06PUPKs=
	-----END PRIVATE KEY-----`;


	var subject_pki = new jCastle.pki('rsa');
    subject_pki.parse(subject_priv_pem);

//    console.log('subject_pki.n: ', subject_pki.getPublicKey().n.toString(16));

	var issuer_pki = new jCastle.pki('rsa');
	issuer_pki.parse(issuer_priv_pem);

//    console.log('issuer_pki.n: ', issuer_pki.getPublicKey().n.toString(16));

	var cert = jCastle.certificate.create(); // or jCastle.x509Cert.create();
	cert.setSignKey(issuer_pki);


	var issuer = [{
		name: 'countryName',
		value: 'JP',
		type: jCastle.asn1.tagPrintableString
	}, {
		name: 'stateOrProvinceName',
		value: 'Tokyo'
		// type: jCastle.asn1.tagUTF8String // default
	}, {
		name: 'localityName',
		value: 'Chuo-ku'
	}, {
		name: 'organizationName',
		value: 'Frank4DD'
	}, {
		name: 'organizationalUnitName',
		value: 'WebCert Support'
	}, {
		name: 'commonName',
		value: 'Frank4DD Web CA'
	}, {
		name: 'emailAddress',
		value: 'support@frank4dd.com'
	}];

	var subject = [{
		name: 'countryName',
		value: 'JP',
		type: jCastle.asn1.tagPrintableString
	}, {
		name: 'stateOrProvinceName',
		value: 'Tokyo'
		// type: jCastle.asn1.tagUTF8String // default
	}, {
		name: 'organizationName',
		value: 'Frank4DD'
	}, {
		name: 'commonName',
		value: 'Frank4DD Web CA'
	}];


	var serial = new jCastle.prng().nextBytes(4);
	//serial = BigInteger.fromByteArrayUnsigned(serial);
    serial = parseInt('00' + serial.toString('hex'), 16);

	var cert_info = {
		type: jCastle.certificate.typeCRT,
		tbs: {
			serialNumber: serial,
			issuer: issuer,
			subject: subject,
			subjectPublicKeyInfo: subject_pki.getPublicKeyInfo()
		},
		algo: {
			signHash: 'SHA-256',
			signAlgo: 'RSASSA-PSS' // 'RSASSA-PKCS1-V1_5' // 'EC', 'DSA'
		}
	};

	//
	// RSASSA-PSS test
	//

	pem = cert.export(cert_info);
	// console.log(pem);
		

	cert_info = cert.parse(pem);
    // console.log(cert_info);

	var v = cert.verify(pem, issuer_pki);
	assert.ok(v, 'RSA certificate test for RSASSA-PSS');
    // console.log(v);

    // should be false for it is not self-signed.
	// var v = cert.verify(pem);
	// //assert.ok(v, 'RSA certificate test 2 for RSASSA-PSS');
    // console.log(v);

	assert.ok(subject_pki.publicKeyEquals(cert_info.tbs.subjectPublicKeyInfo.publicKey), "public key verify");
    //console.log(subject_pki.publicKeyEquals(cert_info.tbs.subjectPublicKeyInfo.publicKey));

});


//-------------------------------------------------------------------------------

QUnit.test("CRL Parsing Test", function(assert) {

    var crl_pem = `-----BEGIN X509 CRL-----
    MIIDFDCCAfwCAQEwDQYJKoZIhvcNAQEFBQAwXzEjMCEGA1UEChMaU2FtcGxlIFNp
    Z25lciBPcmdhbml6YXRpb24xGzAZBgNVBAsTElNhbXBsZSBTaWduZXIgVW5pdDEb
    MBkGA1UEAxMSU2FtcGxlIFNpZ25lciBDZXJ0Fw0xMzAyMTgxMDMyMDBaFw0xMzAy
    MTgxMDQyMDBaMIIBNjA8AgMUeUcXDTEzMDIxODEwMjIxMlowJjAKBgNVHRUEAwoB
    AzAYBgNVHRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SBcNMTMwMjE4MTAyMjIy
    WjAmMAoGA1UdFQQDCgEGMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFowPAIDFHlJ
    Fw0xMzAyMTgxMDIyMzJaMCYwCgYDVR0VBAMKAQQwGAYDVR0YBBEYDzIwMTMwMjE4
    MTAyMjAwWjA8AgMUeUoXDTEzMDIxODEwMjI0MlowJjAKBgNVHRUEAwoBATAYBgNV
    HRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SxcNMTMwMjE4MTAyMjUxWjAmMAoG
    A1UdFQQDCgEFMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFqgLzAtMB8GA1UdIwQY
    MBaAFL4SAcyq6hGA2i6tsurHtfuf+a00MAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEB
    BQUAA4IBAQBCIb6B8cN5dmZbziETimiotDy+FsOvS93LeDWSkNjXTG/+bGgnrm3a
    QpgB7heT8L2o7s2QtjX2DaTOSYL3nZ/Ibn/R8S0g+EbNQxdk5/la6CERxiRp+E2T
    UG8LDb14YVMhRGKvCguSIyUG0MwGW6waqVtd6K71u7vhIU/Tidf6ZSdsTMhpPPFu
    PUid4j29U3q10SGFF6cCt1DzjvUcCwHGhHA02Men70EgZFADPLWmLg0HglKUh1iZ
    WcBGtev/8VsUijyjsM072C6Ut5TwNyrrthb952+eKlmxLNgT0o5hVYxjXhtwLQsL
    7QZhrypAM1DLYqQjkiDI7hlvt7QuDGTJ
    -----END X509 CRL-----`;

    var crlList = [
    {
        userCertificate: 1341767,
        revocationDate: '2013-02-18 10:22:12 UTC',
        crlEntryExtensions: {
          cRLReason: 'affiliationChanged',
          invalidityDate: '2013-02-18 10:22:00 UTC'
        }
    },
    {
        userCertificate: 1341768,
        revocationDate: '2013-02-18 10:22:22 UTC',
        crlEntryExtensions: {
          cRLReason: 'certificateHold',
          invalidityDate: '2013-02-18 10:22:00 UTC'
        }
    },
    {
        userCertificate: 1341769,
        revocationDate: '2013-02-18 10:22:32 UTC',
        crlEntryExtensions: {
          cRLReason: 'superseded',
          invalidityDate: '2013-02-18 10:22:00 UTC'
        }
    },
    {
        userCertificate: 1341770,
        revocationDate: '2013-02-18 10:22:42 UTC',
        crlEntryExtensions: {
          cRLReason: 'keyCompromise',
          invalidityDate: '2013-02-18 10:22:00 UTC'
        }
    },
    {
        userCertificate: 1341771,
        revocationDate: '2013-02-18 10:22:51 UTC',
        crlEntryExtensions: {
          cRLReason: 'cessationOfOperation',
          invalidityDate: '2013-02-18 10:22:00 UTC'
        }
    }];
      

    var crlparser = new jCastle.certificate();
    var crl_info = crlparser.parse(crl_pem);

    //console.log(crl_info);
    for (var i = 0; i < crl_info.tbs.revokedCertificates.length; i++) {
        assert.ok(crl_info.tbs.revokedCertificates[i].userCertificate == crlList[i].userCertificate, 'crl serial test');
        assert.ok(crl_info.tbs.revokedCertificates[i].crlEntryExtensions.cRLReason == crlList[i].crlEntryExtensions.cRLReason, 'crl cRLReason test');
    }
});

QUnit.test("DEMO Test 2", function(assert) {

    // DEMO
    // JISCO - jCastle Internet & Security Company
    //
		
	var jisco_priv_pem = `-----BEGIN PRIVATE KEY-----
	MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
	UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
	OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
	LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
	oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
	583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
	ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
	+NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
	lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
	PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
	OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
	3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
	pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
	uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
	GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
	bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
	sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
	QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
	qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
	EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
	MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
	30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
	MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
	o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
	QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
	YTdgkw8sWi3fZ9kH06PUPKs=
	-----END PRIVATE KEY-----`;
		

	jisco_pki = new jCastle.pki('RSA');
	jisco_pki.parse(jisco_priv_pem);

    // console.log('JISCO - jCastle Internet & Security Company');
    // console.log('');
    // console.log('JISCO ROOT PEM: ');
	// console.log(jisco_pki.exportPrivateKey());
    // console.log('');

	// 2. create server private key
    // console.log('Creating server private key...');

	var srv_pki = new jCastle.pki('RSA');
	srv_pki.generateKeypair({
        bits: 2048, 
        exponent: 0x10001 // 65537
    });

    // console.log('Server Private Key PEM: ');
	// console.log(srv_pki.exportPrivateKey());

	// 3. create server CSR
    // console.log('Creating server CSR...');

	var srv_subject = [{
		name: 'C',
		value: 'kr'
	}, {
		name: 'O',
		value: 'demosign'
	}, {
		name: 'OU',
		value: 'demoCA'
	}, {
		name: 'CN',
		value: 'demoCA Class 1'
	}];

	var srv_algo = {
		signAlgo: 'RSASSA-PKCS1-V1_5',
		signHash: 'sha-256'
	};

	var srv_extensions = {
		basicConstraints: {
			cA: true
		},
		keyUsage: {
			critical: true,
			list: ['nonRepudiation', 'digitalSignature']
		}
	};

	var srv_cert = new jCastle.certificate().setSignKey(srv_pki);

	var srv_csr_pem = srv_cert.request({
		subject: srv_subject,
		algo: srv_algo,
		extensions: srv_extensions
	});

    // console.log('Server CSR PEM: ');
	// console.log(srv_csr_pem);
    // console.log('csr verify test: ', srv_cert.verify(srv_csr_pem, srv_pki));
    assert.ok(srv_cert.verify(srv_csr_pem, srv_pki), 'verify crl pem test');

	// 4. create server certificate
    // console.log('Creating server Certificate...');

	var jisco_cert = new jCastle.certificate().setSignKey(jisco_pki);

	var jisco_issuer = [{
		name: 'C',
		value: 'KR'
	}, {
		name: 'O',
		value: 'JISCO'
	}, {
		name: 'OU',
		value: 'Demo Certificate Authority Central'
	}, {
		name: 'CN',
		value: 'JISCO RootCA 1'
	}];

    var serial = new jCastle.prng().nextBytes(4);
    serial = parseInt('00' + serial.toString('hex'), 16);

	var srv_cert_pem = jisco_cert.issue(srv_csr_pem, {
		serialNumber: serial,
		issuer: jisco_issuer,
		algo: {
			signAlgo: 'RSASSA-PKCS1-V1_5',
			hashAlgo: 'sha-256'
		},
		extensions: {
			subjectKeyIdentifier: "hash",
//			authorityKeyIdentifier: {
//				keyIdentifier: "always",
//				authorityCertIssuer: "always"
//			}
		}
	});

    // console.log('Server Certificate PEM:');
	// console.log(srv_cert_pem);

	var cert_info = new jCastle.certificate().parse(srv_cert_pem);

    // console.log(cert_info);

    // console.log(new jCastle.certificate().validate(srv_cert_pem));
    // console.log(new jCastle.certificate().verify(srv_cert_pem, jisco_pki.getPublicKeyInfo()));
    // console.log(cert_info.tbs.subjectPublicKeyInfo.publicKey.n.equals(srv_pki.getPublicKey().n));
    assert.ok(new jCastle.certificate().validate(srv_cert_pem), 'validate cert pem test');
    assert.ok(new jCastle.certificate().verify(srv_cert_pem, jisco_pki.getPublicKeyInfo()), 'verify cert pem test');
    assert.ok(cert_info.tbs.subjectPublicKeyInfo.publicKey.n.equals(srv_pki.getPublicKey().n), 'subject pki equal test');

});

QUnit.test("With RSA Test", function(assert) {

		
	var private_pem = `-----BEGIN PRIVATE KEY-----
	MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
	UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
	OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
	LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
	oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
	583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
	ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
	+NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
	lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
	PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
	OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
	3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
	pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
	uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
	GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
	bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
	sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
	QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
	qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
	EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
	MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
	30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
	MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
	o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
	QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
	YTdgkw8sWi3fZ9kH06PUPKs=
	-----END PRIVATE KEY-----`;
		

	var rsa = new jCastle.pki('RSA');
	rsa.parse(private_pem);

	//var cert = rsa.Certificate.parsePEM(certificate);

	//console.log(cert);


	var serial = 3579;

	var issuer = [{
		name: 'countryName',
		value: 'JP',
		type: jCastle.ASN1.tagPrintableString
	}, {
		name: 'stateOrProvinceName',
		value: 'Tokyo'
		// type: jCastle.ASN1.tagUTF8String // default
	}, {
		name: 'localityName',
		value: 'Chuo-ku'
	}, {
		name: 'organizationName',
		value: 'Frank4DD'
	}, {
		name: 'organizationalUnitName',
		value: 'WebCert Support'
	}, {
		name: 'commonName',
		value: 'Frank4DD Web CA'
	}, {
		name: 'emailAddress',
		value: 'support@frank4dd.com'
	}];

	var subject = [{
		name: 'countryName',
		value: 'JP',
		type: jCastle.ASN1.tagPrintableString
	}, {
		name: 'stateOrProvinceName',
		value: 'Tokyo'
		// type: jCastle.ASN1.tagUTF8String // default
	}, {
		name: 'organizationName',
		value: 'Frank4DD'
	}, {
		name: 'commonName',
		value: 'Frank4DD Web CA'
	}];


	// self-signed certificate

	var cert_info = {
		type: jCastle.certificate.typeCRT,
		tbs: {
			serialNumber: serial,
			issuer: issuer,
			subject: subject,
			subjectPublicKeyInfo: rsa.getPublicKeyInfo()
		},
		algo: {
			signHash: 'SHA-256',
			signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'EC', 'DSA'
		}
	};


//	console.log(jCastle.util.clone(cert_info));

	var cert = new jCastle.certificate();
	cert.setSignKey(rsa);

	pem = cert.exportCertificate(cert_info);
	// console.log(pem);
		

	cert_info = cert.parse(pem);
	// console.log(cert_info);

	var v = cert.verify(pem, rsa);
	assert.ok(v, 'RSA certificate test for RSASSA-PKCS1-V1_5');
	// console.log(v);

	// this certificate is self-signed. so it should be true.
	var v = cert.verify(pem);
	assert.ok(v, 'RSA certificate test 2 for RSASSA-PKCS1-V1_5');
	// console.log(v);

	//
	// RSASSA-PSS test
	//

	cert_info.algo.signAlgo = 'RSASSA-PSS';

	pem = cert.exportCertificate(cert_info);
	// console.log(pem);
		

	cert_info = cert.parse(pem);
	// console.log(cert_info);

	var v = cert.verify(pem, rsa);
	assert.ok(v, 'RSA certificate test for RSASSA-PSS');
	// console.log(v);

	var v = cert.verify(pem);
	assert.ok(v, 'RSA certificate test 2 for RSASSA-PSS');
	// console.log(v);

	//
	// RSASSA-PKCS1-V1_5 with OAEP publickey info
	//
	var cert_info2 = jCastle.util.clone(cert_info);

	cert_info2.algo.signAlgo = 'RSASSA-PKCS1-V1_5';

	cert_info2.tbs.subjectPublicKeyInfo.padding = {
		mode: 'RSAES-OAEP',
		hashAlgo: 'SHA-256',
		label: Buffer.from('jacob lee')
	};

//	console.log(cert_info);

	pem = cert.exportCertificate(cert_info2);
	// console.log(pem);
		

	cert_info2 = cert.parse(pem);
    // console.log(cert_info2);

	var v = cert.verify(pem, rsa);
	assert.ok(v, 'RSA certificate test for RSASSA-PKCS1-V1_5 with OAEP public key info');
	// console.log(v);

	var v = cert.verify(pem);
	assert.ok(v, 'RSA certificate test 2 for RSASSA-PKCS1-V1_5 with OAEP public key info');
	// console.log(v);


});

//----------------------------------------------------------------------------------------------------

QUnit.test("With DSA Test", function(assert) {

    
    var dsa = new jCastle.pki('DSA');
    
    var cert_pem = `-----BEGIN CERTIFICATE-----
    MIIDbjCCAtcCAg4BMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
    A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
    MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
    YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
    ODIyMDcyNzAyWhcNMTcwODIxMDcyNzAyWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
    CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
    ZS5jb20wggG2MIIBKwYHKoZIzjgEATCCAR4CgYEAmSdK1oKHlcz+2aa63qxw3347
    cItRrI49rf2fuz1IJcADUWQ1W2pi/bk/LqLNeLS7cUc3DLSooaLYZJ+8bmmnqr1S
    Bg7ni00PnHxFVTyomf4OHDu4Req8HEEZcehSpkrAXXTlN1lWaxtTh/+F/C6kRELD
    fvK6HTR11UYBntTcxiUCFQCdQJzgURWm7BUEJEDzy6dW2jW7mwKBgFPwcr3ho1gr
    SLK3VyPOMxYn/ExA9JchE0rSZgcOe+EBLCsJj/wHI6ZZzIgX4v8NmmLMi5aBtnnb
    F/dagOXL8BMysKrQ/PJ0qh7G6S9/rmJjfdLei1wjQ99UKxx220Xk8EiFC3NXhsLM
    2DSVNQSh5ZUrAt+UQGv6KfHbrTTjdAHIA4GEAAKBgD6YUIH2lRbFWqp3shUnd7hw
    io9mJi7WBh9aDvi7uWlzlIeXmpRlKwen1hxV6kIF0R46Qe8rAKCLfKq9RtEQuTu2
    EI1oCXn3mszuuERLpVI2ToMep98zTySakoCnT0hZf+nclywamDO78IgWwfyS85ip
    ghBRDQdlNDGm7e6yL2QhMA0GCSqGSIb3DQEBBQUAA4GBAAfRwpqyBJhFbhLacmJM
    cw/Z9l9a77lboFk2U7IbaPuSkcC1V8tou5cM/95SEjQlfv9yusU0xGicNgFF0+Ws
    lQaoZde0jGRMltpwAjjsY9EcGGFMLwmkAl7UX3uUiUPZXxs1tFQS9RsMlQJGQP29
    cds7DZAFX3gv9QXKhM9Stoiv
    -----END CERTIFICATE-----`;

    var cert_info = new jCastle.certificate().parse(cert_pem);

    // console.log(cert_info);
    // console.log(cert_info.tbs.subjectPublicKeyInfo.parameters);



    //----------------------------------------------------------------------------------------------------


    var dsa = new jCastle.pki('DSA');

    // self-signed certificate test

    var priv_pem = `-----BEGIN PRIVATE KEY-----
    MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCNeyl5qEhsOkV9LFYGfSVS4Hv0
    Zc5SpjTIGpT5B89asry1jUReAQcCl3XXdv4PeKGTMgS2v+NYpa4cjWcF/Hsa7o1o
    2t+HtNuIUC9hN9cgeS9pEbh53Aou0V7Z8Ug+FqqW+26jTjN2EIx3JRxB6tjVo6Km
    flDh2MJiVa9rLSnEpXdDbH9kTcybnBuJCspxcPyNLMC73v12CuZUMluXHdBqvOfL
    MF5yVnuDxE0J3Pev0DqG5p9DROEIDFSudrV93/qXGiOzlEJhXmbzehrbLiVg4Ia2
    +Id45CZjdaeiIyqopUbf85if0eU4TUZxOzMnA1pr+ejhwpqVOgDElbsXopyJAiEA
    lQY0J2PHOADuLbk4/QSt7rRU/4o7kc/BRVFsq0G5Gv8CggEASaQxcQCn9i8KHvSx
    q/NaejtOrm0ayrh5TfDpDXZrUYo52tHsBLh0HJpR8sKjfN0i5jz8tEvOf7rVEwc1
    tReHYWa3gsJXBNGakIj0i/HuVoNn2pcugBp0VEGvcHHequAjJoeyQkFKyrMbyWR0
    q5/qGEzUz9421CysX1HWxyT7k85aoVi8PY8o166G1c01F5gTg8mavVeZo1VYivOv
    vPraqB4LewSQVsGubiBCPDCYFxmAPjIzbSbqqbZm+s6KnCxczCQSY/mhzcFFnIuJ
    PfoIGBW+ySP1rJHXLR6sWupeW08LLOLwlfJ/weCNBwyuEtsE7cGfQbp5AE/8xCIs
    S6RgDAQiAiBmd4A7+8gZlyMrnyeB9pShisfymx1864UrLANmOtuB8A==
    -----END PRIVATE KEY-----`;


    var cert_pem = `-----BEGIN CERTIFICATE-----
    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
    -----END CERTIFICATE-----`;


    var cert_info = new jCastle.certificate().parse(cert_pem);

    // console.log(cert_info);

    dsa.parsePrivateKey(priv_pem);

    assert.ok(jCastle.certificate.create().verify(cert_pem, dsa), "DSA verify certificate Test");
    // console.log(jCastle.certificate.create().verify(cert_pem, dsa));

//----------------------------------------------------------------------------------------------------




    // self-signed certificate test

    var priv_pem = `-----BEGIN PRIVATE KEY-----
    MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCNeyl5qEhsOkV9LFYGfSVS4Hv0
    Zc5SpjTIGpT5B89asry1jUReAQcCl3XXdv4PeKGTMgS2v+NYpa4cjWcF/Hsa7o1o
    2t+HtNuIUC9hN9cgeS9pEbh53Aou0V7Z8Ug+FqqW+26jTjN2EIx3JRxB6tjVo6Km
    flDh2MJiVa9rLSnEpXdDbH9kTcybnBuJCspxcPyNLMC73v12CuZUMluXHdBqvOfL
    MF5yVnuDxE0J3Pev0DqG5p9DROEIDFSudrV93/qXGiOzlEJhXmbzehrbLiVg4Ia2
    +Id45CZjdaeiIyqopUbf85if0eU4TUZxOzMnA1pr+ejhwpqVOgDElbsXopyJAiEA
    lQY0J2PHOADuLbk4/QSt7rRU/4o7kc/BRVFsq0G5Gv8CggEASaQxcQCn9i8KHvSx
    q/NaejtOrm0ayrh5TfDpDXZrUYo52tHsBLh0HJpR8sKjfN0i5jz8tEvOf7rVEwc1
    tReHYWa3gsJXBNGakIj0i/HuVoNn2pcugBp0VEGvcHHequAjJoeyQkFKyrMbyWR0
    q5/qGEzUz9421CysX1HWxyT7k85aoVi8PY8o166G1c01F5gTg8mavVeZo1VYivOv
    vPraqB4LewSQVsGubiBCPDCYFxmAPjIzbSbqqbZm+s6KnCxczCQSY/mhzcFFnIuJ
    PfoIGBW+ySP1rJHXLR6sWupeW08LLOLwlfJ/weCNBwyuEtsE7cGfQbp5AE/8xCIs
    S6RgDAQiAiBmd4A7+8gZlyMrnyeB9pShisfymx1864UrLANmOtuB8A==
    -----END PRIVATE KEY-----`;

    var serial = 3579;

    var issuer = [{
        name: 'countryName',
        value: 'JP',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Tokyo'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'localityName',
        value: 'Chuo-ku'
    }, {
        name: 'organizationName',
        value: 'Frank4DD'
    }, {
        name: 'organizationalUnitName',
        value: 'WebCert Support'
    }, {
        name: 'commonName',
        value: 'Frank4DD Web CA'
    }, {
        name: 'emailAddress',
        value: 'support@frank4dd.com'
    }];

    var subject = [{
        name: 'countryName',
        value: 'JP',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Tokyo'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'organizationName',
        value: 'Frank4DD'
    }, {
        name: 'commonName',
        value: 'Frank4DD Web CA'
    }];


    var pkey = new jCastle.pki('DSA');
    pkey.parsePrivateKey(priv_pem);

    var cert_info = {
        type: jCastle.certificate.typeCRT,
        tbs: {
            serialNumber: serial,
            issuer: issuer,
            subject: subject,
            subjectPublicKeyInfo: dsa.getPublicKeyInfo()
        },
        algo: {
            signHash: 'SHA-256',
            signAlgo: 'DSA'
        }
    };

    // console.log(pkey);

    var cert_pem = new jCastle.certificate().setSignKey(pkey).exportCertificate(cert_info);

    var cert_info2 = new jCastle.certificate().parse(cert_pem);

    // console.log(cert_info2);

    assert.ok(new jCastle.certificate().verify(cert_pem, pkey), "DSA verify self-signed certificate Test");
    // console.log(new jCastle.certificate().verify(cert_pem, pkey));
    



});

//----------------------------------------------------------------------------------------------------

QUnit.test("With ECDSA Test", function(assert) {
    

    var cert_pem = `-----BEGIN CERTIFICATE-----
    MIICXjCCAccCAg4GMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
    A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
    MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
    YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
    OTI3MTMwMDE0WhcNMTcwOTI2MTMwMDE0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
    CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
    ZS5jb20wgacwEAYHKoZIzj0CAQYFK4EEACcDgZIABAIZ0Rc0Y3jsqPqqptRz3tiS
    AuvTHA9vUigM2gUjM6YkTKofP7RRls4dqt6aM7/1eLbFg4Jdh9DXS4zU1EFeiZQZ
    +drSQYAmAgAtTzpmtmUoy+miwtiSBomu3CSUe6YrVvWb+Oirmvw2x3BCTJW2Xjhy
    5y6tDPVRRyhg0nh5wm/UxZv4jo7AZuJV8ztZKwCEADANBgkqhkiG9w0BAQUFAAOB
    gQBlaOF5O4RyvDQ1qCAuM6oXjmL3kCA3Kp7VfytDYaxbaJVhC8PnE0A8VPX2ypn9
    aQR4yq98e2umPsrSL7gPddoga+OvatusG9GnIviWGSzazQBQTTQdESJxrPdDXE0E
    YF5PPxAO+0yKGqkl8PepvymXBrMAeszlHaRFXeRojXVALw==
    -----END CERTIFICATE-----`;    

    var cert_info = new jCastle.certificate().parse(cert_pem);

    // console.log(cert_info);


    //----------------------------------------------------------------------------------------------------


    var cert_pem = `-----BEGIN CERTIFICATE-----
    MIIBOTCB4KADAgECAgEBMAoGCCqGSM49BAMCMB4xHDAJBgNVBAYTAlJVMA8GA1UE
    Ax4IAFQAZQBzAHQwHhcNMTMwMjAxMDAwMDAwWhcNMTYwMjAxMDAwMDAwWjAeMRww
    CQYDVQQGEwJSVTAPBgNVBAMeCABUAGUAcwB0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    AQcDQgAE7kM0cycsMDqJklaHEJIJQjgsT8J5Bbb9lEdVAJd8wozsLz8TlLAKHjUu
    de+bAFr1NHW9YgBc55KP2D+12LH1IqMPMA0wCwYDVR0PBAQDAgACMAoGCCqGSM49
    BAMCA0gAMEUCICm4AR4qHakFXmTk74lezPZ8Ab1PdgjSGDUePwXskQo6AiEAigW4
    bOJDAJDn0lzw81CgI2eD+VWV7nj0n3xSFHKNK1g=
    -----END CERTIFICATE-----`;


    var cert_info = new jCastle.certificate().parse(cert_pem);

    // console.log(cert_info);


    var pkey = new jCastle.pki('ECDSA');

    // console.log(cert_info.tbs.subjectPublicKeyInfo);

    pkey.setPublicKey(cert_info.tbs.subjectPublicKeyInfo.publicKey, cert_info.tbs.subjectPublicKeyInfo.parameters);

    var v = new jCastle.certificate().verify(cert_pem, pkey);

    assert.ok(v, "ECDSA Verifying certificate test");
    // console.log(v);


});