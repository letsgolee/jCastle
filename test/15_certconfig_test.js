
const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('Cert-Config');
QUnit.test('Parsing test', assert => {

    const testoid1 = '1.2.3.4';
    const openssl_inf = `
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
    # testoid2=${testoid1}.5.6
    
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
    authorityKeyIdentifier=keyid,issuer:always
    
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
    basicConstraints = critical, bs_section
    
    keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, decipherOnly
    
    authorityKeyIdentifier = keyid,issuer
    
    #subjectAltName=email:copy,email:my@other.address.ma,IP:192.168.7.1,URI:http://my.url.here/
    #subjectAltName=email:copy,email:my@other.address.ma,IP:2013::bf05:17,RID:1.2.3.4,URI:http://my.url.here/
    #subjectAltName=email:copy,email:my@other.address.ma,IP:2013::bf05:17,RID:1.2.3.4,URI:http://my.url.here/,otherName:1.2.3.4;UTF8:some other identifier
    
    subjectAltName = subject_alt_section
    
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
    nsSslServerName  = \$ENV::SSL_FQDN
    
    
    
    
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
    
    #otherName = 1.3.6.1.4.1.1;UTF8:some other identifier
    otherName = 1.3.6.1.4.1.1.;SEQUENCE:seq_section
    
    
    [subject_alt_section]
    
    otherName=1.2.410.200004.10.1.1;SEQUENCE:npki_sec1
    
    [npki_sec1]
    field1 = UTF8:jacob lee
    field2 = SEQUENCE:npki_sec2
    
    [npki_sec2]
    field1 = SEQUENCE:npki_sec3
    
    [npki_sec3]
    field1 = OID:1.2.410.200004.10.1.1.1
    field2 = SEQUENCE:npki_sec4
    
    [npki_sec4]
    field1 = SEQUENCE:npki_sec5
    field2 = EXPLICIT:0,npki_sec6
    
    
    [npki_sec5]
    field1 = OID:2.16.840.1.101.3.4.2.1
    
    [npki_sec6]
    field1 = OCTET:DER:49800B859C322622E0F3A27F8E77463EF60663ACC773953AA6D640BF166C738E
    
    [seq_section]
    
    field1 = UTF8:Some other name 1
    field2 = UTF8:Some other name 2
    field3 = SEQUENCE:seq_section2
    
    [seq_section2]
    
    field1 = UTF8:Some other name 3;
    
    [ v3_ca ]
    
    
    # Extensions for a typical CA
    
    
    # PKIX recommendation.
    
    subjectKeyIdentifier=hash
    
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
    var parser = jCastle.certConfig.create();

    var config = parser.parse(openssl_inf);

    assert.equal(config.v3_req.subjectAltName[0].value.name, '1.2.410.200004.10.1.1', 'Parsing Test');

    assert.equal(config.v3_req.subjectAltName[0].value.items[1].items[0].items[0].value, '1.2.410.200004.10.1.1.1', 'Parsing Test');

    assert.equal(config.v3_req.subjectAltName[0].value.items[1].items[0].items[1].items[0].items[0].value, '2.16.840.1.101.3.4.2.1', 'Parsing Test');

    assert.equal(config.v3_req.issuerAltName[5].value.items[2].items[0].value, 'Some other name 3;', 'Parsing Test');
});