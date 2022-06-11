/**
 * A Javascript implemenation of Certificate Configuration Parser
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee. All rights reserved.
 */

var jCastle = require('./jCastle');
require('./util');
require('./lang/en');
require('./error');
require('./oid');

/**
 * A parser for OpenSSL's configuration file(cnf).
 * 
 */
jCastle.certConfig = class
{
	constructor()
	{
		this.contents = null;
		this.subSections = [];
		this.envVariables = [];
	}

/*
CONFIGURATION FILE FORMAT
=========================

The configuration options are specified in the req section of the configuration file.
As with all configuration files if no value is specified in the specific section
(i.e. req) then the initial unnamed or default section is searched too.

The options available are described in detail below.

input_password output_password
------------------------------

The passwords for the input private key file (if present) and the output private key
file (if one will be created). The command line options passin and passout override
the configuration file values.

default_bits
------------

This specifies the default key size in bits. If not specified then 512 is used.
It is used if the -new option is used. It can be overridden by using the -newkey option.

default_keyfile
---------------

This is the default filename to write a private key to. If not specified 
the key is written to standard output. This can be overridden by the -keyout option.

oid_file
--------

This specifies a file containing additional OBJECT IDENTIFIERS. Each line of the file
should consist of the numerical form of the object identifier followed by white space
then the short name followed by white space and finally the long name.

oid_section
-----------

This specifies a section in the configuration file containing extra object identifiers.
Each line should consist of the short name of the object identifier followed 
by = and the numerical form. The short and long names are the same when this option is used.

RANDFILE
--------

This specifies a filename in which random number seed information is placed and 
read from, or an EGD socket (see RAND_egd). It is used for private key generation.

encrypt_key
-----------

If this is set to no then if a private key is generated it is not encrypted. 
This is equivalent to the -nodes command line option. For compatibility 
encrypt_rsa_key is an equivalent option.

default_md
----------

This option specifies the digest algorithm to use. Any digest supported by the OpenSSL
dgst command can be used. If not present then MD5 is used. This option can be 
overridden on the command line.

string_mask
-----------

This option masks out the use of certain string types in certain fields. Most users
will not need to change this option.

It can be set to several values default which is also the default option uses
PrintableStrings, T61Strings and BMPStrings if the pkix value is used then only 
PrintableStrings and BMPStrings will be used. This follows the PKIX recommendation
in RFC2459. If the utf8only option is used then only UTF8Strings will be used: 
this is the PKIX recommendation in RFC2459 after 2003. Finally the nombstr option 
just uses PrintableStrings and T61Strings: certain software has problems with 
BMPStrings and UTF8Strings: in particular Netscape.

req_extensions
--------------

this specifies the configuration file section containing a list of extensions 
to add to the certificate request. It can be overridden by the -reqexts command line
switch. See the x509v3_config manual page for details of the extension section format.

x509_extensions
---------------

this specifies the configuration file section containing a list of extensions to add 
to certificate generated when the -x509 switch is used. It can be overridden 
by the -extensions command line switch.

prompt
------

if set to the value no this disables prompting of certificate fields and just takes
values from the config file directly. It also changes the expected format of
the distinguished_name and attributes sections.

utf8
----

if set to the value yes then field values to be interpreted as UTF8 strings,
by default they are interpreted as ASCII. This means that the field values,
whether prompted from a terminal or obtained from a configuration file, must be 
valid UTF8 strings.

attributes
----------

this specifies the section containing any request attributes: its format is the same
as distinguished_name. Typically these may contain the challengePassword or 
unstructuredName types. They are currently ignored by OpenSSL's request signing 
utilities but some CAs might want them.

distinguished_name
------------------

This specifies the section containing the distinguished name fields to prompt 
for when generating a certificate or certificate request. The format is described
in the next section.
*/
	/**
	 * resets internal variables.
	 * 
	 * @public
	 */
	reset()
	{
		this.contents = null;
		this.subSections = [];
		this.envVariables = [];
	}

	/**
	 * parses OpenSSL's cnf content string.
	 * @public
	 * 
	 * @param {string} cnf_content OpenSSL's cnf content string.
	 * @param {object} env_variables environmental variables.
	 * 
	 * @returns the parsed configuration object.
	 */
	parse(cnf_content, env_variables)
	{
		this.reset();

		var cnf_str;

		if (Buffer.isBuffer(cnf_content)) cnf_str = cnf_content.toString();
		else cnf_str = cnf_content;

		if (!jCastle.util.isString(cnf_str)) {
			throw jCastle.exception("INVALID_CONFIG", 'CCG001');
		}

		if (typeof env_variables == 'object') {
			for (var item in env_variables) {
				var it = item.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&");
				cnf_str = cnf_str.replace(new RegExp(it, 'g'), env_variables[item]);
			}
		}

		this._buildConfig(cnf_str);

		return this.contents;
	}

	/**
	 * real parser.
	 * @private
	 * 
	 * @param {string} content content string to be parsed.
	 */
	_buildConfig(content)
	{
		this.contents = {};

		// important!
		// first we have to parse to the end and find all sections
		// then each line will be parsed again to get value etc.
		// for all sections must be known first.

		// set type
		this.contents.type = 'CONFIG';

		var lines = content.split("\n");
		var section = '';
		var str_continue = false;
		var key = '';
		var value = '';
		var sections = [];
		var string_keys = [];

		for (var i = 0; i < lines.length; i++) {
			var line = lines[i];
			
			// remove comment
			var pos = line.indexOf('#');
			if (pos == 0) continue;
			// be careful! if pos is -1 then it gives true.
			if (pos > 0) line = line.substr(0, pos - 1);

			if (str_continue) {
				if (/\\$/.test(line)) {
					value += line.replace(/\\$/, '');
				} else {
					str_continue = false;
					value += line;
					if (section.length) {
						//this.contents[section][key] = this._parseValue(key, value, section);
						this.contents[section][key] = value;
					} else {
						this.contents[key] = value;
						string_keys.push(key);
					}
				}
				continue;
			}

			line = line.trim();
			
			// empty or comment
			if (!line.length) continue;

			var m = /^\[(.*)\]$/.exec(line);

			if (m) {
				section = m[1].trim();
				continue;
			}

			if (line.indexOf('=') === -1) continue;

			var t = line.split('=', 2);

			if (section.length) {
				//if (!this.contents.hasOwnProperty(section)) this.contents[section] = {};
				if (!(section in this.contents)) this.contents[section] = {};
				sections.push(section);

				key = t[0].trim();

				// key name change
				switch (key) {
					case 'extendedKeyUsage':		key = 'extKeyUsage'; break;
					case 'crlDistributionPoints':	key = 'cRLDistributionPoints'; break;
					case 'noCheck':					key = 'ocspNoCheck'; break;
					case 'nsBaseUrl':				key = 'netscape-base-url'; break;
					case 'nsRevocationUrl':			key = 'netscape-revocation-url'; break;
					case 'nsCaRevocationUrl':		key = 'netscape-ca-revocation-url'; break;
					case 'nsRenewalUrl':			key = 'netscape-cert-renewal-url'; break;
					case 'nsCaPolicyUrl':			key = 'netscape-ca-policy-url'; break;
					case 'nsSslServerName':			key = 'netscape-ssl-server-name'; break;
					case 'nsComment':				key = 'netscape-comment'; break;
					case 'nsCertType':				key = 'netscape-cert-type'; break;
				}


				value = t[1].trim();

				if (/\\$/.test(value)) {
					value = value.replace(/\\$/, '');
					str_continue = true;
					continue;
				}

				//this.contents[section][key] = this._parseValue(key, value, section);
				this.contents[section][key] = value;
			} else {
				key = t[0].trim();
				value = t[1].trim();

				if (/\\$/.test(value)) {
					value = value.replace(/\\$/, '');
					str_continue = true;
					continue;
				}

				//this.contents[key] = this._parseValue(key, value, section);
				this.contents[key] = value;
			}
		}

		// now we know all sections
		// parse all values
		for (var property in this.contents) {
			//if (jCastle.util.inArray(property, sections)) {
			if (sections.includes(property)) {
				for (var key in this.contents[property]) {
					var value = this.contents[property][key];
					var section = property;
					this.contents[section][key] = this._parseValue(key, value, section);
				}			
			//} else if (jCastle.util.inArray(property, string_keys)) {
			} else if (string_keys.includes(property)) {
				continue;
			} else {
				var value = this.contents[property];
				this.contents[property] = this._parseValue(property, value, null);
			}
		}


		// search env variables
		this._searchEnvVariables(this.contents);

		// replace strings registerd in env_variables...
		this._replaceEnvVariables(this.contents);


//console.log(this.subSections);

		for (var i = 0; i < this.subSections.length; i++) {
			this._parseSubSection(this.subSections[i]);
		}

		// section link in sub section
		for (var i = 0; i < this.subSections.length; i++) {
			this._linkSubSection(this.contents[this.subSections[i]]);
		}

//console.log(this.contents);

		// correct values according to each key
		this._parseAccordingKeys();

		// section link in sections except sub sections
		for (var i in this.contents) {
			if (jCastle.util.isString(this.contents[i]) && this._isSectionLink(this.contents[i])) {
				this.contents[i] = this._getSection(this.contents[i]);
			} else {
				this._linkSubSection(this.contents[i]);
			}
		}

		// remove sub_sections
		for (var i = 0; i < this.subSections.length; i++) {
			delete this.contents[this.subSections[i]];
		}
	}

	/**
	 * recursive function for searching environmental variables
	 * @private
	 * 
	 * @param {object} section a section object.
	 */
	_searchEnvVariables(section)
	{
		// if (typeof section == 'undefined') section = this.contents;
		if (!section) return;

		for (var s in section) {
			//if (jCastle.util.inArray(s, this.subSections)) continue;
			if (this.subSections.includes(s)) continue;

			if (jCastle.util.isString(section[s])) {
				//var m = /\$([a-z\_]+([a-z\_0-9]+)?)/i.exec(section[s]);
				var m = /\$([a-z\_][a-z\_0-9]+)/i.exec(section[s]);
				if (!m) continue;

				if (!(m[1] in section) && !(m[1] in this.contents)) continue;

				var registered = false;
				for (var i = 0; i < this.envVariables.length; i++) {
					if (this.envVariables[i].name == m[1]) {
						registered = true;
						break;
					}
				}

				if (!registered) {
					this.envVariables.push({
						name: m[1],
						value: section[m[1]]
					});
				}
			} else {
				this._searchEnvVariables(section[s]);
			}
		}
	}

	_replaceEnvVariables(section)
	{
		//if (typeof section == 'undefined') section = this.contents;
		if (!section) return;

		for (var s in section) {
			//console.log(s, this.subSections.includes(s));
			//if (jCastle.util.inArray(s, this.subSections)) continue;
			if (this.subSections.includes(s)) continue;

			if (jCastle.util.isString(section[s])) {
				for (var i = 0; i < this.envVariables.length; i++) {
					section[s] = section[s].replace('$'+this.envVariables[i].name, this.envVariables[i].value);
				}
			} else {
				this._replaceEnvVariables(section[s]);
			}
		}	
	}

	_isSectionLink(value)
	{
		if (!jCastle.util.isString(value)) return false;

		value = value.trim();

// let's allow section names without having '@' as a prefix!
//		if (!/^(@)?([a-z\_0-9]+)$/i.test(value)) return false;

		if (value.indexOf('@') == 0) value = value.substr(1);

		return value in this.contents && typeof this.contents[value] == 'object';
	}

	_addToSubSection(section)
	{
		if (section.indexOf('@') == 0) section = section.substr(1);

		//if (!jCastle.util.inArray(section, this.subSections)) {
		if (!this.subSections.includes(section)) {
			//console.log(section, 'is added...');
			this.subSections.push(section);
		}
	}

	_parseValue(key, value, section)
	{
		switch (key) {
			case 'subjectKeyIdentifier':
			case 'nsBaseUrl':
			case 'nsRevocationUrl':
			case 'nsCaRevocationUrl':
			case 'nsRenewalUrl':
			case 'nsCaPolicyUrl':
			case 'nsSslServerName':
			case 'nsComment':
			case 'netscape-base-url':
			case 'netscape-revocation-url':
			case 'netscape-ca-revocation-url':
			case 'netscape-cert-renewal-url':
			case 'netscape-ca-policy-url':
			case 'netscape-ssl-server-name':
			case 'netscape-comment':
				// string
				// nsComment = "some comment here"
				if (/^("|')(.*)("|')$/.test(value)) return value.substr(1, value.length - 2);
				return value;
			case 'basicConstraints':
			case 'keyUsage':
			case 'extendedKeyUsage':
			case 'extKeyUsage':
			case 'nsCertType':
			case 'netscape-cert-type':
			case 'authorityInfoAccess':
			case 'authorityKeyIdentifier':
			case 'cRLDistributionPoints':
			case 'crlDistributionPoints':
			case 'issuingDistributionPoint':
			case 'certificatePolicies':
			case 'policyConstraints':
			case 'inhibitAnyPolicy':
			case 'nameConstraints':
			case 'ocspNoCheck':
			case 'noCheck':
				//critical, CA:TRUE, pathlen:0
				var options = {};
				var opt = value.split(',');
				for (var i = 0; i < opt.length; i++) {
					var v = opt[i].split(':');
					var k = v[0].trim();

					if (v.length == 1) {
						//if (/^(@)([a-z\_0-9]+)$/i.test(k)) {
						if (this._isSectionLink(k)) {
							this._addToSubSection(k);
						}
						options[k] = null;
					} else {
						v.shift();
						v = v.join(':');
						v = v.trim();
						//if (/^(@)([a-z\_0-9]+)$/i.test(v)) {
						if (this._isSectionLink(v)) {
							this._addToSubSection(v);
						}
						options[k] = this._realValue(v);
					}
				}

				return options;
			case 'subjectAltName':
			case 'issuerAltName':
				var options = [];
				var opt = value.split(',');
				for (var i = 0; i < opt.length; i++) {
					var v = opt[i].split(':');
					var k = v[0].trim();

					if (v.length == 1) {
						//if (/^(@)([a-z\_0-9]+)$/i.test(k)) {
						if (this._isSectionLink(k)) {
							this._addToSubSection(k);
						}
						var o = {};
						o[k] = null;
						options.push(o);
					} else {
						v.shift();
						v = v.join(':');
						v = v.trim();
						//if (/^(@)([a-z\_0-9]+)$/i.test(v)) {
						if (this._isSectionLink(v)) {
							this._addToSubSection(v);
						}
						var o = {};
						o[k] = this._realValue(v);
						options.push(o);
					}
				}

				return options;
			// these keys are always have sub sections.
			// we will treat later...
			case 'oid_section':
			case 'default_ca':
			case 'policy':
			case 'distinguished_name':
			case 'x509_extensions':
			case 'req_extensions':
				return this._realValue(value);
			default:
				if (/^("|')(.*)("|')$/.test(value)) return value.substr(1, value.length - 2);

				//if (/^(@)([a-z\_0-9]+)$/i.test(value)) {
				if (this._isSectionLink(value)) {
					this._addToSubSection(value);
				}
				return this._realValue(value);
		}
	}

	_parseSubSection(section_name)
	{
		var section = this.contents[section_name];
		var res = {};

		for (var key in section) {
			var value = section[key];
			switch(key) {
				// basicConstraints
				case 'CA':
					res['cA'] = value;
					break;
				case 'pathlen':
					res['pathLenConstraint'] = value;
					break;

				// cRLDistributionPoints
				// issuingDistributionPoint
				case 'reasons':
				case 'onlysomereasons':
					var v = value.split(',');
					v = v.map(function(s) {return s.trim();});
					res[key] = v;
				break;

				// cRLDistributionPoints
				case 'fullname':
				case 'CRLissuer':
					var v = value.split(':');
					var k = v.shift();
					v = v.join(':');
					res[key] = {};
					res[key][k] = v;
					break;

				// certificatePolicies
				case 'CPS':
				case 'userNotice':
					//if (typeof res[key] == 'undefined') res[key] = [];
					if (!(key in res)) res[key] = [];
					res[key].push(value);
					break;
				case 'noticeNumbers':
					var v = value.split(',');
					v = v.map(function(s) {return parseInt(s, 10); });
					res[key] = v;
					break;

				// subjectAltName
				// issuerAltName
				case 'DNS':
				case 'IP':
				case 'RID':
				case 'URI':
				case 'dirName':
				case 'email':
				case 'otherName':
					//if (!jCastle.util.isArray(res)) res = [];
					if (!Array.isArray(res)) res = [];

					// otherName=1.2.410.200004.10.1.1;SEQUENCE:@npki_sec1
					if (key == 'otherName') {
						var v = value.split(';');
						var d = v[1].split(':');
						var t = d.shift();
						d = d.join(':');
						var o = {};
						o['otherName'] = v[0];
						o['value'] = d == '' ? t : d;
						o['type'] = d == '' ? '' : t;
						res.push(o);
					} else {
						var o = {};
						o[key] = value;
						res.push(o);
					}
					break;

				default:
					// certificatePolicies
					// subjectAltName
					// issuerAltName
					var m = /^(CPS|userNotice|DNS|IP|RID|URI|dirName|email|otherName)\.[0-9]+$/.exec(key);
					if (m) {
						switch (m[1]) {
							case 'CPS':
							case 'userNotice':
								//if (typeof res[m[1]] == 'undefined') res[m[1]] = [];
								if (!(m[1] in res)) res[m[1]] = [];
								res[m[1]].push(value);
								break;
							case 'DNS':
							case 'IP':
							case 'RID':
							case 'URI':
							case 'dirName':
							case 'email':
							case 'otherName':
								//if (!jCastle.util.isArray(res)) res = [];
								if (!Array.isArray(res)) res = [];

								if (m[1] == 'otherName') {
									var v = value.split(';');
									var d = v[1].split(':');
									var t = d.shift();
									d = d.join(':');
									var o = {};
									o['otherName'] = v[0];
									o['value'] = d == '' ? t : d;
									o['type'] = d == '' ? '' : t;
									res.push(o);
								} else {
									var o = {};
									o[m[1]] = value;
									res.push(o);
								}
								break;
						}
					} else {
						// authorityInfoAccess
						var m = /^(OCSP|caIssuers)\;(DNS|URI|RID|dirName|email|IP)(\.[0-9]+)?$/.exec(key);
						if (m) {
							//if (!jCastle.util.isArray(res)) res = [];
							if (!Array.isArray(res)) res = [];

							var o = {};
							o['method'] = m[1];
							o[m[2]] = value;

							res.push(o);
						} else {
							res[key] = value;
						}
					}
			}
		}

		this.contents[section_name] = res;	
	}

	_getSection(section_link)
	{
		if (section_link.indexOf('@') == 0) section_link = section_link.substr(1);

		var link =  jCastle.util.clone(this.contents[section_link]);
		//var link =  Object.assign({}, this.contents[section_link]);
		// later some subsections will be removed.
		// so don't forget to copy it.
		//var link = this.contents[section_link];

		this._linkSubSection(link);

		return link;
	}

	_linkSubSection(section)
	{
		for (var key in section) {
			switch (typeof section[key]) {
				case 'string':
					if (this._isSectionLink(section[key])) {
						section[key] = this._getSection(section[key]);
					}
					break;
				case 'object':
					//if (jCastle.util.isArray(section[key])) {
					if (Array.isArray(section[key])) {
						for (var i = 0; i < section[key].length; i++) {
							if (this._isSectionLink(section[key][i])) {
								section[key][i] = this._getSection(section[key][i]);
							}
						}
					} else {
						for (var i in section[key]) {

							if (this._isSectionLink(section[key][i])) {
								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(section[key][i]);

								section[key][i] = this._getSection(section[key][i]);
							}
						}
					}
					break;
			}
		}
	}

	_parseAccordingKeys()
	{
		for (var section_name in this.contents) {
			//if (jCastle.util.inArray(section_name, this.subSections)) continue;
			if (this.subSections.includes(section_name)) continue;
			if (jCastle.util.isString(this.contents[section_name])) continue;

			var section = this.contents[section_name];

			for (var key in section) {
				switch (key) {
/*
=============
x509v3_config
=============

NAME
====

x509v3_config - X509 V3 certificate extension configuration format

DESCRIPTION
===========

Several of the OpenSSL utilities can add extensions to a certificate 
or certificate request based on the contents of a configuration file.

Typically the application will contain an option to point to an extension section. 
Each line of the extension section takes the form:

	extension_name=[critical,] extension_options

If critical is present then the extension will be critical.

The format of extension_options depends on the value of extension_name.

There are four main types of extension: string extensions, multi-valued extensions, 
raw and arbitrary extensions.

String extensions simply have a string which contains either the value itself 
or how it is obtained.

For example:

	nsComment="This is a Comment"

Multi-valued extensions have a short form and a long form. 
The short form is a list of names and values:

	basicConstraints=critical,CA:true,pathlen:1

The long form allows the values to be placed in a separate section:

	basicConstraints=critical,bs_section

	[bs_section]

	CA=true
	pathlen=1

Both forms are equivalent.

The syntax of raw extensions is governed by the extension code: 
it can for example contain data in multiple sections. 
The correct syntax to use is defined by the extension code itself: 
check out the certificate policies extension for an example.

If an extension type is unsupported then the arbitrary extension syntax must be used,
see the "ARBITRARY EXTENSIONS" section for more details.


STANDARD EXTENSIONS
===================

The following sections describe each supported extension in detail.


Basic Constraints
-----------------

This is a multi valued extension which indicates whether a certificate is a CA certificate.
The first (mandatory) name is CA followed by TRUE or FALSE. 
If CA is TRUE then an optional pathlen name followed by an non-negative value can be included.

For example:

	basicConstraints=CA:TRUE

	basicConstraints=CA:FALSE

	basicConstraints=critical,CA:TRUE, pathlen:0

A CA certificate must include the basicConstraints value with the CA field set to TRUE.
An end user certificate must either set CA to FALSE or exclude the extension entirely.
Some software may require the inclusion of basicConstraints with CA set to FALSE 
for end entity certificates.

The pathlen parameter indicates the maximum number of CAs 
that can appear below this one in a chain. So if you have a CA with a pathlen of zero
it can only be used to sign end user certificates and not further CAs.
*/
					case 'basicConstraints':
						for (var i in section[key]) {
							if (this._isSectionLink(i)) {
								var link = this._getSection(i);

								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(i);

								delete section[key][i];

								for (var attr in link) {
									section[key][attr] = link[attr];
								}
							} else {
								switch (i) {
									case 'CA':
										section[key]['cA'] = section[key]['CA'];
										delete section[key]['CA'];
										break;
									case 'pathlen':
										section[key]['pathLenConstraint'] = section[key]['pathlen'];
										delete section[key]['pathlen'];
										break;
									case 'critical':
										section[key][i] = true;
										break;
								}
							}
						}
						break;
/*
Key Usage
---------

Key usage is a multi valued extension consisting of a list of names of the permitted key usages.

The supported names are: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
keyAgreement, keyCertSign, cRLSign, encipherOnly and decipherOnly.

Examples:

	keyUsage=digitalSignature, nonRepudiation

	keyUsage=critical, keyCertSign
*/
					case 'keyUsage':
						var list = [];
						for (var i in section[key]) {
							if (i == 'critical') {
								section[key][i] = true;
								continue;
							}
							list.push(i);
							delete section[key][i];
						}
						section[key]['list'] = list;
						break;
/*
Extended Key Usage
------------------

This extensions consists of a list of usages indicating purposes 
for which the certificate public key can be used for,

These can either be object short names of the dotted numerical form of OIDs.
While any OID can be used only certain values make sense. 
In particular the following PKIX, NS and MS values are meaningful:

	Value                  Meaning
	-----                  -------
	serverAuth             SSL/TLS Web Server Authentication.
	clientAuth             SSL/TLS Web Client Authentication.
	codeSigning            Code signing.
	emailProtection        E-mail Protection (S/MIME).
	timeStamping           Trusted Timestamping
	msCodeInd              Microsoft Individual Code Signing (authenticode)
	msCodeCom              Microsoft Commercial Code Signing (authenticode)
	msCTLSign              Microsoft Trust List Signing
	msEFS                  Microsoft Encrypted File System

Examples:

	extendedKeyUsage=critical,codeSigning,1.2.3.4
	extendedKeyUsage=serverAuth,clientAuth
*/
					case 'extendedKeyUsage':
					case 'extKeyUsage':
						var res = {};
						var keyPurposeId = [];
						for (var i in section[key]) {
							switch (i) {
								case 'critical':
									res[i] = true;
									break;
								case 'msCodeInd':
									keyPurposeId.push('individualCodeSigning');
									break;
								case 'msCodeCom':
									keyPurposeId.push('commercialCodeSigning');
									break;
								case 'msCTLSign':
									keyPurposeId.push('certTrustListSigning');
									break;
								case 'msEFS':
									keyPurposeId.push('encryptedFileSystem');
									break;
								case 'serverAuth':
								case 'clientAuth':
								case 'codeSigning':
								case 'emailProtection':
								case 'timeStamping':
								default:
									keyPurposeId.push(i);
									break;
							}
						}
						res.keyPurposeId = keyPurposeId;
			//			section['extKeyUsage'] = res;
			//			delete section[key];
						section[key] = res;
						break;
/*
Subject Key Identifier
----------------------

This is really a string extension and can take two possible values. 
Either the word hash which will automatically follow the guidelines in RFC3280 
or a hex string giving the extension value to include. 
The use of the hex string is strongly discouraged.

Example:

	subjectKeyIdentifier=hash
*/
				//case 'subjectKeyIdentifier':
/*
Authority Key Identifier
------------------------

The authority key identifier extension permits two options. 
keyid and issuer: both can take the optional value "always".

If the keyid option is present an attempt is made to copy the subject key identifier 
from the parent certificate. If the value "always" is present 
then an error is returned if the option fails.

The issuer option copies the issuer and serial number from the issuer certificate.
This will only be done if the keyid option fails or is not included 
unless the "always" flag will always include the value.

Example:

	authorityKeyIdentifier=keyid,issuer

--- from www.v13.gr ---

Short version:

Edit openssl.cnf and make sure that authorityKeyIdentifier does not include “issuer”

Long version:

There’s an issue when using the default OpenSSL configuration or 
when basing a config on that: the default OpenSSL configuration has the following:

	authorityKeyIdentifier=keyid,issuer

In the section that lists options for user certificates (i.e. not the CA section).
The above results in new certificates using the extension and 
include two identifiers for the signing CA:

The Key ID of the CA’s cert (because if “keyid”)
The subject and the serial number of the CA’s cert (because of issuer)
For example:

	X509v3 Authority Key Identifier: 
		keyid:7E:E5:82:FF:FF:FF:15:96:9B:40:FF:C9:5E:51:FF:69:67:4D:BF:FF
		DirName:/C=UK/O=V13/OU=V13/CN=V13 Certificate Authority
		serial:8E:FF:A2:1B:74:DD:54:FF

And this is where the pain and the suffering happens:
If you ever decide that you want to re-create the CA’s certificate 
using the same private key then you won’t be able to do so 
because all certificates that are already signed dictate  the subject 
and the serial number of the old certificate as the CA certificate identifier.
Thus your new CA certificate will not be able to verify the existing certificates.

Thus the only way to replace your certificate would be:

To start from scratch recreating all certificates, or
to create another CA certificate with the same subject and serial number (not tested)
Recreating a certificate with the same details (like serial number) 
will make it impossible to have both certificates available and will most probably
cause a mess.

The best approach is to completely remove the “issuer” from authorityKeyIdentifier
from the configuration file. Then only the Key ID will be used to identify the CA
which should be more than enough.

So use the following and live a happy life:

	authorityKeyIdentifier=keyid
*/
					case 'authorityKeyIdentifier':
						var res = {};

						for (var i in section[key]) {
							switch (i) {
								case 'keyid':
									res['keyIdentifier'] = section[key][i];
									break;
								case 'issuer':
									res['authorityCertIssuer'] = section[key][i];
									break;
							}
						}

						section[key] = res;
						break;
/*
Subject Alternative Name
------------------------

The subject alternative name extension allows various literal values 
to be included in the configuration file. These include email (an email address)
URI a uniform resource indicator, DNS (a DNS domain name), 
RID (a registered ID: OBJECT IDENTIFIER), IP (an IP address), 
dirName (a distinguished name) and otherName.

The email option include a special 'copy' value. This will automatically include
and email addresses contained in the certificate subject name in the extension.

The IP address used in the IP options can be in either IPv4 or IPv6 format.

The value of dirName should point to a section containing the distinguished name
to use as a set of name value pairs. Multi values AVAs can be formed 
by prefacing the name with a + character.

otherName can include arbitrary data associated with an OID: 
the value should be the OID followed by a semicolon and the content 
in standard ASN1_generate_nconf format.

Examples:

	subjectAltName=email:copy,email:my@other.address,URI:http://my.url.here/
	subjectAltName=IP:192.168.7.1
	subjectAltName=IP:13::17
	subjectAltName=email:my@other.address,RID:1.2.3.4
	subjectAltName=otherName:1.2.3.4;UTF8:some other identifier

	subjectAltName=dirName:dir_sect

	[dir_sect]
	C=UK
	O=My Organization
	OU=My Unit
	CN=My Name


Issuer Alternative Name
-----------------------

The issuer alternative name option supports all the literal options of subject alternative name.
It does not support the email:copy option because that would not make sense. 
It does support an additional issuer:copy option that will copy all the subject alternative name values
from the issuer certificate (if possible).

Example:

	issuserAltName = issuer:copy
*/
					case 'subjectAltName':
					case 'issuerAltName':
						var tmp = [];

						for (var i = 0; i < section[key].length; i++) {
							var s = section[key][i];
							for (var j in s) {
//console.log(j);
								if (this._isSectionLink(j)) {
//console.log('section name: '+j);
									var link = this._getSection(j);

									// this section will automatically deleted
									// after all work done.
									this._addToSubSection(j);

									tmp = tmp.concat(link);
								} else {
									if (j == 'otherName') {
										var value = s[j];
										var v = value.split(';');
										var d = v[1].split(':');
										var t = d.shift();
										d = d.join(':');
										var o = {};
										o[j] = v[0];
										o['value'] = d == '' ? t : d;
										o['type'] = d == '' ? '' : t;
										tmp.push(o);
									} else{
										if (s[j] == 'copy' &&
											((key == 'subjectAltName' && j == 'email') ||
											(key == 'issuerAltName' && j == 'issuer'))
										) {
											tmp.push('copy');
										} else {
											var o = {};
											o[j] = s[j];
											tmp.push(o);
										}
									}
								}
							}
						}

						var res = [];

//console.log(tmp);

						for (var i = 0; i < tmp.length; i++) {
							if (tmp[i] == 'copy') {
								res.push('copy');
							} else {
//console.log(tmp[i])
								res.push(this._getGeneralName(tmp[i]));
							}
						}

						section[key] = res;
						break;
/*
Authority Info Access
---------------------

The authority information access extension gives details about
how to access certain information relating to the CA. 
Its syntax is accessOID;location where location has the same syntax
as subject alternative name (except that email:copy is not supported).
accessOID can be any valid OID but only certain values are meaningful,
for example OCSP and caIssuers.

Example:

	authorityInfoAccess = OCSP;URI:http://ocsp.my.host/
	authorityInfoAccess = caIssuers;URI:http://my.ca/ca.html
*/
					case 'authorityInfoAccess':
						var res = [];

						for (var i in section[key]) {
							if (this._isSectionLink(i)) {
								var lnk = this._getSection(i);

								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(i);

								res = res.concat(lnk);
							} else {
								var v = i.split(';');
								var o = {};
								o['method'] = v[0];
								o[v[1]] = section[key][i];
								res.push(o);
							}
							delete section[key][i];
						}

						for (var i = 0; i < res.length; i++) {
							var o = {};
							switch (res[i].method) {
								case 'OCSP':
									o.accessMethod = 'ocsp';
									break;
								case 'caIssuers':
								default:
									o.accessMethod = res[i].method;
									break;
							}
							delete res[i].method;

							o.accessLocation = this._getGeneralName(res[i]);
							res[i] = o;
						}

						section[key].accessDescription = res;
						break;
/*
CRL distribution points
-----------------------

This is a multi-valued extension whose options can be either 
in name:value pair using the same form as subject alternative name 
or a single value representing a section name containing 
all the distribution point fields.

For a name:value pair a new DistributionPoint with the fullName field set
to the given value both the cRLissuer and reasons fields are omitted in this case.

In the single option case the section indicated contains values
for each field. In this section:

If the name is "fullname" the value field should contain 
the full name of the distribution point in the same format 
as subject alternative name.

If the name is "relativename" then the value field should 
contain a section name whose contents represent a DN fragment 
to be placed in this field.

The name "CRLIssuer" if present should contain a value 
for this field in subject alternative name format.

If the name is "reasons" the value field should consist of
a comma separated field containing the reasons. Valid reasons are:
"keyCompromise", "CACompromise", "affiliationChanged", "superseded",
"cessationOfOperation", "certificateHold", "privilegeWithdrawn" and "AACompromise".

Simple examples:

	crlDistributionPoints=URI:http://myhost.com/myca.crl
	crlDistributionPoints=URI:http://my.com/my.crl,URI:http://oth.com/my.crl

Full distribution point example:

	crlDistributionPoints=crldp1_section

	[crldp1_section]

	fullname=URI:http://myhost.com/myca.crl
	CRLissuer=dirName:issuer_sect
	reasons=keyCompromise, CACompromise

	[issuer_sect]
	C=UK
	O=Organisation
	CN=Some Name
*/
					case 'cRLDistributionPoints':
						var res = {};
						res.distributionPoints = [];

						for (var i in section[key]) {
							if (this._isSectionLink(i)) {
								var lnk = this._getSection(i);

								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(i);

								res.distributionPoints = res.distributionPoints.concat(lnk);
							} else {
								if (i == 'critical') {
									res.critical = true;
								} else {
									var o = {};
									o['fullname'] = {};
									o['fullname'][i] = section[key][i];
									res.distributionPoints.push(o);
								}
							}
						}

						for (var i = 0; i < res.distributionPoints.length; i++) {
							res.distributionPoints[i].distributionPoint = this._getGeneralName(res.distributionPoints[i].fullname);
							delete res.distributionPoints[i].fullname;

							if ('CRLissuer' in res.distributionPoints[i]) {
								res.distributionPoints[i].cRLIssuer = [];
								res.distributionPoints[i].cRLIssuer.push(this._getGeneralName(res.distributionPoints[i].CRLissuer));
								delete res.distributionPoints[i].CRLissuer;
							}

							if ('reasons' in res.distributionPoints[i]) {
								for (var p = 0; p < res.distributionPoints[i].reasons.length; p++) {
									switch (res.distributionPoints[i].reasons[p]) {
										case 'CACompromise':
											res.distributionPoints[i].reasons[p] = 'cACompromise';
											break;
										case 'AACompromise':
											res.distributionPoints[i].reasons[p] = 'aACompromise';
											break;
									}
								}
							}		
						}

						section[key] = res;
						break;
/*
Issuing Distribution Point
--------------------------

This extension should only appear in CRLs. It is a multi valued extension
whose syntax is similar to the "section" pointed to 
by the CRL distribution points extension with a few differences.

The names "reasons" and "CRLissuer" are not recognized.

The name "onlysomereasons" is accepted which sets this field. 
The value is in the same format as the CRL distribution point "reasons" field.

The names "onlyuser", "onlyCA", "onlyAA" and "indirectCRL" are also 
accepted the values should be a boolean value (TRUE or FALSE) 
to indicate the value of the corresponding field.

Example:

	issuingDistributionPoint=critical, @idp_section

	[idp_section]

	fullname=URI:http://myhost.com/myca.crl
	indirectCRL=TRUE
	onlysomereasons=keyCompromise, CACompromise

	[issuer_sect]
	C=UK
	O=Organisation
	CN=Some Name
*/
					case 'issuingDistributionPoint':
						for (var i in section[key]) {
							if (this._isSectionLink(i)) {
								var link = this._getSection(i);

								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(i);

								delete section[key][i];

								for (var attr in link) {
									section[key][attr] = link[attr];
								}
							} else {
								if (i == 'URI') {
									var v = section[key][i];
									section[key]['fullname'] = {};
									section[key]['fullname'][i] = v;

									delete section[key][i];
								}
							}
						}

						var res = {};

						for (var i in section[key]) {
							switch (i) {
								case 'critical':
									res.critical = true;
									break;
								case 'onlyCA':
									res.onlyContainsCACerts = section[key][i];
									break;
								case 'onlyAA':
									res.onlyContainsAttributeCerts = section[key][i];
									break;
								case 'onlysomereasons':
									res.onlySomeReasons = [];

//console.log(section[key][i]);

									for (var j = 0; j < section[key][i].length; j++) {
										switch (section[key][i][j]) {
											case 'CACompromise':
												res.onlySomeReasons.push('cACompromise');
												break;
											case 'AACompromise':
												res.onlySomeReasons.push('aACompromise');
												break;
											default:
												res.onlySomeReasons.push(section[key][i][j]);
												break;
										}
									}
									break;
								case 'fullname':
									res.distributionPoint = this._getGeneralName(section[key][i]);
									break;
							}
						}

						section[key] = res;
						break;
/*
Certificate Policies
--------------------

This is a raw extension. All the fields of this extension can be set
by using the appropriate syntax.

If you follow the PKIX recommendations and just using one OID 
then you just include the value of that OID. Multiple OIDs can be
set separated by commas, for example:

 certificatePolicies= 1.2.4.5, 1.1.3.4
If you wish to include qualifiers then the policy OID and qualifiers
need to be specified in a separate section: this is done 
by using the @section syntax instead of a literal OID value.

The section referred to must include the policy OID 
using the name policyIdentifier, cPSuri qualifiers can be 
included using the syntax:

	CPS.nnn=value

userNotice qualifiers can be set using the syntax:

	userNotice.nnn=@notice

The value of the userNotice qualifier is specified in the relevant section.
This section can include explicitText, organization and noticeNumbers options.
explicitText and organization are text strings, noticeNumbers is 
a comma separated list of numbers. The organization and noticeNumbers options 
(if included) must BOTH be present. If you use the userNotice option 
with IE5 then you need the 'ia5org' option at the top level 
to modify the encoding: otherwise it will not be interpreted properly.

Example:

	certificatePolicies=ia5org,1.2.3.4,1.5.6.7.8,@polsect

	[polsect]

	policyIdentifier = 1.3.5.8
	CPS.1="http://my.host.name/"
	CPS.2="http://my.your.name/"
	userNotice.1=@notice

	[notice]

	explicitText="Explicit Text Here"
	organization="Organisation Name"
	noticeNumbers=1,2,3,4

The ia5org option changes the type of the organization field.
In RFC2459 it can only be of type DisplayText. In RFC3280 
IA5Strring is also permissible. Some software 
(for example some versions of MSIE) may require ia5org.
*/
					case 'certificatePolicies':
						var res = {};
						res.policyInformation = [];
						
						for (var i in section[key]) {
							if (this._isSectionLink(i)) {
								var lnk = this._getSection(i);

								// this section will automatically deleted
								// after all work done.
								this._addToSubSection(i);

								res.policyInformation.push(lnk);
							} else {
								switch (i) {
									case 'ia5org':
									case 'critical':
										res[i] = true;
										break;
									default:
										var o = {};
										o.policyIdentifier = i;
										res.policyInformation.push(o);
										break;
								}
							}
						}

						for (var i = 0; i < res.policyInformation.length; i++) {
							var info = res.policyInformation[i];
							if ('CPS' in info || 'userNotice' in info) {
								var policyQualifiers = [];

								if ('CPS' in info) {
									for (var j = 0; j < info.CPS.length; j++) {
										var o = {
											policyQualifierId: 'cps',
											qualifier: {
												value: info.CPS[j],
												type: jCastle.asn1.tagIA5String
											}
										};
										policyQualifiers.push(o);
									}

									delete res.policyInformation[i].CPS;
								}

								if ('userNotice' in info) {
									for (var j = 0; j < info.userNotice.length; j++) {
										var o = {
											policyQualifierId: 'unotice',
											qualifier: {
												explicitText: {
													value: info.userNotice[j].explicitText,
													type: 'ia5org' in res ? jCastle.asn1.tagIA5String : jCastle.asn1.tagUTF8String
												}
											}
										};

										if ('organization' in info.userNotice[j]) {
											o.qualifier.organization = {
												value: info.userNotice[j].organization,
												type: 'ia5org' in res ? jCastle.asn1.tagIA5String : jCastle.asn1.tagUTF8String
											};
										}

										if ('noticeNumbers' in info.userNotice[j]) {
											o.qualifier.noticeNumbers = jCastle.util.clone(info.userNotice[j].noticeNumbers);
											//o.qualifier.noticeNumbers = Object.assign({}, info.userNotice[j].noticeNumbers);
										}

										policyQualifiers.push(o);
									}

									delete res.policyInformation[i].userNotice;
								}

								res.policyInformation[i].policyQualifiers = policyQualifiers;
							}
						}

						section[key] = res;
						break;
/*
Policy Constraints
------------------

This is a multi-valued extension which consisting of the names 
requireExplicitPolicy or inhibitPolicyMapping and 
a non negative integer value. At least one component must be present.

Example:

	policyConstraints = requireExplicitPolicy:3
*/
				//case 'policyConstraints
/*
Inhibit Any Policy
------------------

This is a string extension whose value must be a non negative integer.

Example:

inhibitAnyPolicy = 2
*/
					case 'inhibitAnyPolicy':
						for (var i in section[key]) {
							this.contents[section_name][key] = {
								skipCerts: parseInt(i)
							};
						}
						break;
/*
Name Constraints
----------------

The name constraints extension is a multi-valued extension.
The name should begin with the word permitted or excluded followed by a ;.
The rest of the name and the value follows the syntax of subjectAltName
except email:copy is not supported and the IP form should 
consist of an IP addresses and subnet mask separated by a /.

Examples:

	nameConstraints=permitted;IP:192.168.0.0/255.255.0.0

	nameConstraints=permitted;email:.somedomain.com

	nameConstraints=excluded;email:.com
*/
					case 'nameConstraints':
						var tmp = {};
						for (var i in section[key]) {
							if (i == 'critical') {
								tmp.critical = true;
								continue;
							}

							var s = i.split(';');
							if (typeof tmp[s[0]] == 'undefined') tmp[s[0]] = [];
							var o = {};
							o[s[1]] = section[key][i];
							tmp[s[0]].push(o);
						}

						var res = {};
						if ('critical' in tmp) {
							res.critical = true;
						}

						if ('excluded' in tmp) {
							res.excludedSubtrees = [];

							for (var i = 0; i < tmp.excluded.length; i++) {
								var o = {
									base: this._getGeneralName(tmp.excluded[i])
								};

								res.excludedSubtrees.push(o);
							}
						}

						if ('permitted' in tmp) {
							res.permittedSubtrees = [];

							for (var i = 0; i < tmp.permitted.length; i++) {
								var o = {
									base: this._getGeneralName(tmp.permitted[i])
								};

								res.permittedSubtrees.push(o);
							}
						}

						section[key] = res;
						break;
/*
OCSP No Check
-------------

The OCSP No Check extension is a string extension but its value is ignored.

Example:

	noCheck = ignored
*/
					case 'ocspNoCheck':
						for (var i in section[key]) {
							this.contents[section_name][key] = i;
						}
						break;
/*
DEPRECATED EXTENSIONS
=====================

The following extensions are non standard, Netscape specific 
and largely obsolete. Their use in new applications is discouraged.


Netscape String extensions
--------------------------

Netscape Comment (nsComment) is a string extension containing 
a comment which will be displayed when the certificate is viewed 
in some browsers.

Example:

	nsComment = "Some Random Comment"

Other supported extensions in this category are: nsBaseUrl,
nsRevocationUrl, nsCaRevocationUrl, nsRenewalUrl, nsCaPolicyUrl
and nsSslServerName.


Netscape Certificate Type
-------------------------

This is a multi-valued extensions which consists of a list of flags
to be included. It was used to indicate the purposes 
for which a certificate could be used. The basicConstraints,
keyUsage and extended key usage extensions are now used instead.

Acceptable values for nsCertType are: client, server, email,
objsign, reserved, sslCA, emailCA, objCA.
*/
					case 'nsCertType':
					case 'netscape-cert-type':
						var list = [];
						for (var i in section[key]) {
							list.push(i);
							delete section[key][i];
						}

						var res = [];
						for (var i = 0; i < list.length; i++) {
							switch (list[i]) {
								case 'client':
									res.push('SSL client'); break;
								case 'server':
									res.push('SSL server'); break;
								case 'email':
									res.push('S/MIME'); break;
								case 'objsign':
									res.push('Object Signing'); break;
								case 'reserved':
									res.push('Reserved'); break;
								case 'sslCA':
									res.push('SSL CA'); break;
								case 'emailCA':
									res.push('S/MIME CA'); break;
								case 'objCA':
									res.push('Object Signing CA'); break;
							}
						}

						section[key].value = res;
						break;
					case 'netscape-base-url':
					case 'netscape-revocation-url':
					case 'netscape-ca-revocation-url':
					case 'netscape-cert-renewal-url':
					case 'netscape-ca-policy-url':
					case 'netscape-ssl-server-name':
					case 'netscape-comment':
						var o = {
							value: section[key],
							type: jCastle.asn1.tagIA5String
						};
						section[key] = o;
						break;
/*
ARBITRARY EXTENSIONS
====================

If an extension is not supported by the OpenSSL code 
then it must be encoded using the arbitrary extension format.
It is also possible to use the arbitrary format for supported extensions.
Extreme care should be taken to ensure that the data is 
formatted correctly for the given extension type.

There are two ways to encode arbitrary extensions.

The first way is to use the word ASN1 followed 
by the extension content using the same syntax as ASN1_generate_nconf. 
For example:

	1.2.3.4=critical,ASN1:UTF8String:Some random data

	1.2.3.4=ASN1:SEQUENCE:seq_sect

	[seq_sect]

	field1 = UTF8:field1
	field2 = UTF8:field2

It is also possible to use the word DER to include the raw encoded data 
in any extension.

	1.2.3.4=critical,DER:01:02:03:04
	1.2.3.4=DER:01020304

The value following DER is a hex dump of the DER encoding of the extension
Any extension can be placed in this form to override the default behaviour. 
For example:

	basicConstraints=critical,DER:00:01:02:03


WARNING
=======

There is no guarantee that a specific implementation will process a given extension.
It may therefore be sometimes possible to use certificates for purposes prohibited
by their extensions because a specific application does not recognize or honour
the values of the relevant extensions.

The DER and ASN1 options should be used with caution. 
It is possible to create totally invalid extensions if they are not used carefully.



NOTES
=====

If an extension is multi-value and a field value must contain a comma 
the long form must be used otherwise the comma would be misinterpreted 
as a field separator. For example:

	subjectAltName=URI:ldap://somehost.com/CN=foo,OU=bar

will produce an error but the equivalent form:

	subjectAltName=@subject_alt_section

	[subject_alt_section]
	subjectAltName=URI:ldap://somehost.com/CN=foo,OU=bar

is valid.

Due to the behaviour of the OpenSSL conf library the same field name 
can only occur once in a section. This means that:

	subjectAltName=@alt_section

	[alt_section]

	email=steve@here
	email=steve@there

will only recognize the last value. This can be worked around by using the form:

	[alt_section]

	email.1=steve@here
	email.2=steve@there

(from openssl's x509v3_config doucument)
*/
				}
			}
		}
	}

	_getGeneralName(obj)
	{
		var o = {};

		if ('email' in obj) {
			o.name = 'rfc822Name';
			o.value = obj.email;
			o.type = jCastle.asn1.tagIA5String;
			return o;
		}

		if ('IP' in obj) {
			o.name = 'iPAddress';
			o.value = obj.IP;
			o.type = jCastle.asn1.tagOctetString;
			return o;
		}

		if ('RID' in obj) {
			o.name = 'registeredID';
			o.value = obj.RID;
			return o;
		}

		if ('URI' in obj) {
			o.name = 'uniformResourceIdentifier';
			o.value = obj.URI;
			o.type = jCastle.asn1.tagIA5String;
			return o;
		}

		if ('DNS' in obj) {
			o.name = 'dNSName';
			o.value = obj.DNS;
			o.type = jCastle.asn1.tagIA5String;
			return o;
		}

		if ('otherName' in obj) {
			// Object { otherName: "1.2.3.4", value: "some other identifier", type: "UTF8" }
			// Object { otherName: "1.3.6.1.4.1.1.", value: Object, type: "SEQUENCE" }
			o.name = 'otherName';
			o.value = {};
			o.value.name = obj.otherName;
//			console.log(obj);
			if (obj.type == 'SEQUENCE') {
				o.value.items = this._parseASN1Items(obj.value);
				o.value.type = jCastle.asn1.tagSequence;
			} else {
				o.value.value = obj.value;
				o.value.type = this._getASN1Type(obj.type);
			}

			return o;
		}

		if ('dirName' in obj) {
			o.name = 'directoryName';
			o.value = [];

			for (var i in obj.dirName) {
				var name = '';
				switch (i) {
					case 'countryName':
					case 'C':
						name = 'countryName';
						break;
					case 'stateOrProvinceName':
					case 'ST':
						name = 'stateOrProvinceName';
						break;
					case 'localityName':
					case 'L':
						name = 'localityName';
						break;
					case 'organizationName':
					case 'O':
						name = 'organizationName';
						break;
					case 'organizationalUnitName':
					case 'OU':
						name = 'organizationalUnitName';
						break;
					case 'commonName':
					case 'CN':
						name = 'commonName';
						break;
					case 'emailAddress':
					case 'E':
						name = 'emailAddress';
						break;
					case 'streetAddress':
					case 'STREET':
						name = 'streetAddress';
						break;
				}

				var v = {};
				v.name = name;
				v.value = obj.dirName[i];
				v.type = jCastle.asn1.tagUTF8String;
				o.value.push(v);
			}

			return o;
		}

		return null;
	}

/*
https://www.openssl.org/docs/manmaster/crypto/ASN1_generate_v3.html


GENERATION STRING FORMAT
========================

The actual data encoded is determined by the string str and the configuration
information. The general format of the string is:

[modifier,]type[:value]

That is zero or more comma separated modifiers followed by a type followed 
by an optional colon and a value. The formats of type, value and modifier 
are explained below.


SUPPORTED TYPES
---------------

The supported types are listed below. Unless otherwise specified only 
the ASCII format is permissible.

BOOLEAN, BOOL

This encodes a boolean type. The value string is mandatory and should be TRUE 
or FALSE. Additionally TRUE, true, Y, y, YES, yes, FALSE, false, N, n, NO 
and no are acceptable.

NULL

Encode the NULL type, the value string must not be present.

INTEGER, INT

Encodes an ASN1 INTEGER type. The value string represents the value of 
the integer, it can be prefaced by a minus sign and is normally interpreted 
as a decimal value unless the prefix 0x is included.

ENUMERATED, ENUM

Encodes the ASN1 ENUMERATED type, it is otherwise identical to INTEGER.

OBJECT, OID

Encodes an ASN1 OBJECT IDENTIFIER, the value string can be a short name,
a long name or numerical format.

UTCTIME, UTC

Encodes an ASN1 UTCTime structure, the value should be in the format 
YYMMDDHHMMSSZ.

GENERALIZEDTIME, GENTIME

Encodes an ASN1 GeneralizedTime structure, the value should be in the 
format YYYYMMDDHHMMSSZ.

OCTETSTRING, OCT

Encodes an ASN1 OCTET STRING. value represents the contents of this structure,
the format strings ASCII and HEX can be used to specify the format of value.

BITSTRING, BITSTR

Encodes an ASN1 BIT STRING. value represents the contents of this structure,
the format strings ASCII, HEX and BITLIST can be used to specify the format of value.

If the format is anything other than BITLIST the number of unused bits is set to zero.

UNIVERSALSTRING, UNIV, IA5, IA5STRING, UTF8, UTF8String, BMP, BMPSTRING,
VISIBLESTRING, VISIBLE, PRINTABLESTRING, PRINTABLE, T61, T61STRING, 
TELETEXSTRING, GeneralString, NUMERICSTRING, NUMERIC

These encode the corresponding string types. value represents the contents 
of this structure. The format can be ASCII or UTF8.

SEQUENCE, SEQ, SET

Formats the result as an ASN1 SEQUENCE or SET type. value should be a section 
name which will contain the contents. The field names in the section are ignored 
and the values are in the generated string format. If value is absent 
then an empty SEQUENCE will be encoded.


MODIFIERS
---------

Modifiers affect the following structure, they can be used to add EXPLICIT
or IMPLICIT tagging, add wrappers or to change the string format of the final type
and value. The supported formats are documented below.

EXPLICIT, EXP

Add an explicit tag to the following structure. This string should be followed
by a colon and the tag value to use as a decimal value.

By following the number with U, A, P or C UNIVERSAL, APPLICATION, PRIVATE or
CONTEXT SPECIFIC tagging can be used, the default is CONTEXT SPECIFIC.

IMPLICIT, IMP

This is the same as EXPLICIT except IMPLICIT tagging is used instead.

OCTWRAP, SEQWRAP, SETWRAP, BITWRAP

The following structure is surrounded by an OCTET STRING, a SEQUENCE, a SET 
or a BIT STRING respectively. For a BIT STRING the number of unused bits is
set to zero.

FORMAT

This specifies the format of the ultimate value. It should be followed by 
a colon and one of the strings ASCII, UTF8, HEX or BITLIST.

If no format specifier is included then ASCII is used. If UTF8 is specified 
then the value string must be a valid UTF8 string. For HEX the output must 
be a set of hex digits. BITLIST (which is only valid for a BIT STRING) is 
a comma separated list of the indices of the set bits, all other bits are zero.

EXAMPLES
--------

A simple IA5String:

	IA5STRING:Hello World

An IA5String explicitly tagged:

	EXPLICIT:0,IA5STRING:Hello World

An IA5String explicitly tagged using APPLICATION tagging:

	EXPLICIT:0A,IA5STRING:Hello World

A BITSTRING with bits 1 and 5 set and all others zero:

	FORMAT:BITLIST,BITSTRING:1,5

A more complex example using a config file to produce a SEQUENCE consisting 
of a BOOL an OID and a UTF8String:

	asn1 = SEQUENCE:seq_section

	[seq_section]

	field1 = BOOLEAN:TRUE
	field2 = OID:commonName
	field3 = UTF8:Third field

This example produces an RSAPrivateKey structure, this is the key contained
in the file client.pem in all OpenSSL distributions (note: the field names 
such as 'coeff' are ignored and are present just for clarity):

	asn1=SEQUENCE:private_key
	[private_key]
	version=INTEGER:0

	n=INTEGER:0xBB6FE79432CC6EA2D8F970675A5A87BFBE1AFF0BE63E879F2AFFB93644\
	D4D2C6D000430DEC66ABF47829E74B8C5108623A1C0EE8BE217B3AD8D36D5EB4FCA1D9

	e=INTEGER:0x010001

	d=INTEGER:0x6F05EAD2F27FFAEC84BEC360C4B928FD5F3A9865D0FCAAD291E2A52F4A\
	F810DC6373278C006A0ABBA27DC8C63BF97F7E666E27C5284D7D3B1FFFE16B7A87B51D

	p=INTEGER:0xF3929B9435608F8A22C208D86795271D54EBDFB09DDEF539AB083DA912\
	D4BD57

	q=INTEGER:0xC50016F89DFF2561347ED1186A46E150E28BF2D0F539A1594BBD7FE467\
	46EC4F

	exp1=INTEGER:0x9E7D4326C924AFC1DEA40B45650134966D6F9DFA3A7F9D698CD4ABEA\
	9C0A39B9

	exp2=INTEGER:0xBA84003BB95355AFB7C50DF140C60513D0BA51D637272E355E397779\
	E7B2458F

	coeff=INTEGER:0x30B9E4F2AFA5AC679F920FC83F1F2DF1BAF1779CF989447FABC2F5\
	628657053A

This example is the corresponding public key in a SubjectPublicKeyInfo structure:

	# Start with a SEQUENCE
	asn1=SEQUENCE:pubkeyinfo

	# pubkeyinfo contains an algorithm identifier and the public key wrapped
	# in a BIT STRING
	[pubkeyinfo]
	algorithm=SEQUENCE:rsa_alg
	pubkey=BITWRAP,SEQUENCE:rsapubkey

	# algorithm ID for RSA is just an OID and a NULL
	[rsa_alg]
	algorithm=OID:rsaEncryption
	parameter=NULL

	# Actual public key: modulus and exponent
	[rsapubkey]
	n=INTEGER:0xBB6FE79432CC6EA2D8F970675A5A87BFBE1AFF0BE63E879F2AFFB93644\
	D4D2C6D000430DEC66ABF47829E74B8C5108623A1C0EE8BE217B3AD8D36D5EB4FCA1D9

	e=INTEGER:0x010001


RETURN VALUES
-------------

ASN1_generate_nconf() and ASN1_generate_v3() return the encoded data 
as an ASN1_TYPE structure or NULL if an error occurred.
*/
	_parseASN1Items(obj)
	{
		var res = [];
		var value, type;
		for(var i in obj) {
			// should be field1, field2, field3 ...
			value = obj[i].split(':');
			type = value.shift().trim();
			value = value.join(':').trim();

			if (value == '') {
				value = type;
				type = '';
			}

			switch (type.toUpperCase()) {
				case 'SEQUENCE':
				case 'SEQ':
				case 'SET':
					if (!this._isSectionLink(value)) {
						throw jCastle.exception("NOT_SECTION_LINK", 'CCG002');
					}
					var s = this._getSection(value);

					// this section will automatically deleted
					// after all work done.
					this._addToSubSection(value);

					value = this._parseASN1Items(s);


					var o = {
						items: value,
						type: type == 'SET' ? jCastle.asn1.tagSet : jCastle.asn1.tagSequence
					};

					res.push(o);
					break;
				case 'EXPLICIT':
				case 'EXP':
					var v = value.split(',');
					var t = v.shift().trim();
					value = v.join(',').trim();

					if (value == '') {
						throw jCastle.exception("NO_TAG_TYPE_GIVEN", 'CCG003');
					}
					
					t = parseInt(t, 16);

					if (!this._isSectionLink(value)) {
						throw jCastle.exception("NOT_SECTION_LINK", 'CCG004');
					}
					var s = this._getSection(value);

					// this section will automatically deleted
					// after all work done.
					this._addToSubSection(value);

					value = this._parseASN1Items(s);

					var o = {
						items: value,
						type: t,
						tagClass: jCastle.asn1.tagClassContextSpecific,
						constructed: true
					};

					res.push(o);
					break;
				case 'IMPLICIT':
				case 'IMP':
					var v = value.split(',');
					var t = v.shift().trim();
					value = v.join(',').trim();

					if (value == '') {
						throw jCastle.exception("NO_TAG_TYPE_GIVEN", 'CCG005');
					}
					
					t = parseInt(t, 16);

					var m = /^DER\:(.*)/.exec(value);
					if (m) {
						//value = jCastle.encoding.hex.decode(m[1].replace(/\:/g, ''));
						value = Buffer.from(m[1].replace(/\:/g, ''), 'hex').toString('latin1');
					}

					var o = {
						value: value,
						type: t,
						tagClass: jCastle.asn1.tagClassContextSpecific,
						constructed: false
					};
					res.push(o);
					break;
				default:
					var m = /^DER\:(.*)/.exec(value);
					type = this._getASN1Type(type);

					if (m) {
						//value = jCastle.encoding.hex.decode(m[1].replace(/\:/g, ''));
						value = Buffer.from(m[1].replace(/\:/g, ''), 'hex').toString('latin1');
					} else {
						switch (type) {
							case jCastle.asn1.tagInteger:
								if (value.substr(0, 2).toLowerCase() == '0x') {
									value = parseInt(value.substr(2), 16);
								} else {
									value = parseInt(value);
								}
								break;
							case jCastle.asn1.tagBoolean:
								switch (value.toUpperCase()) {
									case 'FALSE':
									case 'NO':
									case 'N':
										value = false;
										break;
									case 'TRUE':
									case 'YES':
									case 'Y':
									default:
										value = true;
										break;
								}
								break;
							case jCastle.asn1.tagOID:
								if (!/^[0-9\.]+$/.test(value)) {
									var oid = jCastle.oid.getOID(value);
									if (!oid) {
										if (value in this.contents.new_oid) {
											value = this.contents.new_oid[value];
										} else {
											throw jCastle.exception("UNKNOWN_OID", 'CCG006');
										}
									}
								}
								break;
						}
					}

					var o = {
						value: value,
						type: type
					};
					res.push(o);
					break;
			}
		}

		return res;
	}

/*
This sets a mask for permitted string types. There are several options. 
	default: PrintableString, T61String, BMPString.
	pkix	 : PrintableString, BMPString.
	utf8only: only UTF8Strings.
	nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
	MASK:XXXX a literal mask value.
WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
so use this option with caution!
*/
	_getStringMask(is_req)
	{
		var string_mask = '';

		if (typeof this.contents.ca.default_ca == 'object' &&
			'string_mask' in this.contents.ca.default_ca) {
			string_mask = this.contents.ca.default_ca.string_mask;
		}

		if (is_req) {
			if ('string_mask' in this.contents.req) {
				string_mask = this.contents.req.string_mask;
			}
		}

		return jCastle.certConfig.fn.getStringMask(string_mask);
	}

	_getASN1Type(type)
	{
		switch (type.toUpperCase()) {
			case 'BOOL':
			case 'BOOLEAN':
				return jCastle.asn1.tagBoolean;
			case 'UTF8':
			case 'UTF8STRING':
				return jCastle.asn1.tagUTF8String;
			case 'OBJECT':
			case 'OID':
				return jCastle.asn1.tagOID;
			case 'BITSTR':
			case 'BITSTRING':
				return jCastle.asn1.tagBitString;
			case 'BMP':
			case 'BMPSTRING':
				return jCastle.asn1.tagBMP8String;
			case 'PRINTABLE':
			case 'PRINTABLESTRING':
				return jCastle.asn1.tagPrintableString;
			case 'T61':
			case 'T61STRING':
			case 'TELETEXSTRING':
				return jCastle.asn1.tagT61String;
			case 'NUMERIC':
			case 'NUMERICSTRING':
				return jCastle.asn1.tagNumericString;
			case 'GRAPHIC':
			case 'GRAPHICSTRING':
				return jCastle.asn1.tagGraphicString;
			case 'VISIBLE':
			case 'VISIBLESTRING':
				return jCastle.asn1.tagVisibleString;
			case 'GENERAL':
			case 'GENERALSTRING':
				return jCastle.asn1.tagGeneralString;
			case 'UNIVERSALSTRING':
			case 'UNIV':
				return jCastle.asn1.tagUniversalString;
			case 'SEQUENCE':
			case 'SEQ':
				return jCastle.asn1.tagSequence;
			case 'SET':
				return jCastle.asn1.tagSet;
			case 'OCT':
			case 'OCTETSTRING':
				return jCastle.asn1.tagOctetString;
			case 'IA5':
			case 'NULL':
				return jCastle.asn1.tagNull;
			case 'INT':
			case 'INTEGER':
				return jCastle.asn1.tagInteger;
			case 'ENUMERATED':
			case 'ENUM':
				return jCastle.asn1.tagEnumerated;
			case 'UTCTIME':
			case 'UTC':
				return jCastle.asn1.tagUTCTime;
			case 'GENERALIZEDTIME':
			case 'GENTIME':
				return jCastle.asn1.tagGeneralizedTime;
			case 'IA5STRING':
			case 'IA5':
			default:
				return jCastle.asn1.tagIA5String;
		}
	}

	_realValue(value)
	{
		value = value.trim();

		switch (value) {
			case 'true':
			case 'TRUE':
				return true;
			case 'false':
			case 'FALSE':
				return false;
			default:
				if (/^[0-9]+$/.test(value)) return parseInt(value);
				return value;
		}
	}
};

/**
 * creates a new certificate config parser
 * @public
 * 
 * @returns a new certificate config parser
 */
jCastle.certConfig.create = function()
{
	return new jCastle.certConfig();
};

/**
 * parses OpenSSL's configuration string.
 * @public
 * 
 * @param {string} config OpenSSL's configuration string
 * 
 * @returns a parsed config object.
 */
jCastle.certConfig.parse = function(config)
{
	return new jCastle.certConfig().parse(config);
};

jCastle.certConfig.fn = {};

/**
 * get a asn1 type integer for the given string mask.
 * @public
 * 
 * @param {string} string_mask 
 * 
 * @returns the integer value for string mask.
 */
jCastle.certConfig.fn.getStringMask = function(string_mask)
{
	switch (string_mask) {
		case 'default':
			return jCastle.asn1.tagPrintableString;
		case 'pkix':
			return jCastle.asn1.tagBMPString;
		case 'utf8only':
			return jCastle.asn1.tagUTF8String;
		case 'nombstr':
			return jCastle.asn1.tagPrintableString;
		default: 
			return jCastle.asn1.tagIA5String;
	}
};

/**
 * rasterizes the certConfig object.
 * @public
 * 
 * @param {object} cert_config certConfig object.
 */
jCastle.certConfig.rasterize =
jCastle.certConfig.rasterizeSchema = function(cert_config)
{
	if (jCastle.util.isString(cert_config)) {
		try {
			cert_config = new jCastle.certConfig().parse(cert_config);
		} catch (e) {
			throw jCastle.exception('INVALID_CONFIG', 'CCG007');
		}
	}

	var res = jCastle.util.clone(cert_config);
	//var res = Object.assign({}, cert_config);

	for (var section in res) {
		//if (jCastle.util.isArray(res[section])) jCastle.certConfig._rasterizeList(res[section]);
		if (Array.isArray(res[section])) jCastle.certConfig._rasterizeList(res[section]);
		else if (jCastle.certConfig._isObjectValue(res[section])) jCastle.certConfig._rasterizeObjectValue(res[section]);
	}

	return res;
};

jCastle.certConfig._isObjectValue = function(val)
{
	return !jCastle.util.isString(val) && typeof val == 'object' && val != null;
};

jCastle.certConfig._rasterizeStringType = function(type)
{
	switch (type) {
		case 3: return 'Bit String';
		case 4: return 'Octet String';
		case 12: return 'UTF8 String';
		case 19: return 'Printable String';
		case 20: return 'Teletex String';
		case 22: return 'IA5 String';
		case 26: return 'Visible String';
		case 27: return 'General String';
		case 28: return 'Universal String';
		case 30: return 'BMP String';
	}
	return type;
};

jCastle.certConfig._rasterizeObjectValue = function(obj)
{
	if ('value' in obj && 'type' in obj) {
		obj.type = jCastle.certConfig._rasterizeStringType(obj.type);
		return;
	}

	for (var item in obj) {
		//if (jCastle.util.isArray(obj[item])) jCastle.certConfig._rasterizeList(obj[item]);
		if (Array.isArray(obj[item])) jCastle.certConfig._rasterizeList(obj[item]);
		else if (jCastle.certConfig._isObjectValue(obj[item])) jCastle.certConfig._rasterizeObjectValue(obj[item]);
	}
};

jCastle.certConfig._rasterizeList = function(list)
{
	for (var i = 0; i < list.length; i++) {
		var item = list[i];
		//if (jCastle.util.isArray(item)) jCastle.certConfig._rasterizeList(item);
		if (Array.isArray(item)) jCastle.certConfig._rasterizeList(item);
		else if (jCastle.certConfig._isObjectValue(item)) jCastle.certConfig._rasterizeObjectValue(item);
	}
};

jCastle.CertConfig = jCastle.certConfig;

module.exports = jCastle.certConfig;