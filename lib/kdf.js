/**
 * A Javascript implemenation of Password-Based Key Derivation Functions
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

/*
test vectors for pbkdf1 and pbkdf2 : https://www.ietf.org/rfc/rfc6070.txt
*/
var jCastle = require('./jCastle');
require('./util');

jCastle.kdf = {
    /**
     * PKCS#5 Key Derive Function.
     * 
     * @public
     * @param {buffer} password password value.
     * @param {buffer} salt salt value.
     * @param {number} len key length.
     * @param {string} hash_algo hash algorithm name. (default: 'md5')
     * @returns derived key in buffer.
     */
    pkcs5DeriveKey: function(password, salt, len, hash_algo = 'md5')
    {
        len = len || jCastle.digest.getDigestLength(hash_algo);
            
        var md = new jCastle.digest(hash_algo);		
        var result = Buffer.alloc(len);
        var pos = 0;
            
        password = Buffer.from(password, 'latin1');
        salt = Buffer.from(salt, 'latin1');
    
        var tmp = md.start().update(password).update(salt).finalize();
        result.set(tmp, 0);
        pos += tmp.length;
            
        while (pos < len) {
            tmp = md.start().update(tmp).update(password).update(salt).finalize();
            result.set(tmp.slice(0, tmp.length > len - pos ? len - pos : tmp.length), pos);
            pos += tmp.length;
        }
    
        return result;
    },
    
/*
    SEC 1: Elliptic Curve Cryptography
    
    3.6.1 ANS X9.63 Key Derivation Function
    
    Keying data should be calculated using ANSI-X9.63-KDF as follows:
    
    Setup: Select one of the approved hash functions listed in Section 3.5. Let Hash denote the hash
    function chosen, hashlen denote the length in octets of hash values computed using Hash, and
    hashmaxlen denote the maximum length in octets of messages that can be hashed using Hash.
    
    Input: The input to the key derivation function is:
    
        1. An octet string Z which is the shared secret value.
        2. An integer keydatalen which is the length in octets of the keying data to be generated.
        3. (Optional) An octet string SharedInfo which consists of some data shared by the entities
           intended to share the shared secret value Z.
    
    Output: The keying data K which is an octet string of length keydatalen octets, or “invalid”.
    
    Actions: Calculate the keying data K as follows:
    
        1. Check that |Z| + |SharedInfo| + 4 < hashmaxlen. If |Z| + |SharedInfo| + 4 >= hashmaxlen,
           output “invalid” and stop.
    
        2. Check that keydatalen < hashlen × (232 − 1). If keydatalen >= hashlen × (232 − 1), output
           “invalid” and stop.
    
        3. Initiate a 4 octet, big-endian octet string Counter as 00000001{16}.
    
        4. For i = 1 to keydatalen/hashlen, do the following:
    
            4.1. Compute:
                 K{i} = Hash(Z || Counter || [SharedInfo])
                 using the selected hash function from the list of approved hash functions in Section 3.5.
            4.2. Increment Counter.
            4.3. Increment i.
    
        5. Set K to be the leftmost keydatalen octets of:
            K1 || K2 || . . . || K{keydatalen/hashlen}.
    
        6. Output K.
*/
    /**
     * ANS X9.63 Key Derivation Function
     * 
     * @public
     * @param {string} hash_algo hash algorithm name
     * @param {number} dklen key length
     * @param {buffer} z Z value
     * @param {buffer} sharedInfo sharedInfo value
     * @returns derived key.
     */
    ansX963DeriveKey: function(hash_algo, dklen, z, sharedInfo)
    {
        hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
    
        function increaseCounter(cnt_bl)
        {
            var carry = 1;
            var j = 4;
    
            while (j-- && carry) {
                var x = cnt_bl[j] + carry;
                carry = x > 0xff ? 1 : 0;
                cnt_bl[j] = x & 0xff;
            }
        }
    
        if (!z || !z.length) throw jCastle.exception('INVALID_INPUT_SIZE', 'KDF006');
        if (!dklen) throw jCastle.exception('INVALID_KEYSIZE', 'KDF007');
        z = Buffer.from(z, 'latin1');
        sharedInfo = Buffer.from(sharedInfo, 'latin1');
    
        var dk = Buffer.alloc(dklen);
        var md = jCastle.digest.create(hash_algo);
        var cnt_bl = Buffer.from([0,0,0,1]);
        var pos = 0;
    
        while (pos < dklen) {
            md.start({algoName: hash_algo})
                .update(z)
                .update(cnt_bl)
                .update(sharedInfo);
            var h = md.finalize();
            dk.set(h.slice(0, h.length > dklen - pos ? dklen - pos : h.length), pos);
            pos += h.length;
    
            increaseCounter(cnt_bl);
        }
    
        return dk;
    },
/*
        The Single-step Key-Derivation Function
        ---------------------------------------
        http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
    
        5.8.1 The Single-step Key-Derivation Function
    
        This section specifies an approved key-derivation function (KDF) that is 
        executed in a single step, rather than the two-step procedure discussed in 
        Section 5.8.2. The input to the KDF includes the shared secret Z 
        (represented as a byte string).
    
        This single-step KDF uses an auxiliary function H, which can be either 1)
        an approved hash function, denoted as hash, as defined in [FIPS 180] or 2)
        an HMAC with an approved hash function, hash, denoted as HMAC-hash, as 
        defined in [FIPS 198]. Table 6 and Table 7 identify the minimum output block
        length for the hash functions and HMACs required for each FFC and ECC 
        parameter-size set. 
    
        5.8.1.1 The Single-Step KDF Specification
    
        This section specifies an approved single-step key-derivation function (KDF),
        whose input includes the shared secret Z (represented as a byte string) and 
        other information. The KDF is specified as follows:
    
        Function call: kdf (Z, OtherInput),
    
            where OtherInput consists of keydatalen and OtherInfo.
    
        Auxiliary Function H (two options):
    
            Option 1: H(x) = hash(x), where hash is an approved hash function meeting
            the selection requirements specified in this Recommendation (see Sections
            5.1 and 5.8.1), and the input, x, is a bit string.
    
            Option 2: H(x) = HMAC-hash(salt, x), where HMAC-hash is an instantiation 
            of the HMAC function (as defined in [FIPS 198]) employing an approved 
            hash function, hash (see Section 5.1), and hash meets the selection 
            requirements specified in this Recommendation (see Sections 5.1 and 
            5.8.1). An implementation-dependent byte string, salt, serves as the 
            HMAC key, and x (the input to H) is a bit string that serves as the 
            HMAC “message” – as specified in [FIPS 198].
    
        Implementation-Dependent Parameters:
    
            1. hashlen: an integer that indicates the length (in bits) of the output
            block of the hash function, hash, employed by the auxiliary function, H,
            that is used to derive blocks of secret keying material.
    
            2. max_H_inputlen: an integer that indicates the maximum permitted length
            (in bits) of the bit string, x, that is used as input to the auxiliary 
            function, H.
    
            3. salt: a (public or private) byte string that is only required when an
            HMAC-based auxiliary function is implemented (see Option 2 above). The
            salt could be, for example, a value computed from nonces exchanged as
            part of a key-establishment protocol that employs one or more of the
            key-agreement schemes specified in this Recommendation, a value already
            shared by the protocol participants, or a value that is pre-determined 
            by the protocol. In this case, the length of the salt can be any 
            agreed-upon length. However, if there is no means of selecting the salt,
            then it shall be an all-zero byte string whose bit length equals that 
            specified as the length of the input block for the hash function, hash.
    
        Input:
    
            1. Z: a byte string that represents the shared secret z.
    
            2. keydatalen: An integer that indicates the length (in bits) of the 
            secret keying material to be derived; keydatalen shall be less than or
            equal to hashlen × (232 –1).
    
            3. OtherInfo: A bit string of context-specific data (see Section 5.8.1.2 
            for details).
    
        Process:
    
            1. reps = ceil(keydatalen / hashlen).
    
            2. If reps > (2^32 − 1), then return an error indicator without 
               performing the remaining actions.
    
            3. Initialize a 32-bit, big-endian bit string counter as 00000001(16)
               (i.e. 0x00000001).
    
            4. If "counter || Z || OtherInfo" is more than max_H_inputlen bits long,
               then return an error indicator without performing the remaining
               actions.
    
            5. For i = 1 to reps by 1, do the following:
    
                5.1 Compute K(i) = H(counter || Z || OtherInfo).
                5.2 Increment counter (modulo 2^32), treating it as an unsigned 
                32-bit integer.
    
            6. Let K_Last be set to K(reps) if (keydatalen / hashlen) is an integer;
               otherwise, let K_Last be set to the (keydatalen mod hashlen) leftmost
               bits of K(reps).
    
            7. Set DerivedKeyingMaterial = K(1) || K(2) || … || K(reps-1) || K_Last.
    
        Output:
    
            The bit string DerivedKeyingMaterial of length keydatalen bits (or an 
            error indicator).
    
        Notes:
    
            When an approved key-agreement scheme is used to determine a shared 
            secret Z, the participants should know which entity is acting as 
            “party U” and which entity is acting as “party V” to ensure (among other
            things) that they will derive the same keying material. (See Section 6 
            for descriptions of the specific actions required of parties U and V 
            during the execution of each of the approved key-agreement schemes.) The
            roles of party U and party V shall be assigned to the key-establishment 
            participants by the protocol employing the keyagreement scheme.
    
            In step 5.1 above, the entire output of the hash function hash shall be
            used whether H(x) = hash(x) or H(x) = HMAC-hash(salt, x). Therefore, 
            the bit length of each output block of H is hashlen bits. Some of the
            hash functions specified in [FIPS 180] are defined with an internal
            truncation operation (e.g., SHA-384). In these cases, the “entire 
            output” of hash is the output value as defined in [FIPS 180] (e.g., for
            SHA-384, the entire output is defined to be the 384 bits resulting from
            the internal truncation, so hashlen = 384, in this case). Any truncation
            performed by the KDF (external to hash) is done in step 6.
    
        5.8.1.2 OtherInfo
    
        The bit string OtherInfo should be used to ensure that the derived keying 
        material is adequately “bound” to the context of the key-agreement 
        transaction. Although other methods may be used to bind keying material to
        the transaction context, this Recommendation makes no statement as to the
        adequacy of these other methods. Failure to adequately bind the derived 
        keying material to the transaction context could adversely affect the types
        of assurance that can be provided by certain key-agreement schemes.
    
        Context-specific information that may be appropriate for inclusion in 
        OtherInfo:
    
            • Public information about parties U and V, such as their identifiers.
    
            • The public keys contributed by each party to the key-agreement 
              transaction. (In the case of a static public key, one could include a
              certificate that contains the public key.)
    
            • Other public and/or private information shared between parties U and 
              V before or during the transaction, such as nonces or pre-shared 
              secrets.
    
            • An indication of the protocol or application employing the key 
              derivation method.
    
            • Protocol-related information, such as a label or session identifier.
    
            • The desired length of the derived keying material.
    
            • An indication of the key-agreement scheme and/or key-derivation 
              method used.
    
            • An indication of the domain parameters associated with the asymmetric
              key pairs employed for key establishment.
    
            • An indication of other parameter or primitive choices (e.g., hash 
              functions, MacTag lengths, etc.).
    
            • An indication of how the derived keying material should be parsed, 
              including an indication of which algorithm(s) will use the (parsed)
              keying material.
    
        For rationale in support of including entity identifiers, scheme 
        identifiers, and/or other information in OtherInfo, see Appendix B.
    
        The meaning of each information item and each item’s position within the bit
        string OtherInfo shall be specified. In addition, each item of information
        included in OtherInfo shall be unambiguously represented, for example, as a
        fixed-length bit string or in the form Datalen || Data, where Data is a 
        variable-length string of zero or more (eight-bit) bytes, and Datalen is a
        fixed-length, big-endian counter that indicates the length (in bytes) of Data. 
        These requirements can be satisfied, for example, by using ASN.1 DER encoding
        as specified in 5.8.1.2.2 for OtherInfo.
    
        Recommended formats for OtherInfo are specified in Sections 5.8.1.2.1 and 
        5.8.1.2.2. One of these two formats should be used by the single-step KDF 
        specified in Section 5.8.1.1 when the auxiliary function employed is H = 
        hash. When the recommended formats are used, the included items of 
        information shall be divided into (three, four, or five) subfields as 
        defined below.
    
            AlgorithmID: A required non-null subfield that indicates how the derived
            keying material will be parsed and for which algorithm(s) the derived
            secret keying material will be used. For example, AlgorithmID might 
            indicate that bits 1-112 are to be used as a 112-bit HMAC key and that
            bits 113-240 are to be used as a 128-bit AES key.
    
            PartyUInfo: A required non-null subfield containing public information
            about party U. At a minimum, PartyUInfo shall include IDU, an identifier
            for party U, as a distinct item of information. This subfield could 
            also include information about the public key(s) contributed to the 
            key-agreement transaction by party U. The nonce provided by party U as 
            required in a C(0e, 2s) scheme (see Section 6.3) shall be included in
            this subfield.
    
            PartyVInfo: A required non-null subfield containing public information 
            about party V. At a minimum, PartyVInfo shall include IDV, an 
            identifier for party V, as a distinct item of information. This subfield
            could also include information about the public key(s) contributed to
            the key-agreement transaction by party V. The nonce provided by party V 
            when acting as a key-confirmation recipient in a C(1e, 2s) scheme or a 
            C(0e, 2s) scheme shall be included in this field (see Sections 6.2.1.5
            and 6.3.3).
    
            SuppPubInfo: An optional subfield, which could be null that contains 
            additional, mutually known public information (e.g., keydatalen, the
            domain parameters associated with the keys used to derive the shared
            secret, an identifier for the particular key-agreement scheme that was
            used to form Z, an indication of the protocol or application employing 
            that scheme, a session identifier, etc.; this is particularly useful
            if these aspects of the key-agreement transaction can vary – see 
            Appendix B for further discussion).
    
            SuppPrivInfo: An optional subfield, which could be null, that contains 
            additional, mutually known private information (e.g., a shared secret
            symmetric key that has been communicated through a separate channel).
    
        5.8.1.2.1 The Concatenation Format for OtherInfo
    
        This section specifies the concatenation format for OtherInfo. This format
        has been designed to provide a simple means of binding the derived keying
        material to the context of the keyagreement transaction, independent of
        other actions taken by the relying application. Note: When the single-step
        KDF specified in Section 5.8.1.1 is used with H = hash as the auxiliary 
        function and this concatenation format for OtherInfo, the resulting 
        key-derivation method is the Concatenation Key Derivation Function 
        specified in the original version of SP 800-56A.
    
        For this format, OtherInfo is a bit string equal to the following 
        concatenation:
    
         AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo },
    
        where the five subfields are bit strings comprised of items of information
        as described in Section 5.8.1.2.
    
        Each of the three required subfields AlgorithmID, PartyUInfo, and PartyVInfo
        shall be the concatenation of a pre-determined sequence of substrings in 
        which each substring represents a distinct item of information. Each such 
        substring shall have one of these two formats: either it is a fixed-length
        bit string, or it has the form Datalen || Data – where Data is a 
        variable-length string of zero or more (eight-bit) bytes, and Datalen is a 
        fixed-length, big-endian counter that indicates the length (in bytes) of 
        Data. (In this variable-length format, a null string of data shall be 
        represented by a zero value for Datalen, indicating the absence of 
        following data.) A protocol using this format for OtherInfo shall specify
        the number, ordering and meaning of the information-bearing substrings that
        are included in each of the subfields AlgorithmID, PartyUInfo, and 
        PartyVInfo, and shall also specify which of the two formats (fixed-length or
        variable-length) is used by each such substring to represent its distinct 
        item of information. The protocol shall specify the lengths for all 
        fixed-length quantities, including the Datalen counters.
        
        Each of the optional subfields SuppPrivInfo and SuppPubInfo (when allowed by
        the protocol employing the one-step KDF) shall be the concatenation of a 
        pre-determined sequence of substrings representing additional items of 
        information that may be used during key derivation upon mutual agreement of
        parties U and V. Each substring representing an item of information shall
        be of the form Datalen || Data, where Data is a variable-length string of 
        zero or more (eight-bit) bytes and Datalen is a fixed-length, big-endian
        counter that indicates the length (in bytes) of Data; the use of this form
        for the information allows parties U and V to omit a particular information
        item without confusion about the meaning of the other information that is
        provided in the SuppPrivInfo or SuppPubInfo subfield. The substrings 
        representing items of information that parties U and V choose not to 
        contribute are set equal to Null, and are represented in this 
        variable-length format by setting Datalen equal to zero. If a protocol 
        allows the use of the OtherInfo subfield SuppPrivInfo and/or the subfield
        SuppPubInfo, then the protocol shall specify the number, ordering and 
        meaning of additional items of information that may be used in the allowed
        subfield(s) and shall specify the fixed-length of the Datalen counters.
    
        5.8.1.2.2 The ASN.1 Format for OtherInfo
        
        The ASN.1 format for OtherInfo provides an alternative means of binding the
        derived keying material to the context of the key-agreement transaction, 
        independent of other actions taken by the relying application. Note: When
        the single-step KDF specified in Section 5.8.1.1 is used with H = hash as
        the auxiliary function and this ASN.1 format for OtherInfo, the resulting 
        key-derivation method is the ASN.1 Key Derivation Function specified in the
        original version of SP800-56A.
        
        For the ASN.1 format, OtherInfo is a bit string resulting from the ASN.1 
        DER encoding (see [ISO/IEC 8825-1]) of a data structure comprised of a 
        sequence of three required subfields AlgorithmID, PartyUInfo, and 
        PartyVInfo, and, optionally, a subfield SuppPubInfo and/or a subfield 
        SuppPrivInfo – as described in Section 5.8.1.2. A protocol using this format
        for OtherInfo shall specify the type, ordering and number of distinct items 
        of information included in each of the (three, four, or five) subfields 
        employed.
    
        5.8.1.2.3 Other Formats for OtherInfo
    
        Formats other than those provided in Sections 5.8.1.2.1 and 5.8.1.2.2 
        (e.g., those providing the items of information in a different arrangement)
        may be used for OtherInfo, but the contextspecific information described in
        the preceding sections should be included (see the discussion in Section
        5.8.1.2). This Recommendation makes no statement as to the adequacy of other
        formats.
    
*/
    /**
     * Single-Step KDF or Concat KDF
     * 
     * @public
     * @param {*} Z Z value
     * @param {*} keylen key length
     * @param {*} other_info otherInfo value
     * @param {*} hash_algo hash algorithm name. (default: 'sha-256')
     * @param {*} hash_type hash type. (default: 'hash')
     * @param {*} salt salt value.
     * @returns derived key.
     */
    singlestepKDF: function(Z, keylen, other_info, hash_algo = 'sha-256', hash_type = 'hash', salt)
    {
        function increaseCounter(cnt_bl)
        {
            var carry = 1;
            var j = 4;
    
            while (j-- && carry) {
                var x = cnt_bl[j] + carry;
                carry = x > 0xff ? 1 : 0;
                cnt_bl[j] = x & 0xff;
            }
        }
    
        var md = null;
    
        switch (hash_type.toLowerCase()) {
            case 'hash':
            case 'digest':
                hash_type = 'hash';
                md = jCastle.digest.create(hash_algo);
                break;
            case 'hmac':
            case 'hmac-hash':
                hash_type = 'hmac';
                if (!salt) throw jCastle.exception('SALT_NOT_SET', 'KDF001');
                md = jCastle.hmac.create(hash_algo);
                    break;
            default:
                throw jCastle.exception('UNKNOWN_ALGORITHM', 'KDF002');
        }
    
        var hashlen = jCastle.digest.getDigestLength(hash_algo);
        var reps = Math.ceil(keylen / hashlen);
        var UNSIGNED_INT_MAX_VALUE = 4294967295;
    
        if (keylen > hashlen * UNSIGNED_INT_MAX_VALUE) {
            throw jCastle.exception('KEYLEN_TOO_LARGE', 'KDF003'); // 2^32 - 1
        }
            
        if (reps > UNSIGNED_INT_MAX_VALUE) {
            throw jCastle.exception('KEY_DERIVATION_FAIL', 'KDF004');
        }
    
        var counter_block = Buffer.from([0,0,0,1]);
        var z = Buffer.from(Z, 'latin1');
        var otherInfo = Buffer.from(other_info, 'latin1');

        if (salt) salt = Buffer.from(salt, 'latin1');
        else salt = Buffer.alloc(0);

        var derived_key = Buffer.alloc(keylen);
        var pos = 0;
    
        for (var i = 0; i <= reps; i++) {
            md.start({
                algoName: hash_algo, 
                key: salt
            })
            .update(counter_block)
            .update(z)
            .update(otherInfo);
                
            var h = md.finalize();
                
            if (pos < keylen) {
                derived_key.set(h.slice(0, h.length > keylen - pos ? keylen - pos : h.length), pos);
                pos += h.length;
            }
    
            increaseCounter(counter_block);
        }
    
        return derived_key;
    },
    
    /*
    https://www.ietf.org/rfc/rfc2898.txt
    
       PBKDF1 applies a hash function, which shall be MD2 [6], MD5 [19] or
       SHA-1 [18], to derive keys. The length of the derived key is bounded
       by the length of the hash function output, which is 16 octets for MD2
       and MD5 and 20 octets for SHA-1. PBKDF1 is compatible with the key
       derivation process in PKCS #5 v1.5.
    
       PBKDF1 is recommended only for compatibility with existing
       applications since the keys it produces may not be large enough for
       some applications.
    
       PBKDF1 (P, S, c, dkLen)
    
       Options:        Hash       underlying hash function
    
       Input:          P          password, an octet string
                       S          salt, an eight-octet string
                       c          iteration count, a positive integer
                       dkLen      intended length in octets of derived key,
                                  a positive integer, at most 16 for MD2 or
                                  MD5 and 20 for SHA-1
    
       Output:         DK         derived key, a dkLen-octet string
    
       Steps:
    
          1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
             "derived key too long" and stop.
    
          2. Apply the underlying hash function Hash for c iterations to the
             concatenation of the password P and the salt S, then extract
             the first dkLen octets to produce a derived key DK:
    
                       T_1 = Hash (P || S) ,
                       T_2 = Hash (T_1) ,
                       ...
                       T_c = Hash (T_{c-1}) ,
                       DK = Tc<0..dkLen-1>
    
          3. Output the derived key DK.
    */
    /*
    PBKDF1 definition comes after openssl's EVP_BytesToKey. 
    because of that EVP_BytesToKey function can derives a key who's length is more than hash length.
    
    see http://stackoverflow.com/questions/8008253/c-sharp-version-of-openssl-evp-bytestokey-method
    https://gist.github.com/caspencer/1339719
    
    // M[] is an array of message digests
    // MD() is the message digest function.
    
    M[0] = MD(data . salt);
    for (i = 1; i < count; i++) M[0] = MD(M[0]);
    
    i=1
    while (data still needed for key and iv) {
        M[i] = MD(M[i-1] . data . salt);
        for (i = 1; i < count; i++) M[i] = MD(M[i]);
        i++;
    }
    
    If the salt is NULL, it is not used.
    The digests are concatenated together.
    M = M[0] . M[1] . M[2] .......
    
    */
    /**
     * PBKDF1 Key derive function.
     * 
     * @public
     * @param {buffer} password password value.
     * @param {buffer} salt salt value
     * @param {number} iterations iterations value.
     * @param {number} len key size.
     * @param {string} hash_algo hash algorithm name. (default: 'md5')
     * @returns derived key.
     */
    pbkdf1: function(password, salt, iterations, len, hash_algo = 'md5')
    {
        if (!iterations) iterations = 1;
        if (!salt || !salt.length) throw jCastle.exception('SALT_NOT_SET', 'KDF006');
        salt = Buffer.from(salt, 'latin1');
    
        var len_limit = jCastle.digest.getDigestLength(hash_algo);
        if (!len) len = len_limit;
    
        if (len > len_limit) throw jCastle.exception('DERIVED_KEY_TOO_LONG', 'KDF005');
    
        var md = jCastle.digest.create(hash_algo);
        var dk = md.start().update(password).update(salt).finalize();
    
        for (var i = 1; i < iterations; i++) {
            dk = md.digest(dk);
        }
    
        return Buffer.slice(dk, 0, len);
    },
    
    /*
    https://www.ietf.org/rfc/rfc2898.txt
    
       PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
       example) to derive keys. The length of the derived key is essentially
       unbounded. (However, the maximum effective search space for the
       derived key may be limited by the structure of the underlying
       pseudorandom function. See Appendix B.1 for further discussion.)
       PBKDF2 is recommended for new applications.
    
       PBKDF2 (P, S, c, dkLen)
    
       Options:        PRF        underlying pseudorandom function (hLen
                                  denotes the length in octets of the
                                  pseudorandom function output)
    
       Input:          P          password, an octet string
                       S          salt, an octet string
                       c          iteration count, a positive integer
                       dkLen      intended length in octets of the derived
                                  key, a positive integer, at most
                                  (2^32 - 1) * hLen
    
       Output:         DK         derived key, a dkLen-octet string
    
       Steps:
    
          1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
             stop.
    
          2. Let l be the number of hLen-octet blocks in the derived key,
             rounding up, and let r be the number of octets in the last
             block:
    
                       l = CEIL (dkLen / hLen) ,
                       r = dkLen - (l - 1) * hLen .
    
             Here, CEIL (x) is the "ceiling" function, i.e. the smallest
             integer greater than, or equal to, x.
    
          3. For each block of the derived key apply the function F defined
             below to the password P, the salt S, the iteration count c, and
             the block index to compute the block:
    
                       T_1 = F (P, S, c, 1) ,
                       T_2 = F (P, S, c, 2) ,
                       ...
                       T_l = F (P, S, c, l) ,
    
             where the function F is defined as the exclusive-or sum of the
             first c iterates of the underlying pseudorandom function PRF
             applied to the password P and the concatenation of the salt S
             and the block index i:
    
                       F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    
             where
    
                       U_1 = PRF (P, S || INT (i)) ,
                       U_2 = PRF (P, U_1) ,
                       ...
                       U_c = PRF (P, U_{c-1}) .
    
             Here, INT (i) is a four-octet encoding of the integer i, most
             significant octet first.
    
          4. Concatenate the blocks and extract the first dkLen octets to
             produce a derived key DK:
    
                       DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
    
          5. Output the derived key DK.
    
       Note. The construction of the function F follows a "belt-and-
       suspenders" approach. The iterates U_i are computed recursively to
       remove a degree of parallelism from an opponent; they are exclusive-
       ored together to reduce concerns about the recursion degenerating
       into a small set of values.
    */
    /**
     * PBKDF2 Key derive function
     * 
     * @public
     * @param {buffer} password password value.
     * @param {buffer} salt salt value
     * @param {number} iterations iterations value.
     * @param {number} len key size.
     * @param {string} hash_algo hash algorithm name. (default: 'sha-1')
     * @returns derived key.
     */
    pbkdf2: function(password, salt, iterations, len, hash_algo = 'sha-1')
    {
        if (!len) len = jCastle.digest.getDigestLength(hash_algo);
        if (!salt || !salt.length) throw jCastle.exception('SALT_NOT_SET', 'KDF007');
    
        var hmac_length = jCastle.digest.getDigestLength(hash_algo);
        var size = Math.ceil(len / hmac_length);
        var hmac = new jCastle.hmac(hash_algo);

        password = Buffer.from(password, 'latin1');
        salt = Buffer.from(salt, 'latin1');
    
        if (len > hmac_length * 0xFFFFFFFF) {
            throw jCastle.exception('DERIVED_KEY_TOO_LONG', 'KDF005');
        }
    
        function int32b2buf(i32)
        {
            var output = Buffer.alloc(4);
            var j = 0;
            for (var i = 0; i < 32; i += 8)
                output[j++] = (i32 >>> (24 - i % 32)) & 0xFF;
            return output;
        }
    
        function F(password, salt, iterations, i)
        {
            var t = Buffer.alloc(hmac_length);
            var s = Buffer.concat([salt, int32b2buf(i)]);
            var u;
    
            for (var j = 1; j <= iterations; j++) {
                u = hmac.start({ key: password }).update(s).finalize();
                t = Buffer.xor(t, u);
                s = u.slice(0);
            }
    
            return t;
        }
    
        var tmp = Buffer.alloc(len);
        var pos = 0;
            
        for(var i = 1; i <= size; i++) {
            var t = F(password, salt, iterations, i);
            if (pos < len) {
                tmp.set(t.slice(0, t.length > tmp.length - pos ? tmp.length - pos : t.length), pos);
                pos += t.length;
            }
        }
    
        return tmp;
    },
    
    
    // https://tools.ietf.org/html/rfc7292#appendix-B
    /*
    Appendix B.  Deriving Keys and IVs from Passwords and Salt
    
       Note that this method for password privacy mode is not recommended
       and is deprecated for new usage.  The procedures and algorithms
       defined in PKCS #5 v2.1 [13] [22] should be used instead.
       Specifically, PBES2 should be used as encryption scheme, with PBKDF2
       as the key derivation function.
    
       The method presented here is still used to generate the key in
       password integrity mode.
    
       We present here a general method for using a hash function to produce
       various types of pseudorandom bits from a password and a string of
       salt bits.  This method is used for password privacy mode and
       password integrity mode in the present standard.
    
    B.1.  Password Formatting
    
       The underlying password-based encryption methods in PKCS #5 v2.1 view
       passwords (and salt) as being simple byte strings.  The underlying
       password-based encryption methods and the underlying password-based
       authentication methods in this version of this document are similar.
    
       What's left unspecified in the above paragraph is precisely where the
       byte string representing a password comes from.  (This is not an
       issue with salt strings, since they are supplied as a password-based
       encryption (or authentication) parameter.)  PKCS #5 v2.1 says: "[...]
       a password is considered to be an octet string of arbitrary length
       whose interpretation as a text string is unspecified.  In the
       interest of interoperability, however, it is recommended that
       applications follow some common text encoding rules.  ASCII and UTF-8
       are two possibilities."
    
       In this specification, however, all passwords are created from
       BMPStrings with a NULL terminator.  This means that each character in
       the original BMPString is encoded in 2 bytes in big-endian format
       (most-significant byte first).  There are no Unicode byte order
       marks.  The 2 bytes produced from the last character in the BMPString
       are followed by 2 additional bytes with the value 0x00.
    
       To illustrate with a simple example, if a user enters the 6-character
       password "Beavis", the string that PKCS #12 implementations should
       treat as the password is the following string of 14 bytes:
    
       0x00 0x42 0x00 0x65 0x00 0x61 0x00 0x76 0x00 0x69 0x00 0x73 0x00 0x00
    
    B.2.  General Method
    
       Let H be a hash function built around a compression function f:
    
          Z_2^u x Z_2^v -> Z_2^u
    
       (that is, H has a chaining variable and output of length u bits, and
       the message input to the compression function of H is v bits).  The
       values for u and v are as follows:
    
               HASH FUNCTION     VALUE u        VALUE v
                 MD2, MD5          128            512
                   SHA-1           160            512
                  SHA-224          224            512
                  SHA-256          256            512
                  SHA-384          384            1024
                  SHA-512          512            1024
                SHA-512/224        224            1024
                SHA-512/256        256            1024
    
       Furthermore, let r be the iteration count.
    
       We assume here that u and v are both multiples of 8, as are the
       lengths of the password and salt strings (which we denote by p and s,
       respectively) and the number n of pseudorandom bits required.  In
       addition, u and v are of course non-zero.
    
       For information on security considerations for MD5 [19], see [25] and
       [1], and on those for MD2, see [18].
    
       The following procedure can be used to produce pseudorandom bits for
       a particular "purpose" that is identified by a byte called "ID".  The
       meaning of this ID byte will be discussed later.
    
       1.  Construct a string, D (the "diversifier"), by concatenating v/8
           copies of ID.
    
       2.  Concatenate copies of the salt together to create a string S of
           length v(ceiling(s/v)) bits (the final copy of the salt may be
           truncated to create S).  Note that if the salt is the empty
           string, then so is S.
    
       3.  Concatenate copies of the password together to create a string P
           of length v(ceiling(p/v)) bits (the final copy of the password
           may be truncated to create P).  Note that if the password is the
           empty string, then so is P.
    
       4.  Set I=S||P to be the concatenation of S and P.
    
       5.  Set c=ceiling(n/u).
    
       6.  For i=1, 2, ..., c, do the following:
    
           A.  Set A2=H^r(D||I). (i.e., the r-th hash of D||I,
               H(H(H(... H(D||I))))
    
           B.  Concatenate copies of Ai to create a string B of length v
               bits (the final copy of Ai may be truncated to create B).
    
           C.  Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
               blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
               setting I_j=(I_j+B+1) mod 2^v for each j.
    
       7.  Concatenate A_1, A_2, ..., A_c together to form a pseudorandom
           bit string, A.
    
       8.  Use the first n bits of A as the output of this entire process.
    
       If the above process is being used to generate a DES key, the process
       should be used to create 64 random bits, and the key's parity bits
       should be set after the 64 bits have been produced.  Similar concerns
       hold for 2-key and 3-key triple-DES keys, for CDMF keys, and for any
       similar keys with parity bits "built into them".
    
    B.3.  More on the ID Byte
    
       This standard specifies 3 different values for the ID byte mentioned
       above:
    
       1.  If ID=1, then the pseudorandom bits being produced are to be used
           as key material for performing encryption or decryption.
    
       2.  If ID=2, then the pseudorandom bits being produced are to be used
           as an IV (Initial Value) for encryption or decryption.
    
       3.  If ID=3, then the pseudorandom bits being produced are to be used
           as an integrity key for MACing.
    
    B.4.  Keys for Password Integrity Mode
    
       When password integrity mode is used to protect a PFX PDU, a password
       and salt are used to derive a MAC key.  As with password privacy
       mode, the password is a Unicode string, and the salt is a byte
       string.  No particular lengths are prescribed in this standard for
       either the password or the salt, but the general advice about
       passwords and salt that is given in Appendix C applies here, as well.
    
       The hash function used to derive MAC keys is whatever hash function
       is going to be used for MACing.  The MAC keys that are derived have
       the same length as the hash function's output.  In this version of
       this standard, SHA-1, SHA-224, SHA-256, SHA384, SHA-512, SHA-512/224,
       or SHA/512/256 can be used to perform MACing, and so the MAC keys can
       be 160, 224, 256, 384, or 512 bits.  See Appendix A for more
       information on MACing.
    */
    /**
     * PKCS#12 Key Derive Function.
     * @param {buffer} password password value
     * @param {buffer} salt salt value
     * @param {number} iterations iterations value
     * @param {number} id id value. id: 1 = Key, 2 = IV, 3 = MAC
     * @param {number} len key length.
     * @param {string} hash_algo hash algorithm name. (default: 'sha-1')
     * @param {buffer} bmpPassword password in bmp string. for test. OpenSSL acceps password as it is.
     * @returns 
     */
    pkcs12DeriveKey: function(password, salt, iterations, id, len, hash_algo = 'sha-1', bmpPassword)
    {
    //  function toBMPString(str)
    //  {
    //      var bmp_str = '';
    //      for (var i = 0; i < str.length; i++) {
    //          var c = str.charCodeAt(i);
    //          bmp_str += String.fromCharCode(c >>> 8 & 0xFF) + String.fromCharCode(c & 0xFF);
    //      }
    //      bmp_str += String.fromCharCode(0) + String.fromCharCode(0); // null terminate
    //      return bmp_str;
    //  }

        var bmp_pass;

        // test for vectors.
        // openssl's derive key function accepts password as it is,
        // and it is NOT transformed to a bmpstring.
        if (!password && bmpPassword) {
            bmp_pass = Buffer.from(bmpPassword, 'latin1');
        } else {
            password = Buffer.from(password, 'latin1');
            bmp_pass = Buffer.from(Buffer.toBmpString(password, 'latin1'), 'latin1');
        }
        if (!salt || !salt.length) throw jCastle.exception('SALT_NOT_SET', 'KDF008');
        salt = Buffer.from(salt, 'latin1');
    		
        var u = jCastle.digest.getDigestLength(hash_algo);
        var v = jCastle.digest.getBlockSize(hash_algo);
        var md = jCastle.digest.create(hash_algo);

            // console.log('password: ', password);
            // console.log('bmp_pass: ', bmp_pass);
            // console.log('salt:     ', salt);
    
        if (!len) len = jCastle.digest.getDigestLength(hash_algo);
    
        var Plen = v * Math.ceil(bmp_pass.length / v);
        var P = Buffer.alloc(Plen);
        for (var i = 0; i < Plen; i++) {
            P[i] = bmp_pass[i % bmp_pass.length];
        }
    
        var Slen = v * Math.ceil(salt.length / v);
        var S = Buffer.alloc(Slen);
        for (var i = 0; i < Slen; i++) {
            S[i] = salt[i % salt.length];
        }
    
        var D = Buffer.alloc(v, id);
        var Ai, dkey = Buffer.alloc(len), pos = 0;
            
        while (len) {
            Ai = md.start().update(D).update(S).update(P).finalize();
    
            for (i = 1; i < iterations; i++) {
                Ai = md.digest(Ai);
            }
    
            var use_len = len > u ? u : len;
    
            if (pos < dkey.length) {
                dkey.set(Ai.slice(0, use_len), pos);
                pos += use_len;
            }
    
            len -= use_len;
    
            if (len <= 0) {
                break;
            }
    
            // Concatenating copies of Ai into B
            var B = Buffer.alloc(v);
            for (i = 0; i < v; i++) {
                B[i] = Ai[i % Ai.length];
            }
    
            // B + 1
            var j = v;
            var carry = 1;
            while (j-- && carry) {
                var x = B[j] + carry;
                carry = x > 0xff ? 1 : 0;
                B[j] = x & 0xff;
            }
    
            var c = 0;
            for (i = v; i > 0; i--) {
                j = S[i - 1] + B[i - 1] + c;
                c = (j >>> 8)  & 0xff;
                S[i - 1] = j & 0xff;
            }
    
            c = 0;
            for (i = v; i > 0; i--) {
                j = P[i - 1] + B[i - 1] + c;
                c = (j >>> 8)  & 0xff;
                P[i - 1] = j & 0xff;
            }
        }
        return dkey;
    }
};
    
jCastle.KDF = jCastle.kdf;

module.exports = jCastle.kdf;    