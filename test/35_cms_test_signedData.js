const jCastle = require('../lib/index');
const QUnit = require('qunit');


//
// Test 1
//
QUnit.module("CMS");
QUnit.test("CMS Parsing Test", function(assert) {

	var signedData = `
    MIIHZwYJKoZIhvcNAQcCoIIHWDCCB1QCAQExDzANBglghkgBZQMEAgEFADATBgkq
    hkiG9w0BBwGgBgQEaW1nZ6CCBZ4wggWaMIIEhKADAgECAgQjSHwDMA0GCSqGSIb3
    DQEBCwUAMFIxCzAJBgNVBAYTAmtyMRAwDgYDVQQKDAd5ZXNzaWduMRUwEwYDVQQL
    DAxBY2NyZWRpdGVkQ0ExGjAYBgNVBAMMEXllc3NpZ25DQSBDbGFzcyAyMB4XDTE4
    MTEwNTE1MDAwMFoXDTE5MTEwNzE0NTk1OVowcjELMAkGA1UEBhMCa3IxEDAOBgNV
    BAoMB3llc3NpZ24xFDASBgNVBAsMC3BlcnNvbmFsNElCMQ0wCwYDVQQLDAROQUNG
    MSwwKgYDVQQDDCPqsJXsm5Drr7goKTAwMTEwNDMyMDA3MDgxNzExMTAwMDkxMTCC
    ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOYMcL/Z0TlPUcbvoHiVgJJT
    C6GYGLW1s5iAuBycmpuMLPynGR0PT1VwxqLfb6nP12fmCOy2zX2cUmuL1ONjxL8K
    G/AozFV5vIttSD6zAl7C5lSZQ9mFLEQkw2BKfsrgEmY2NTu6K5PVmFpPD1LqbGpM
    +2uWW/XYlts33M6nvR3+RoYa1Cej6oj5/70nlMyvcckSUWHgKRNQkVeeiibeKasw
    /UCvZKgenduvBXMptbaFNKQHNSxLZ5JKFbcE7qkYooBrsMdJQgjexnxgAx5CvTnB
    qwp+v+uvHwNrKnygOE6gBGTS+zkoJtECHf3fbWTSQGuZGzpG2LFmG8BVvW5CdMUC
    AwEAAaOCAlgwggJUMIGPBgNVHSMEgYcwgYSAFO/cRNLGjcAOozjAfJPGw0G/So/w
    oWikZjBkMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lTQTEuMCwGA1UECwwlS29y
    ZWEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgQ2VudHJhbDEWMBQGA1UEAwwNS0lT
    QSBSb290Q0EgNIICEBwwHQYDVR0OBBYEFC4lKKT1P2VtjIo/2HvCC/gNeKtpMA4G
    A1UdDwEB/wQEAwIGwDB5BgNVHSABAf8EbzBtMGsGCSqDGoyaRQEBBDBeMC4GCCsG
    AQUFBwICMCIeIMd0ACDHeMmdwRyylAAgrPXHeMd4yZ3BHAAgx4WyyLLkMCwGCCsG
    AQUFBwIBFiBodHRwOi8vd3d3Lnllc3NpZ24ub3Iua3IvY3BzLmh0bTBoBgNVHREE
    YTBfoF0GCSqDGoyaRAoBAaBQME4MCeqwleybkOuvuDBBMD8GCiqDGoyaRAoBAQEw
    MTALBglghkgBZQMEAgGgIgQgw8HxHqX1LaqXArEqMYb0vc+9hodjRHI+/zAGdwih
    PKwwcgYDVR0fBGswaTBnoGWgY4ZhbGRhcDovL2RzLnllc3NpZ24ub3Iua3I6Mzg5
    L291PWRwNXAzNjMxNixvdT1BY2NyZWRpdGVkQ0Esbz15ZXNzaWduLGM9a3I/Y2Vy
    dGlmaWNhdGVSZXZvY2F0aW9uTGlzdDA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUH
    MAGGHGh0dHA6Ly9vY3NwLnllc3NpZ24ub3JnOjQ2MTIwCwYJKoZIhvcNAQELA4IB
    AQA0nyso3DyR7lA/hHmrXdrfjuY1r8GzT2hHu39Dyyxw1rvBgo7fO9ZloXUTuuPw
    Q8OhJBYzQe7xn/iaGLD1fz1ki45NyPhHLCysEVxrZ0RpNpDYbRF0q+NPBUB6NF/u
    U39pGMmgH69Hgh0xkTaO7RbGKHnXLtfobzdDzal4vKomuHJtLcdzyqjZ1gZVx/1D
    LJFJZx/REq1uD+9NX6256NtENDGPyWQ1FekWR9e8TUE6Rie5Rt0uhH3Obr/4yuGY
    29ff7cnTQ7IWwpp2qpuZBWbOEDZ3a2etF36qPiid4yTfm6ce+QiAjPhI9OyI4mUW
    6tisvlxsjaHSV1cVqX9isrL/MYIBhTCCAYECAQEwWjBSMQswCQYDVQQGEwJrcjEQ
    MA4GA1UECgwHeWVzc2lnbjEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRowGAYDVQQD
    DBF5ZXNzaWduQ0EgQ2xhc3MgMgIEI0h8AzANBglghkgBZQMEAgEFADANBgkqhkiG
    9w0BAQEFAASCAQDa1dfkFFGASZ/oKIJyRgUboD2oKKFkisqoycufJ7PrrAl+wf1D
    voLnGZGQyTRURjswxAcBlie9+nIYxqFeGnEzdkAjTKlDSPp8+vozDVNvNsitEKkn
    89rSGHSEMmpbFkFimsmWRwh6/IneK0EhjUZMz32B5GkXpip3IP9gKOWq+zuG9xAK
    m5d7QCZSQwpCbM67Sa7KilNfT/Z0T59zFLDYO2i0rTgeCwa7IEmp6G7RpPNQ1mrR
    2Zctbdq56Q/IXg3UQQnP5BTewKQED4KPLm9FtYsByWtkEOj42eLSEmqs1rNCdhVy
    MfmI+/GilD+bRfu4nmGjAkdNqBr2Dh2MCOqL`;

	var cms_info = jCastle.cms.create().parse(signedData);

    // console.log('cms_info: ', cms_info);
    // console.log(cms_info.content.signerInfos);
    // console.log(cms_info.content.certificates);

	// var pptable = prettyPrint(cms_info);
	// document.getElementById('printarea').appendChild(pptable);

	// document.getElementById('printarea1').innerHTML = "<p>SingedData CMS Infomation Structure:<pre>\n<code>\n"+cms_info_stringify_data+"\n</code>\n</pre></p>";

    assert.ok(cms_info.validation, 'cms parsing test');
});

// console.log('--------------------------------------------------------------');
//
// Test 2
//


QUnit.test("CMS Parsing Test", function(assert) {

	var privkey_data = `
    30 82 05 10 30 1A 06 08 2A 83 1A 8C 9A 44 01 0F 30 0E 04 08 A3 5D B6 91 48 4F AB AD 02 02 04 00 
    04 82 04 F0 21 2B AA B6 16 DB 55 AB 53 E1 6E 54 24 86 26 69 FB D0 FF 4F DC F5 CF CB C3 69 48 C8 
    3E 34 8A 35 5A EE 4B A9 D4 BD F4 E4 97 5D 87 9B A3 03 F7 5D 87 02 E7 C5 BA 6C 69 32 8F D7 B8 69 
    BC 84 86 A7 B8 6E 80 6D B3 06 5F CF 14 B8 6B FD 85 61 79 CA BB 21 F4 B7 3A 99 42 2B 55 46 44 6B 
    65 6D EC 51 2B F2 E6 58 F0 87 4B DC FA 98 1A 45 27 BB 90 C3 A6 20 CC 57 0B 95 69 75 1F 67 B9 E6 
    D3 D4 C8 6D 90 FE 54 42 7F 5D 43 A7 02 63 D3 63 B6 D0 45 72 08 B3 DA 12 01 51 B9 75 23 50 B7 0D 
    BB 6A F1 D7 15 64 0B D5 FC ED C9 B2 0A 7A C1 90 FF 85 E3 70 78 40 4E 00 FF C8 B6 C0 B3 FA 8E 87 
    89 FC E4 4E DC 41 D1 08 74 FE 29 B7 81 FE F3 77 08 F9 12 29 21 FC DD 91 EA 42 F4 08 49 76 FD 21 
    4D E0 9E 53 42 4B AA 3A 60 91 73 30 EF 00 FF 74 1F 7A EA 5D FB 1F 2A 19 2A 17 5C D0 6B C2 00 B4 
    57 6F 43 68 A6 15 FE 06 2C 3A 73 C3 DC 09 BC 72 03 2D 39 6A CD 49 BE 8B 7E C7 4A 36 2F EB 31 FE 
    62 41 BC A8 24 BC 8A B9 66 5B 6E 85 55 2E B1 9C 34 C8 27 8B FD 6B B5 BC CA A9 9D D6 69 31 A9 A7 
    4C D3 B7 71 FE 56 2B 80 3A 5A 1E 87 EA AF D9 86 32 D1 5D 4A D9 9B 67 AE 4F C2 65 70 BD 55 4C B4 
    43 9A B9 1E 27 1D 02 12 BF DA 36 7C 5A 35 F9 28 67 6C 70 1E 61 8B B5 0B 02 68 C6 54 D5 49 A9 2C 
    81 78 50 6C AD 46 48 89 C6 3E EE 9B 39 33 60 22 A6 29 0F 90 DF BE E5 9E 67 D5 F6 80 7C 98 48 53 
    7A 16 A9 06 40 79 E6 76 A8 F7 89 E8 A6 67 A6 BC DD CE 3C 22 41 CE 0D 13 C0 F6 AE 1E 16 7F 9A 8E 
    03 BC B2 F6 53 63 B1 48 7C 50 8E 7B 4B 94 F8 63 67 7F B2 75 41 9A 68 69 94 63 4D 7B 7F 21 A9 F1 
    12 BC E9 0B 40 18 9C 73 56 89 50 2C 19 8F 0E C1 F2 D7 98 24 CE 59 CC 8E BD 3C C1 8A DC 20 6B BD 
    FC F8 01 45 3F 6A 51 68 D1 19 83 71 50 36 28 4C E7 4D F5 77 5D CE B9 DD 06 73 DF AE DE D4 C4 63 
    DA EC C0 17 8E 25 CE F5 9E E8 40 B0 46 68 25 03 49 C0 43 1B 48 EA 03 6A E5 0B 5F DE 22 22 1A 3E 
    61 A6 E4 91 0B 20 C5 66 C2 7D 97 94 DC B0 95 12 A7 83 03 BF 1D AA 59 02 CA 7D D1 6E 3E 1F 95 F6 
    4D 7E E7 01 46 0F 78 FF FE DA 52 A1 12 AF DD 4A C8 12 42 BA C8 B4 D3 3D E3 CE FB AD 10 11 FC BA 
    96 99 1D 13 20 BD 96 F8 EA 87 87 B7 51 C7 EB 85 84 FB 24 1E B1 08 BF B4 E4 9E FF FD 95 25 90 E0 
    56 67 DB 90 CC 8A BD 3B BE D3 8D 60 72 3E 3F F2 1B C3 D9 DB 40 43 2D 21 F1 99 0B E5 FC 11 9B 14 
    F0 8E 94 10 19 E6 9B 79 54 02 0E ED 9E 40 A0 82 3C C2 8A B9 9C 3C F5 9A D8 DE A2 91 D4 67 DA CA 
    19 28 6F CD 0A 96 5B B1 82 BD E9 C8 C7 F9 70 52 46 DF 67 B2 08 89 CD E4 65 EE 3B 29 94 30 8D 98 
    66 5C 96 F9 F7 35 0E A0 81 18 57 7F CF E0 E1 1D 18 0C 89 61 6D 4E FF EA 8E 8C C7 86 1C CD 44 10 
    58 2C 86 A6 0E F3 58 39 82 BD E5 E0 BF 22 CC 6E 6C 81 7A F7 E3 1B A0 7D 97 E1 93 9C B3 74 58 29 
    21 9A DD CF B2 69 C4 EE B3 93 38 40 3F 85 1A 8A D1 5B 1E B3 DA 19 FF 9B DD 0B 7B 07 14 DE 9D 25 
    B0 76 96 58 69 4D B4 E4 B0 67 A6 F4 FE B1 FF EB 0D 24 C9 1E 7F 30 A3 57 D5 15 2B 40 FB 9B 4F 75 
    D8 1D 5E 51 07 43 71 D5 C4 79 A1 65 C1 C4 A0 EE D6 F2 C9 7B C0 31 BF FF 26 96 7F 26 EF 65 52 1C 
    16 BE CA A2 34 13 38 42 0D 25 22 CD E9 CF 51 01 A4 0A DD FF D8 5C 60 21 7C C3 F5 D8 00 A7 5D 82 
    C3 1A A6 91 6F 25 E3 B8 12 78 04 5E AA FE C7 3B E1 CB 09 99 8D C4 B2 DC 46 55 74 E1 43 87 E3 97 
    8E BD B8 95 27 98 5C DB CE 98 EC 9F 5D DF BD 54 E5 45 3C 28 6A F6 4A D2 E3 F4 0E F8 49 2C F2 1D 
    51 2E 96 77 9C 9C 73 43 E9 14 3B C5 16 DB FA CC 9C 1E 78 97 B9 FA 9F 22 85 F5 BD 4A 14 11 2C 34 
    27 C3 9A 89 73 40 DF 82 CA D8 A1 F9 9E FF 07 E3 B6 69 A0 72 CA D8 9C 73 12 6E F1 F3 D3 3C A8 05 
    B6 C5 37 9E 5A 6B 97 13 19 8E 3D 22 33 DD DB DC 84 17 BE 37 DF 35 53 34 6F 31 09 7D DD CD 8B E1 
    DE 94 5F 36 CB B0 37 63 D4 9C BB 47 F1 83 38 A6 5F CF 76 03 E5 A9 D3 28 E9 C3 52 CE A4 7D AB 4B 
    1F EA 85 C4 90 92 C0 1B DF CB 92 BB 46 E9 86 5E 2A 25 FC F8 5D 28 7E 38 0A 27 13 27 D5 BE 36 83 
    38 B6 B1 77 EC CE B2 6D EB AE DC 2C 1B A5 52 AF 10 7A 37 4C 56 BA 36 70 6B A8 32 29 5F 13 16 67 
    F9 9D DC 13 7F 41 BF 55 2E A6 AC DD DC 60 2D CC 79 60 DA 28 02 2E 3E 48 DE 05 EF EF 15 91 CD 8A 
    20 0A 84 79 1F A9 B1 4D 22 FF B1 90 BC 0F 14 99 A3 12 1C 92`;

	var cert_data = `
    30 82 05 9A 30 82 04 84 A0 03 02 01 02 02 04 23 48 7C 03 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 
    05 00 30 52 31 0B 30 09 06 03 55 04 06 13 02 6B 72 31 10 30 0E 06 03 55 04 0A 0C 07 79 65 73 73 
    69 67 6E 31 15 30 13 06 03 55 04 0B 0C 0C 41 63 63 72 65 64 69 74 65 64 43 41 31 1A 30 18 06 03 
    55 04 03 0C 11 79 65 73 73 69 67 6E 43 41 20 43 6C 61 73 73 20 32 30 1E 17 0D 31 38 31 31 30 35 
    31 35 30 30 30 30 5A 17 0D 31 39 31 31 30 37 31 34 35 39 35 39 5A 30 72 31 0B 30 09 06 03 55 04 
    06 13 02 6B 72 31 10 30 0E 06 03 55 04 0A 0C 07 79 65 73 73 69 67 6E 31 14 30 12 06 03 55 04 0B 
    0C 0B 70 65 72 73 6F 6E 61 6C 34 49 42 31 0D 30 0B 06 03 55 04 0B 0C 04 4E 41 43 46 31 2C 30 2A 
    06 03 55 04 03 0C 23 EA B0 95 EC 9B 90 EB AF B8 28 29 30 30 31 31 30 34 33 32 30 30 37 30 38 31 
    37 31 31 31 30 30 30 39 31 31 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 
    0F 00 30 82 01 0A 02 82 01 01 00 E6 0C 70 BF D9 D1 39 4F 51 C6 EF A0 78 95 80 92 53 0B A1 98 18 
    B5 B5 B3 98 80 B8 1C 9C 9A 9B 8C 2C FC A7 19 1D 0F 4F 55 70 C6 A2 DF 6F A9 CF D7 67 E6 08 EC B6 
    CD 7D 9C 52 6B 8B D4 E3 63 C4 BF 0A 1B F0 28 CC 55 79 BC 8B 6D 48 3E B3 02 5E C2 E6 54 99 43 D9 
    85 2C 44 24 C3 60 4A 7E CA E0 12 66 36 35 3B BA 2B 93 D5 98 5A 4F 0F 52 EA 6C 6A 4C FB 6B 96 5B 
    F5 D8 96 DB 37 DC CE A7 BD 1D FE 46 86 1A D4 27 A3 EA 88 F9 FF BD 27 94 CC AF 71 C9 12 51 61 E0 
    29 13 50 91 57 9E 8A 26 DE 29 AB 30 FD 40 AF 64 A8 1E 9D DB AF 05 73 29 B5 B6 85 34 A4 07 35 2C 
    4B 67 92 4A 15 B7 04 EE A9 18 A2 80 6B B0 C7 49 42 08 DE C6 7C 60 03 1E 42 BD 39 C1 AB 0A 7E BF 
    EB AF 1F 03 6B 2A 7C A0 38 4E A0 04 64 D2 FB 39 28 26 D1 02 1D FD DF 6D 64 D2 40 6B 99 1B 3A 46 
    D8 B1 66 1B C0 55 BD 6E 42 74 C5 02 03 01 00 01 A3 82 02 58 30 82 02 54 30 81 8F 06 03 55 1D 23 
    04 81 87 30 81 84 80 14 EF DC 44 D2 C6 8D C0 0E A3 38 C0 7C 93 C6 C3 41 BF 4A 8F F0 A1 68 A4 66 
    30 64 31 0B 30 09 06 03 55 04 06 13 02 4B 52 31 0D 30 0B 06 03 55 04 0A 0C 04 4B 49 53 41 31 2E 
    30 2C 06 03 55 04 0B 0C 25 4B 6F 72 65 61 20 43 65 72 74 69 66 69 63 61 74 69 6F 6E 20 41 75 74 
    68 6F 72 69 74 79 20 43 65 6E 74 72 61 6C 31 16 30 14 06 03 55 04 03 0C 0D 4B 49 53 41 20 52 6F 
    6F 74 43 41 20 34 82 02 10 1C 30 1D 06 03 55 1D 0E 04 16 04 14 2E 25 28 A4 F5 3F 65 6D 8C 8A 3F 
    D8 7B C2 0B F8 0D 78 AB 69 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 06 C0 30 79 06 03 55 1D 20 
    01 01 FF 04 6F 30 6D 30 6B 06 09 2A 83 1A 8C 9A 45 01 01 04 30 5E 30 2E 06 08 2B 06 01 05 05 07 
    02 02 30 22 1E 20 C7 74 00 20 C7 78 C9 9D C1 1C B2 94 00 20 AC F5 C7 78 C7 78 C9 9D C1 1C 00 20 
    C7 85 B2 C8 B2 E4 30 2C 06 08 2B 06 01 05 05 07 02 01 16 20 68 74 74 70 3A 2F 2F 77 77 77 2E 79 
    65 73 73 69 67 6E 2E 6F 72 2E 6B 72 2F 63 70 73 2E 68 74 6D 30 68 06 03 55 1D 11 04 61 30 5F A0 
    5D 06 09 2A 83 1A 8C 9A 44 0A 01 01 A0 50 30 4E 0C 09 EA B0 95 EC 9B 90 EB AF B8 30 41 30 3F 06 
    0A 2A 83 1A 8C 9A 44 0A 01 01 01 30 31 30 0B 06 09 60 86 48 01 65 03 04 02 01 A0 22 04 20 C3 C1 
    F1 1E A5 F5 2D AA 97 02 B1 2A 31 86 F4 BD CF BD 86 87 63 44 72 3E FF 30 06 77 08 A1 3C AC 30 72 
    06 03 55 1D 1F 04 6B 30 69 30 67 A0 65 A0 63 86 61 6C 64 61 70 3A 2F 2F 64 73 2E 79 65 73 73 69 
    67 6E 2E 6F 72 2E 6B 72 3A 33 38 39 2F 6F 75 3D 64 70 35 70 33 36 33 31 36 2C 6F 75 3D 41 63 63 
    72 65 64 69 74 65 64 43 41 2C 6F 3D 79 65 73 73 69 67 6E 2C 63 3D 6B 72 3F 63 65 72 74 69 66 69 
    63 61 74 65 52 65 76 6F 63 61 74 69 6F 6E 4C 69 73 74 30 38 06 08 2B 06 01 05 05 07 01 01 04 2C 
    30 2A 30 28 06 08 2B 06 01 05 05 07 30 01 86 1C 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 79 65 73 73 
    69 67 6E 2E 6F 72 67 3A 34 36 31 32 30 0B 06 09 2A 86 48 86 F7 0D 01 01 0B 03 82 01 01 00 34 9F 
    2B 28 DC 3C 91 EE 50 3F 84 79 AB 5D DA DF 8E E6 35 AF C1 B3 4F 68 47 BB 7F 43 CB 2C 70 D6 BB C1 
    82 8E DF 3B D6 65 A1 75 13 BA E3 F0 43 C3 A1 24 16 33 41 EE F1 9F F8 9A 18 B0 F5 7F 3D 64 8B 8E 
    4D C8 F8 47 2C 2C AC 11 5C 6B 67 44 69 36 90 D8 6D 11 74 AB E3 4F 05 40 7A 34 5F EE 53 7F 69 18 
    C9 A0 1F AF 47 82 1D 31 91 36 8E ED 16 C6 28 79 D7 2E D7 E8 6F 37 43 CD A9 78 BC AA 26 B8 72 6D 
    2D C7 73 CA A8 D9 D6 06 55 C7 FD 43 2C 91 49 67 1F D1 12 AD 6E 0F EF 4D 5F AD B9 E8 DB 44 34 31 
    8F C9 64 35 15 E9 16 47 D7 BC 4D 41 3A 46 27 B9 46 DD 2E 84 7D CE 6E BF F8 CA E1 98 DB D7 DF ED 
    C9 D3 43 B2 16 C2 9A 76 AA 9B 99 05 66 CE 10 36 77 6B 67 AD 17 7E AA 3E 28 9D E3 24 DF 9B A7 1E 
    F9 08 80 8C F8 48 F4 EC 88 E2 65 16 EA D8 AC BE 5C 6C 8D A1 D2 57 57 15 A9 7F 62 B2 B2 FF`;

	var signed_data = `
    30 82 07 67 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 07 58 30 82 07 54 02 01 01 31 0F 30 0D 06 09 
    60 86 48 01 65 03 04 02 01 05 00 30 13 06 09 2A 86 48 86 F7 0D 01 07 01 A0 06 04 04 69 6D 67 67 
    A0 82 05 9E 30 82 05 9A 30 82 04 84 A0 03 02 01 02 02 04 23 48 7C 03 30 0D 06 09 2A 86 48 86 F7 
    0D 01 01 0B 05 00 30 52 31 0B 30 09 06 03 55 04 06 13 02 6B 72 31 10 30 0E 06 03 55 04 0A 0C 07 
    79 65 73 73 69 67 6E 31 15 30 13 06 03 55 04 0B 0C 0C 41 63 63 72 65 64 69 74 65 64 43 41 31 1A 
    30 18 06 03 55 04 03 0C 11 79 65 73 73 69 67 6E 43 41 20 43 6C 61 73 73 20 32 30 1E 17 0D 31 38 
    31 31 30 35 31 35 30 30 30 30 5A 17 0D 31 39 31 31 30 37 31 34 35 39 35 39 5A 30 72 31 0B 30 09 
    06 03 55 04 06 13 02 6B 72 31 10 30 0E 06 03 55 04 0A 0C 07 79 65 73 73 69 67 6E 31 14 30 12 06 
    03 55 04 0B 0C 0B 70 65 72 73 6F 6E 61 6C 34 49 42 31 0D 30 0B 06 03 55 04 0B 0C 04 4E 41 43 46 
    31 2C 30 2A 06 03 55 04 03 0C 23 EA B0 95 EC 9B 90 EB AF B8 28 29 30 30 31 31 30 34 33 32 30 30 
    37 30 38 31 37 31 31 31 30 30 30 39 31 31 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 
    00 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00 E6 0C 70 BF D9 D1 39 4F 51 C6 EF A0 78 95 80 92 53 
    0B A1 98 18 B5 B5 B3 98 80 B8 1C 9C 9A 9B 8C 2C FC A7 19 1D 0F 4F 55 70 C6 A2 DF 6F A9 CF D7 67 
    E6 08 EC B6 CD 7D 9C 52 6B 8B D4 E3 63 C4 BF 0A 1B F0 28 CC 55 79 BC 8B 6D 48 3E B3 02 5E C2 E6 
    54 99 43 D9 85 2C 44 24 C3 60 4A 7E CA E0 12 66 36 35 3B BA 2B 93 D5 98 5A 4F 0F 52 EA 6C 6A 4C 
    FB 6B 96 5B F5 D8 96 DB 37 DC CE A7 BD 1D FE 46 86 1A D4 27 A3 EA 88 F9 FF BD 27 94 CC AF 71 C9 
    12 51 61 E0 29 13 50 91 57 9E 8A 26 DE 29 AB 30 FD 40 AF 64 A8 1E 9D DB AF 05 73 29 B5 B6 85 34 
    A4 07 35 2C 4B 67 92 4A 15 B7 04 EE A9 18 A2 80 6B B0 C7 49 42 08 DE C6 7C 60 03 1E 42 BD 39 C1 
    AB 0A 7E BF EB AF 1F 03 6B 2A 7C A0 38 4E A0 04 64 D2 FB 39 28 26 D1 02 1D FD DF 6D 64 D2 40 6B 
    99 1B 3A 46 D8 B1 66 1B C0 55 BD 6E 42 74 C5 02 03 01 00 01 A3 82 02 58 30 82 02 54 30 81 8F 06 
    03 55 1D 23 04 81 87 30 81 84 80 14 EF DC 44 D2 C6 8D C0 0E A3 38 C0 7C 93 C6 C3 41 BF 4A 8F F0 
    A1 68 A4 66 30 64 31 0B 30 09 06 03 55 04 06 13 02 4B 52 31 0D 30 0B 06 03 55 04 0A 0C 04 4B 49 
    53 41 31 2E 30 2C 06 03 55 04 0B 0C 25 4B 6F 72 65 61 20 43 65 72 74 69 66 69 63 61 74 69 6F 6E 
    20 41 75 74 68 6F 72 69 74 79 20 43 65 6E 74 72 61 6C 31 16 30 14 06 03 55 04 03 0C 0D 4B 49 53 
    41 20 52 6F 6F 74 43 41 20 34 82 02 10 1C 30 1D 06 03 55 1D 0E 04 16 04 14 2E 25 28 A4 F5 3F 65 
    6D 8C 8A 3F D8 7B C2 0B F8 0D 78 AB 69 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 06 C0 30 79 06 
    03 55 1D 20 01 01 FF 04 6F 30 6D 30 6B 06 09 2A 83 1A 8C 9A 45 01 01 04 30 5E 30 2E 06 08 2B 06 
    01 05 05 07 02 02 30 22 1E 20 C7 74 00 20 C7 78 C9 9D C1 1C B2 94 00 20 AC F5 C7 78 C7 78 C9 9D 
    C1 1C 00 20 C7 85 B2 C8 B2 E4 30 2C 06 08 2B 06 01 05 05 07 02 01 16 20 68 74 74 70 3A 2F 2F 77 
    77 77 2E 79 65 73 73 69 67 6E 2E 6F 72 2E 6B 72 2F 63 70 73 2E 68 74 6D 30 68 06 03 55 1D 11 04 
    61 30 5F A0 5D 06 09 2A 83 1A 8C 9A 44 0A 01 01 A0 50 30 4E 0C 09 EA B0 95 EC 9B 90 EB AF B8 30 
    41 30 3F 06 0A 2A 83 1A 8C 9A 44 0A 01 01 01 30 31 30 0B 06 09 60 86 48 01 65 03 04 02 01 A0 22 
    04 20 C3 C1 F1 1E A5 F5 2D AA 97 02 B1 2A 31 86 F4 BD CF BD 86 87 63 44 72 3E FF 30 06 77 08 A1 
    3C AC 30 72 06 03 55 1D 1F 04 6B 30 69 30 67 A0 65 A0 63 86 61 6C 64 61 70 3A 2F 2F 64 73 2E 79 
    65 73 73 69 67 6E 2E 6F 72 2E 6B 72 3A 33 38 39 2F 6F 75 3D 64 70 35 70 33 36 33 31 36 2C 6F 75 
    3D 41 63 63 72 65 64 69 74 65 64 43 41 2C 6F 3D 79 65 73 73 69 67 6E 2C 63 3D 6B 72 3F 63 65 72 
    74 69 66 69 63 61 74 65 52 65 76 6F 63 61 74 69 6F 6E 4C 69 73 74 30 38 06 08 2B 06 01 05 05 07 
    01 01 04 2C 30 2A 30 28 06 08 2B 06 01 05 05 07 30 01 86 1C 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 
    79 65 73 73 69 67 6E 2E 6F 72 67 3A 34 36 31 32 30 0B 06 09 2A 86 48 86 F7 0D 01 01 0B 03 82 01 
    01 00 34 9F 2B 28 DC 3C 91 EE 50 3F 84 79 AB 5D DA DF 8E E6 35 AF C1 B3 4F 68 47 BB 7F 43 CB 2C 
    70 D6 BB C1 82 8E DF 3B D6 65 A1 75 13 BA E3 F0 43 C3 A1 24 16 33 41 EE F1 9F F8 9A 18 B0 F5 7F 
    3D 64 8B 8E 4D C8 F8 47 2C 2C AC 11 5C 6B 67 44 69 36 90 D8 6D 11 74 AB E3 4F 05 40 7A 34 5F EE 
    53 7F 69 18 C9 A0 1F AF 47 82 1D 31 91 36 8E ED 16 C6 28 79 D7 2E D7 E8 6F 37 43 CD A9 78 BC AA 
    26 B8 72 6D 2D C7 73 CA A8 D9 D6 06 55 C7 FD 43 2C 91 49 67 1F D1 12 AD 6E 0F EF 4D 5F AD B9 E8 
    DB 44 34 31 8F C9 64 35 15 E9 16 47 D7 BC 4D 41 3A 46 27 B9 46 DD 2E 84 7D CE 6E BF F8 CA E1 98 
    DB D7 DF ED C9 D3 43 B2 16 C2 9A 76 AA 9B 99 05 66 CE 10 36 77 6B 67 AD 17 7E AA 3E 28 9D E3 24 
    DF 9B A7 1E F9 08 80 8C F8 48 F4 EC 88 E2 65 16 EA D8 AC BE 5C 6C 8D A1 D2 57 57 15 A9 7F 62 B2 
    B2 FF 31 82 01 85 30 82 01 81 02 01 01 30 5A 30 52 31 0B 30 09 06 03 55 04 06 13 02 6B 72 31 10 
    30 0E 06 03 55 04 0A 0C 07 79 65 73 73 69 67 6E 31 15 30 13 06 03 55 04 0B 0C 0C 41 63 63 72 65 
    64 69 74 65 64 43 41 31 1A 30 18 06 03 55 04 03 0C 11 79 65 73 73 69 67 6E 43 41 20 43 6C 61 73 
    73 20 32 02 04 23 48 7C 03 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 30 0D 06 09 2A 86 48 86 
    F7 0D 01 01 01 05 00 04 82 01 00 DA D5 D7 E4 14 51 80 49 9F E8 28 82 72 46 05 1B A0 3D A8 28 A1 
    64 8A CA A8 C9 CB 9F 27 B3 EB AC 09 7E C1 FD 43 BE 82 E7 19 91 90 C9 34 54 46 3B 30 C4 07 01 96 
    27 BD FA 72 18 C6 A1 5E 1A 71 33 76 40 23 4C A9 43 48 FA 7C FA FA 33 0D 53 6F 36 C8 AD 10 A9 27 
    F3 DA D2 18 74 84 32 6A 5B 16 41 62 9A C9 96 47 08 7A FC 89 DE 2B 41 21 8D 46 4C CF 7D 81 E4 69 
    17 A6 2A 77 20 FF 60 28 E5 AA FB 3B 86 F7 10 0A 9B 97 7B 40 26 52 43 0A 42 6C CE BB 49 AE CA 8A 
    53 5F 4F F6 74 4F 9F 73 14 B0 D8 3B 68 B4 AD 38 1E 0B 06 BB 20 49 A9 E8 6E D1 A4 F3 50 D6 6A D1 
    D9 97 2D 6D DA B9 E9 0F C8 5E 0D D4 41 09 CF E4 14 DE C0 A4 04 0F 82 8F 2E 6F 45 B5 8B 01 C9 6B 
    64 10 E8 F8 D9 E2 D2 12 6A AC D6 B3 42 76 15 72 31 F9 88 FB F1 A2 94 3F 9B 45 FB B8 9E 61 A3 02 
    47 4D A8 1A F6 0E 1D 8C 08 EA 8B`;

	var password = 'sdh-060206';

	privkey_data = Buffer.from(privkey_data.replace(/[^0-9A-Z]/ig, ''), 'hex');
	cert_data = Buffer.from(cert_data.replace(/[^0-9A-Z]/ig, ''), 'hex');
	signed_data = Buffer.from(signed_data.replace(/[^0-9A-Z]/ig, ''), 'hex');

	// private key for signing
	var pki = new jCastle.pki();
	pki.parsePrivateKey(privkey_data, password);

	// certificate for signed data
	var cert = new jCastle.certificate();
	var cert_info = cert.parse(cert_data);

    // console.log('cert_info: ', cert_info);

    var signed_data_parsed = jCastle.cms.create().parse(signed_data);
    // console.log(signed_data_parsed);

	//
	// parse cms
	//
	var cms = jCastle.cms.create();

	var content = 'imgg';
	// var cms_info_text = document.getElementById('cms_info_text').innerText;
    var cms_info_text = `
    {
        "contentType": "signedData",
        "content": {
            "signerInfos": [
                {
                    "digestAlgorithm": "sha-256",
                    "signatureAlgorithm": {
                        "algo": "RSA",
                        "padding": {
                            "mode": "RSAES-PKCS-V1_5" // PKCS1_Type_2
                        }
                    }
                }
            ]
        }
    }`;

	cms_info_text = cms_info_text.trim();
	cms_info_text = cms_info_text.replace(/\/\/[^\n]*\n/g, ''); // remove comment or JSON will give you an parsing error

	var cms_info = JSON.parse(cms_info_text);

//	cms_info.content.encapContentInfo.content = content;
//	cms_info.content.signerInfos[0].signerIdentifier.issuer = cert_info.tbs.issuer;
//	cms_info.content.signerInfos[0].signerIdentifier.serialNumber = cert_info.tbs.serialNumber;
//	cms_info.content.certificates.push(cert_data);

/*
	var cms_info = {
		"contentType": "signedData",
		"content": {
			"digestAlgorithms": [
				"sha-256"
			],
			"signerInfos": [
				{
					"digestAlgorithm": "sha-256",
					"signatureAlgorithm": {
						"algo": "RSA",
						"encoding": {
							"mode": "RSAES-PKCS-V1_5"
						}
					}
				}
			]
		}
	};

	// input data
	var signed_data = cms.exportCMS(cms_info, {
		format: 'base64', 
		privateKey: pki,
		certificates: [
			originator_certificate, // for signerIdentifier
		],
		content: content
	});
*/

	var signed_pem = cms.exportCMS(cms_info, {
		format: 'pem',
		cmsKey: {
			privateKey: privkey_data,
			password: password,
			certificate: cert_data
		},
		certificates: [cert_data],
		content: content
	});

    // console.log('signed_pem: ', signed_pem);

	var cms_info2 = cms.parse(signed_pem);

    // console.log('cms_info2: ', cms_info2);

	assert.equal(cms_info2.content.encapContentInfo.content.toString(), content, 'CMS SignedData parsing test');
    // console.log('CMS SignedData parsing test: ', cms_info2.content.encapContentInfo.content.toString() ==content);

	// var pptable = prettyPrint(cms_info);
	// document.getElementById('printarea').appendChild(pptable);


});

// console.log('--------------------------------------------------------------');

QUnit.test("CMS signedData - export / parse Test", function(assert) {

	var private_pem = `
	-----BEGIN RSA PRIVATE KEY-----
	MIIEowIBAAKCAQEAd75gcW+OTGaofS9S3JNJ3dYfsKQZyZG1g0VmFgTh1L+EfwPn
	SH1iUg3ClBFdK1FPvQmPQaaMfny339g4ZeYkknBg7ia6V0hMVkwPhjxwWMY6nv49
	zOpB/yxocugc7S4OfYrVcRiS1v1RBLwuExvDLOmf2jk6NOFywrdvZi4aTNDr4ISc
	HZc3io2kmqPO6SvGhnAC1FEIa+j3Za2i5xMDlOFMsqxg4s0tk43f4d8o9B902T/l
	fwN/onWpqyCgt9bf0mIWWzK8cjGg0vbnzcNfIPF6wEBygl2zqvbESGFqT8G7sJLj
	kmZed7R/D3IZMDg1wd6d/Z2zJ6n5SzRkcTVYUQIDAQABAoIBAA1X6plZbAr5eZcR
	mfM4eoe836UodDMxCIALULftbVjuyo342mIKjtVD8UXctXwpQHB5SzxumcNSlI7e
	IlLAlZy35yVCrYsiZFdNfIFh5McPt+KVxD88b4RG55C+atLHShgVS3mh2mMYsVmM
	urmoY1Ry6DxCGklgQhCOrlw9kPK0QXM+JW+3OGabOzP6BbaNLeGXDCChkJI8D7/l
	5P9t6vgHaUrrYYMNE74nrrsCCn8T0v84spKG6ZyA0i1nydB3MmP5GDzZcEtfjgpM
	TkjJMztSUsJaLHQ1uM5s58ZIVNS/udfcR/6o3PmqYnQQWm9oPdKPdF562fbmTpzF
	iC9bbe0CgYEA1junKEkzfGAmCaCQaB6nNBHAr8C5WdLgmkZRtVRNnUNSP1V3r4V9
	bwiPSVE49+PbWNduIJo8PRxfb5Gm1W+4Zyrh6vnp2/52j9R6gV6+WqXuTavDiCQi
	+NvANubaJwX9wA5Rd5TEjzut8ThdQgAZWKAdOtSf/sy6zkHKBNlPu5MCgYEAjxbF
	GeK9HW2mvpWjTzbxpS7KHaFcrcxvUXNuZ7m4Gag79nZQ5XCSEuj1p0L6MtjejhtH
	heTC6IZ+CIZs0PyTu3Ygo8H5pkTVaZ2wgVEi8/yferx4MKNZk6Ya0UYutlU1bqko
	JyWHUkh+A6Qnk7edrnJev2PE3cNH3z9A5+wuMwsCgYEActD9wYWZ5mrReA9p1aO4
	ERwCnS85J37xiT1uxTQtdL+D8RWpU5TDqSJ5SN4THigsguzSxP5kkowGShFRzMpX
	llNRSVIvmAxFFsjV70gL1SFhGpeX7/sOEzoTRllrScbYPHpwBxrgTbO6gbGnqZvL
	+ce2YrVaGoE3DRwNXZPqO6kCgYCKlkAy0SPfw9szThVNXObw2P+TcT0lbBMJLabq
	ObuwxfvFu1Sg1MX2IMIEzV8tLlVoB83fRfDta43YTfJI+8lOUJxOX0qgGp0k3UEe
	Duquq6f/JVm3qg7RbZkdxj7qBF9rHdUxDS0iqem7NxvJ+5ZyZn2UG1qKe2A6PrZr
	qpoYfwKBgJ2Vxcy/PlEKeM6IFB97mKOSt8vP3c77kJVEDUoTqskgmGatd/EweBkW
	qW4xLcm4+R/Iq9ZQKTNcc3CXIrE/n0ApaT1MatSorWamT49T7R+mJ/rz+AlqvQ+m
	vupbfQ4R+68KsjpnE7JJiHhiVnqz+GE3YJMPLFot32fZB9Oj1Dyr
	-----END RSA PRIVATE KEY-----`;

    var password = 'password';

    var bits = 1024;

	/* root */

	var root = new jCastle.pki('RSA');
	root.parsePrivateKey(private_pem);

	var issuer = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Chungcheongbuk-do'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'localityName',
        value: 'Cheongju'
    }, {
        name: 'organizationName',
        value: 'jCastle Corp'
    }, {
        name: 'organizationalUnitName',
        value: 'WebCert Support'
    }, {
        name: 'commonName',
        value: 'jCastle Web CA'
    }, {
        name: 'emailAddress',
        value: 'support@jcastle.net'
    }];


	/* alice */

	var alice = jCastle.pki.create('RSA');
	alice.generateKeypair({
        bits: bits,
        exponent: 0x10001
    });
	var alice_privkey_pem = alice.exportPrivateKey({ password: password });

    // console.log('alice private key:');
    // console.log(alice_privkey_pem);

	var alice_subject = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Seoul'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'organizationName',
        value: 'DACOCHE'
    }, {
        name: 'commonName',
        value: 'Dacoche Web Flatform'
    }];

	var alice_cert_info = {
		type: jCastle.certificate.typeCRT,
		tbs: {
			serial: 750365,
			issuer: issuer,
			subject: alice_subject,
			subjectPublicKeyInfo: alice.getPublicKeyInfo()
		},
		algo: {
			signHash: 'SHA-256',
			signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'EC', 'DSA'
		}
	};

	var alice_cert = jCastle.certificate.create();
	alice_cert.setSignKey(root);
	var alice_cert_pem = alice_cert.exportCertificate(alice_cert_info);

    // console.log('alice certificate:');
    // console.log(alice_cert_pem);

	/* bob */
	/* signed data need no bob's public key nor certificate */

/*
	var bob = jCastle.pki.create('RSA');
	bob.generateKeypair({
        bits: bits,
        exponent: 0x10001
    });
	var bob_privkey_pem = bob.exportPrivateKey({password: password});

	var bob_subject = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Seoul'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'organizationName',
        value: 'Hareem'
    }, {
        name: 'commonName',
        value: 'Hareem Food'
    }];

	var bob_cert_info = {
		type: jCastle.certificate.typeCRT,
		tbs: {
			serial: 6649112,
			issuer: issuer,
			subject: bob_subject,
			subjectPublicKeyInfo: bob.getPublicKeyInfo()
		},
		algo: {
			signHash: 'SHA-256',
			signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'EC', 'DSA'
		}
	};

	var bob_cert = jCastle.certificate.create();
	bob_cert.setSignKey(root);
	var bob_cert_pem = bob_cert.exportCertificate(bob_cert_info);
*/

	/* alice exports cms with signedData */

	var content = 'alice the queen!';

	var cms_info = {
		"contentType": "signedData",
		"content": {
			"digestAlgorithms": [
				"sha-256"
			],
			"signerInfos": [
				{
					"digestAlgorithm": "sha-256",
					"signatureAlgorithm": {
						"algo": "RSA",
						"padding": {
							"mode": "RSAES-PKCS-V1_5" // PKCS1_Type_2
						}
					}
				}
			]
		}
	};

	var cms = jCastle.cms.create();

	var cms_signed_data_pem = cms.exportCMS(cms_info, {
		format: 'pem', 
		cmsKey: {
			privateKey: alice_privkey_pem,
			password: password,
			certificate: alice_cert_pem
		},
		certificates: [alice_cert_pem],
		// crls: [
		//	alice_crl_pem
		// ],
		content: content
	});

    // console.log('alice create signed data:');
    // console.log(cms_signed_data_pem);

	/* bob parses cms pem and verifies it */

	var cms_info = cms.parse(cms_signed_data_pem);

    // console.log('cms_info: ', cms_info);

	assert.equal(cms_info.content.encapContentInfo.content.toString(), content, 'CMS SignedData parsing test');
    // console.log('CMS SignedData parsing test: ', cms_info.content.encapContentInfo.content.equals(content));

	assert.ok(jCastle.cms.verifySignedData(cms_info), 'CMS SignedData verify test');
    // console.log('CMS SignedData verify test: ', jCastle.cms.verifySignedData(cms_info));

});


// console.log('--------------------------------------------------------------');

//
// Test 3
//

QUnit.test("CMS Parsing Test", function(assert) {
    /*
    openssl cms -sign -in content.txt -aes128 -nosmimecap -signer certificate.pem -inkey private-key.pem -nodetach -out signed-data-2-noattr.pem -outform PEM
    */
    var signedData = `
    -----BEGIN CMS-----
    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
    j0yIIMI9oMuQOn6T0FqIf2Fy24X5Ug==
    -----END CMS-----`;

    var cms_info = jCastle.cms.create().parse(signedData);
    
	// console.log(cms_info);
    // console.log(cms_info.content.signerInfos);
    // console.log(cms_info.content.certificates);
    // console.log(cms_info.content.encapContentInfo.content.toString());
    // console.log(cms_info.content.signerInfos[0].signerIdentifier.serialNumber.toString());
    
    // var pptable = prettyPrint(cms_info);
    // document.getElementById('printarea').appendChild(pptable);
    
    // document.getElementById('printarea1').innerHTML = "<p>SingedData CMS Infomation Structure:<pre>\n<code>\n"+cms_info_stringify_data+"\n</code>\n</pre></p>";

    assert.ok(cms_info.validation, 'cms parsing test');
    assert.ok(cms_info.content.encapContentInfo.content.toString() == 'hello world!', 'cms content test');
});

