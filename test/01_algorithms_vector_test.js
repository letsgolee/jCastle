
const QUnit = require('qunit');
const jCastle = require('../lib/index');

QUnit.module('Anubis');
QUnit.test("Vector Test", function(assert) {
	//Test vectors : key_length, pt, ct, key
	
	var testVectors = [
		// 128 bit keys
		[
		   16,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xF0, 0x68, 0x60, 0xFC, 0x67, 0x30, 0xE8, 0x18, 
			 0xF1, 0x32, 0xC7, 0x8A, 0xF4, 0x13, 0x2A, 0xFE ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   16,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xA8, 0x66, 0x84, 0x80, 0x07, 0x74, 0x5C, 0x89, 
			 0xFC, 0x5E, 0xB5, 0xBA, 0xD4, 0xFE, 0x32, 0x6D ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 160-bit keys
		[
		   20,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xBD, 0x5E, 0x32, 0xBE, 0x51, 0x67, 0xA8, 0xE2,
			 0x72, 0xD7, 0x95, 0x0F, 0x83, 0xC6, 0x8C, 0x31 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   20,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x4C, 0x1F, 0x86, 0x2E, 0x11, 0xEB, 0xCE, 0xEB,
			 0xFE, 0xB9, 0x73, 0xC9, 0xDF, 0xEF, 0x7A, 0xDB ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 192-bit keys 
		[
		   24,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x17, 0xAC, 0x57, 0x44, 0x9D, 0x59, 0x61, 0x66, 
			 0xD0, 0xC7, 0x9E, 0x04, 0x7C, 0xC7, 0x58, 0xF0 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   24,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x71, 0x52, 0xB4, 0xEB, 0x1D, 0xAA, 0x36, 0xFD, 
			 0x57, 0x14, 0x5F, 0x57, 0x04, 0x9F, 0x70, 0x74 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 224-bit keys
		[
		   28,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xA2, 0xF0, 0xA6, 0xB9, 0x17, 0x93, 0x2A, 0x3B, 
			 0xEF, 0x08, 0xE8, 0x7A, 0x58, 0xD6, 0xF8, 0x53 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   28,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xF0, 0xCA, 0xFC, 0x78, 0x8B, 0x4B, 0x4E, 0x53, 
			 0x8B, 0xC4, 0x32, 0x6A, 0xF5, 0xB9, 0x1B, 0x5F ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 256-bit keys 
		[
		   32,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xE0, 0x86, 0xAC, 0x45, 0x6B, 0x3C, 0xE5, 0x13, 
			 0xED, 0xF5, 0xDF, 0xDD, 0xD6, 0x3B, 0x71, 0x93 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   32,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x50, 0x01, 0xB9, 0xF5, 0x21, 0xC1, 0xC1, 0x29, 
			 0x00, 0xD5, 0xEC, 0x98, 0x2B, 0x9E, 0xE8, 0x21 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 288-bit keys 
		[
		   36,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xE8, 0xF4, 0xAF, 0x2B, 0x21, 0xA0, 0x87, 0x9B, 
			 0x41, 0x95, 0xB9, 0x71, 0x75, 0x79, 0x04, 0x7C ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   36,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xE6, 0xA6, 0xA5, 0xBC, 0x8B, 0x63, 0x6F, 0xE2, 
			 0xBD, 0xA7, 0xA7, 0x53, 0xAB, 0x40, 0x22, 0xE0 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 320-bit keys 
		[
		   40,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x17, 0x04, 0xD7, 0x2C, 0xC6, 0x85, 0x76, 0x02, 
			 0x4B, 0xCC, 0x39, 0x80, 0xD8, 0x22, 0xEA, 0xA4 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   40,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x7A, 0x41, 0xE6, 0x7D, 0x4F, 0xD8, 0x64, 0xF0, 
			 0x44, 0xA8, 0x3C, 0x73, 0x81, 0x7E, 0x53, 0xD8 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		]
/*
		// tweaked version ===> big indian

		// 128 bit keys
		[
		   16,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xB8, 0x35, 0xBD, 0xC3, 0x34, 0x82, 0x9D, 0x83,
			 0x71, 0xBF, 0xA3, 0x71, 0xE4, 0xB3, 0xC4, 0xFD ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   16,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xE6, 0x14, 0x1E, 0xAF, 0xEB, 0xE0, 0x59, 0x3C,
			 0x48, 0xE1, 0xCD, 0xF2, 0x1B, 0xBA, 0xA1, 0x89 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 160-bit keys 
		[
		   20,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x97, 0x59, 0x79, 0x4B, 0x5C, 0xA0, 0x70, 0x73,
			 0x24, 0xEF, 0xB3, 0x58, 0x67, 0xCA, 0xD4, 0xB3 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   20,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xB8, 0x0D, 0xFB, 0x9B, 0xE4, 0xA1, 0x58, 0x87,
			 0xB3, 0x76, 0xD5, 0x02, 0x18, 0x95, 0xC1, 0x2E ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 192-bit keys 
		[
		   24,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x7D, 0x62, 0x3B, 0x52, 0xC7, 0x4C, 0x64, 0xD8,
			 0xEB, 0xC7, 0x2D, 0x57, 0x97, 0x85, 0x43, 0x8F ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   24,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xB1, 0x0A, 0x59, 0xDD, 0x5D, 0x5D, 0x8D, 0x67,
			 0xEC, 0xEE, 0x4A, 0xC4, 0xBE, 0x4F, 0xA8, 0x4F ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 224-bit keys 
		[
		   28,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x68, 0x9E, 0x05, 0x94, 0x6A, 0x94, 0x43, 0x8F,
			 0xE7, 0x8E, 0x37, 0x3D, 0x24, 0x97, 0x92, 0xF5 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   28,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xDD, 0xB7, 0xB0, 0xB4, 0xE9, 0xB4, 0x9B, 0x9C,
			 0x38, 0x20, 0x25, 0x0B, 0x47, 0xC2, 0x1F, 0x89 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 256-bit keys 
		[
		   32,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x96, 0x00, 0xF0, 0x76, 0x91, 0x69, 0x29, 0x87,
			 0xF5, 0xE5, 0x97, 0xDB, 0xDB, 0xAF, 0x1B, 0x0A ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   32,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x69, 0x9C, 0xAF, 0xDD, 0x94, 0xC7, 0xBC, 0x60,
			 0x44, 0xFE, 0x02, 0x05, 0x8A, 0x6E, 0xEF, 0xBD ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		],

		// 288-bit keys 
		[
		   36,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x0F, 0xC7, 0xA2, 0xC0, 0x11, 0x17, 0xAC, 0x43,
			 0x52, 0x5E, 0xDF, 0x6C, 0xF3, 0x96, 0x33, 0x6C ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00 ]
		], [
		   36,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xAD, 0x08, 0x4F, 0xED, 0x55, 0xA6, 0x94, 0x3E,
			 0x7E, 0x5E, 0xED, 0x05, 0xA1, 0x9D, 0x41, 0xB4 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x01 ]
		],

		// 320-bit keys 
		[
		   40,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0xFE, 0xE2, 0x0E, 0x2A, 0x9D, 0xC5, 0x83, 0xBA,
			 0xA3, 0xA6, 0xD6, 0xA6, 0xF2, 0xE8, 0x06, 0xA5 ],
		   [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
		], [
		   40,
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
		   [ 0x86, 0x3D, 0xCC, 0x4A, 0x60, 0x34, 0x9C, 0x28,
			 0xA7, 0xDA, 0xA4, 0x3B, 0x0A, 0xD7, 0xFD, 0xC7 ],
		   [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
		]
*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		// key_length, pt, expected, key
		var vector = testVectors[i];
		
		var keylen = vector[0];
		var pt = Buffer.from(vector[1]);
		var expected = Buffer.from(vector[2]);
		var key = Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.anubis('anubis-'+(keylen * 8));
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});	

QUnit.module('Aria');
QUnit.test("Vector Test", function(assert) {
	// keybits, key, pt, expected
	var testVectors = [
		[
			128,
			[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
			[0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb],
			[0xc6, 0xec, 0xd0, 0x8e, 0x22, 0xc3, 0x0a, 0xbd, 0xb2, 0x15, 0xcf, 0x74, 0xe2, 0x07, 0x5e, 0x6e]
		],
		[
			128,
			"000102030405060708090a0b0c0d0e0f",
			"00112233445566778899aabbccddeeff",
			"d718fbd6ab644c739da95f3be6451778"
		],
		[
			192,
			"000102030405060708090a0b0c0d0e0f1011121314151617",
			"00112233445566778899aabbccddeeff",
			"26449c1805dbe7aa25a468ce263a9e79"
		],
		[
			256,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"00112233445566778899aabbccddeeff",
			"f92bd7c79fb72e2f2b8f80c1972d24fc"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.aria('aria');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}

});

QUnit.module('Blowfish');
QUnit.test("Vector Test", function(assert) {
/*
https://www.schneier.com/code/vectors.txt

Test vectors by Eric Young.  These tests all assume Blowfish with 16 rounds.

All data is shown as a hex string with 012345 loading as
data[0]=0x01;
data[1]=0x23;
data[2]=0x45;
ecb test data (taken from the DES validation tests)

key bytes               clear bytes             cipher bytes
0000000000000000        0000000000000000        4EF997456198DD78
FFFFFFFFFFFFFFFF        FFFFFFFFFFFFFFFF        51866FD5B85ECB8A
3000000000000000        1000000000000001        7D856F9A613063F2
1111111111111111        1111111111111111        2466DD878B963C9D
0123456789ABCDEF        1111111111111111        61F9C3802281B096
1111111111111111        0123456789ABCDEF        7D0CC630AFDA1EC7
0000000000000000        0000000000000000        4EF997456198DD78
FEDCBA9876543210        0123456789ABCDEF        0ACEAB0FC6A0A28D
7CA110454A1A6E57        01A1D6D039776742        59C68245EB05282B
0131D9619DC1376E        5CD54CA83DEF57DA        B1B8CC0B250F09A0
07A1133E4A0B2686        0248D43806F67172        1730E5778BEA1DA4
3849674C2602319E        51454B582DDF440A        A25E7856CF2651EB
04B915BA43FEB5B6        42FD443059577FA2        353882B109CE8F1A
0113B970FD34F2CE        059B5E0851CF143A        48F4D0884C379918
0170F175468FB5E6        0756D8E0774761D2        432193B78951FC98
43297FAD38E373FE        762514B829BF486A        13F04154D69D1AE5
07A7137045DA2A16        3BDD119049372802        2EEDDA93FFD39C79
04689104C2FD3B2F        26955F6835AF609A        D887E0393C2DA6E3
37D06BB516CB7546        164D5E404F275232        5F99D04F5B163969
1F08260D1AC2465E        6B056E18759F5CCA        4A057A3B24D3977B
584023641ABA6176        004BD6EF09176062        452031C1E4FADA8E
025816164629B007        480D39006EE762F2        7555AE39F59B87BD
49793EBC79B3258F        437540C8698F3CFA        53C55F9CB49FC019
4FB05E1515AB73A7        072D43A077075292        7A8E7BFA937E89A3
49E95D6D4CA229BF        02FE55778117F12A        CF9C5D7A4986ADB5
018310DC409B26D6        1D9D5C5018F728C2        D1ABB290658BC778
1C587F1C13924FEF        305532286D6F295A        55CB3774D13EF201
0101010101010101        0123456789ABCDEF        FA34EC4847B268B2
1F1F1F1F0E0E0E0E        0123456789ABCDEF        A790795108EA3CAE
E0FEE0FEF1FEF1FE        0123456789ABCDEF        C39E072D9FAC631D
0000000000000000        FFFFFFFFFFFFFFFF        014933E0CDAFF6E4
FFFFFFFFFFFFFFFF        0000000000000000        F21E9A77B71C49BC
0123456789ABCDEF        0000000000000000        245946885754369A
FEDCBA9876543210        FFFFFFFFFFFFFFFF        6B5C5A9C5D9E0A5A
set_key test data
data[8]= FEDCBA9876543210
c=F9AD597C49DB005E k[ 1]=F0
c=E91D21C1D961A6D6 k[ 2]=F0E1
c=E9C2B70A1BC65CF3 k[ 3]=F0E1D2
c=BE1E639408640F05 k[ 4]=F0E1D2C3
c=B39E44481BDB1E6E k[ 5]=F0E1D2C3B4
c=9457AA83B1928C0D k[ 6]=F0E1D2C3B4A5
c=8BB77032F960629D k[ 7]=F0E1D2C3B4A596
c=E87A244E2CC85E82 k[ 8]=F0E1D2C3B4A59687
c=15750E7A4F4EC577 k[ 9]=F0E1D2C3B4A5968778
c=122BA70B3AB64AE0 k[10]=F0E1D2C3B4A596877869
c=3A833C9AFFC537F6 k[11]=F0E1D2C3B4A5968778695A
c=9409DA87A90F6BF2 k[12]=F0E1D2C3B4A5968778695A4B
c=884F80625060B8B4 k[13]=F0E1D2C3B4A5968778695A4B3C
c=1F85031C19E11968 k[14]=F0E1D2C3B4A5968778695A4B3C2D
c=79D9373A714CA34F k[15]=F0E1D2C3B4A5968778695A4B3C2D1E
c=93142887EE3BE15C k[16]=F0E1D2C3B4A5968778695A4B3C2D1E0F
c=03429E838CE2D14B k[17]=F0E1D2C3B4A5968778695A4B3C2D1E0F00
c=A4299E27469FF67B k[18]=F0E1D2C3B4A5968778695A4B3C2D1E0F0011
c=AFD5AED1C1BC96A8 k[19]=F0E1D2C3B4A5968778695A4B3C2D1E0F001122
c=10851C0E3858DA9F k[20]=F0E1D2C3B4A5968778695A4B3C2D1E0F00112233
c=E6F51ED79B9DB21F k[21]=F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344
c=64A6E14AFD36B46F k[22]=F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455
c=80C7D7D45A5479AD k[23]=F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566
c=05044B62FA52D080 k[24]=F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677

chaining mode test data
key[16]   = 0123456789ABCDEFF0E1D2C3B4A59687
iv[8]     = FEDCBA9876543210
data[29]  = "7654321 Now is the time for " (includes trailing '\0')
data[29]  = 37363534333231204E6F77206973207468652074696D6520666F722000
cbc cipher text
cipher[32]= 6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC
cfb64 cipher text cipher[29]= 
E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3 
ofb64 cipher text cipher[29]= 
E73214A2822139CA62B343CC5B65587310DD908D0C241B2263C2CF80DA

*/

	// key, pt, expectd
	var testVectors = [
		["0000000000000000", "0000000000000000", "4EF997456198DD78"],
		["FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"],
		["3000000000000000", "1000000000000001", "7D856F9A613063F2"],
		["1111111111111111", "1111111111111111", "2466DD878B963C9D"],
		["0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"],
		["1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7"],
		["0000000000000000", "0000000000000000", "4EF997456198DD78"],
		["FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"],
		["7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"],
		["0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"],
		["07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4"],
		["3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB"],
		["04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A"],
		["0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918"],
		["0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98"],
		["43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5"],
		["07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79"],
		["04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3"],
		["37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969"],
		["1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B"],
		["584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E"],
		["025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD"],
		["49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019"],
		["4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3"],
		["49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5"],
		["018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778"],
		["1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201"],
		["0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2"],
		["1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE"],
		["E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D"],
		["0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4"],
		["FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC"],
		["0123456789ABCDEF", "0000000000000000", "245946885754369A"],
		["FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A"]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[0], 'hex');
		var pt = Buffer.from(vector[1], 'hex');
		var expected = Buffer.from(vector[2], 'hex');

		var cipher = new jCastle.algorithm.blowfish('blowfish');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Camellia');
QUnit.test("Vector Test", function(assert) {
	// keybits, key, pt, expected
	var testVectors = [
		[
			128,
			[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
			[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
			[0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43]
		],
		[
			128,
			[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x6C, 0x22, 0x7F, 0x74, 0x93, 0x19, 0xA3, 0xAA, 0x7D, 0xA2, 0x35, 0xA9, 0xBB, 0xA0, 0x5A, 0x2C]
		],
		[
			128,
			[0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48],
			[0x78, 0x35, 0x78, 0x66, 0xFD, 0x8B, 0x2C, 0xAE, 0xD4, 0xD1, 0xBB, 0xA3, 0xCF, 0xD5, 0x34, 0x0A],
			[0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.camellia('camellia');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}

});


// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/cast-128/Cast-128-128-64.verified.test-vectors
QUnit.module('Cast-128/Cast5');
QUnit.test("Vector Test", function(assert) {
	// keybits, key, pt, expected
	var testVectors = [
		[
			128,
			"01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A",
			"01 23 45 67 89 AB CD EF",
			"23 8B 4F E5 84 7E 44 B2"
		],
		// https://tools.ietf.org/html/rfc2144
		[
			80,
			//"01 23 45 67 12 34 56 78 23 45 00 00 00 00 00 00",
			"01 23 45 67 12 34 56 78 23 45",
			"01 23 45 67 89 AB CD EF",
			"EB 6A 71 1A 2C 02 27 1B"
		],
		[
			40,
			//"01 23 45 67 12 00 00 00 00 00 00 00 00 00 00 00",
			"01 23 45 67 12",
			"01 23 45 67 89 AB CD EF",
			"7A C8 16 D1 6E 9B 30 2E"
		],
		[
			128,
			"000102030405060708090A0B0C0D0E0F",
			"E44B90E3664F87A3",
			"0011223344556677"
		],
		[
			128,
			"2BD6459F82C5B300952C49104881FF48",
			"6347735B3C61B2F6",
			"EA024714AD5C4D84"
		],
		[
			128,
			"00000000000000000000000000000000",
			"A000428294710644",
			"0000000000000000"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');

		var cipher = new jCastle.algorithm.cast('cast-128');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}

});


// https://tools.ietf.org/html/rfc2612
QUnit.module('Cast-256/Cast6');
QUnit.test("Vector Test", function(assert) {
	// keybits, key, pt, expected
	var testVectors = [
		[
			128,
			"2342bb9efa38542c0af75647f29f615d",
			"00000000000000000000000000000000",
			"c842a08972b43d20836c91d1b7530f6b"
		],
		[
			192,
			"2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
			"00000000000000000000000000000000",
			"1b386c0210dcadcbdd0e41aa08a7a7e8"
		],
		[
			256,
			"2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
			"00000000000000000000000000000000",
			"4f6a2038286897b9c9870136553317fa"
		]

	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');

		var cipher = new jCastle.algorithm.cast('cast-256');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}

});

QUnit.module('Chacha20');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		{
		  key:      '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
		  nonce:    '00:00:00:09:00:00:00:4a:00:00:00:00',
		  counter:  1,
		  expected: '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4'+
					'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e'+
					'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2'+
					'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'
		},
		{
		  key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
					'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
		  nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
		  counter:  1,
		  expected: '9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d'+
					'cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed'+
					'29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5'+
					'31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f'
		},
		{
		  key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
					'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
		  nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
		  counter:  1,
		  expected: '3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd'+
					'83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a'+
					'8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd'+
					'4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0'
		},
		{
		  key:      '00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
					'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
		  nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
		  counter:  2,
		  expected: '72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32'+
					'8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca'+
					'13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09'+
					'24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96'
		},
		{
		  key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
					'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
		  nonce:    '00 00 00 00 00 00 00 00 00 00 00 02',
		  counter:  0,
		  expected: 'c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd'+
					'1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7'+
					'8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7'+
					'5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d'
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.alloc(expected.length);
		var nonce = Buffer.from(vector.nonce.replace(/[ \:]/g, ''), 'hex');
		var counter = vector.counter || 0;
		

		var cipher = new jCastle.algorithm.chacha20('chacha20', {counter: counter});

		cipher.setNonce(nonce);
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		// chacha20 is a stream cipher.
		cipher.setNonce(nonce);
		cipher.setCounter(counter);
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});


QUnit.module('Clefia');
QUnit.test("Clefia Vector Test", function(assert) {
	var testVectors = [
		[
			128,
			[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
			[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
			[0xde, 0x2b, 0xf2, 0xfd, 0x9b, 0x74, 0xaa, 0xcd, 0xf1, 0x29, 0x85, 0x55, 0x45, 0x94, 0x94, 0xfd]
		],
		[
			192,
			[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
			 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80],
			[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
			[0xe2, 0x48, 0x2f, 0x64, 0x9f, 0x02, 0x8d, 0xc4, 0x80, 0xdd, 0xa1, 0x84, 0xfd, 0xe1, 0x81, 0xad]
		],
		[
			256,
			[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
			 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00],
			[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
			[0xa1, 0x39, 0x78, 0x14, 0x28, 0x9d, 0xe8, 0x0c, 0x10, 0xda, 0x46, 0xd1, 0xfa, 0x48, 0xb3, 0x8a]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.clefia('clefia');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('DES');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [ // key, pt, ct
		[
			[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
			[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00]
		],
		[
			[0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08],
			[0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08],
			[0x10, 0x77, 0x2D, 0x40, 0xFA, 0xD2, 0x42, 0x57]
		],
		[
			[0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C],
			[0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C],
			[0x52, 0x1B, 0x7F, 0xB3, 0xB4, 0x1B, 0xB7, 0x91]
		],
		[
			[0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00],
			[0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84],
			[0x12, 0x6E, 0xFE, 0x8E, 0xD3, 0x12, 0x19, 0x0A]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[0]);
		var pt = Buffer.from(vector[1]);
		var expected = Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.des('des');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");
		
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('TripleDES/DES-EDE3');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x95, 0xA8, 0xD7, 0x28, 0x13, 0xDA, 0xA9, 0x4D]
		],
		[
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7]
		],
		[
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x54, 0x95, 0xC6, 0xAB, 0xF1, 0xE5, 0xDF, 0x51]
		],
		[
			[0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A,
			 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A],
			[0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A, 0x8A],
			[0x30, 0x10, 0x85, 0xE3, 0xFD, 0xE7, 0x24, 0xE1]
		],
		[
			[0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
			 0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00],
			[0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84],
			[0xC6, 0x16, 0xAC, 0xE8, 0x43, 0x95, 0x82, 0x47]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[0]);
		var pt = Buffer.from(vector[1]);
		var expected = Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.des('3des');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");
		
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}


});

QUnit.module('GOST28147');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [ // key, pt, ct
// this vector does not work. maybe different sbox is used.
//		[
//			"00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000",
//			"00000000 00000000",
//			"0eca1a54 4d33070b"
//		],
		[
			"546d203368656c326973652073736e62206167796967747473656865202c3d73",
			"0000000000000000",
			"1b0bbc32cebcab42"
		],
		[
			"75 71 31 34 B6 0F EC 45 A6 07 BB 83 AA 37 46 AF 4F F9 9D A6 D1 B5 3B 5B 1B 40 2A 1B AA 03 0D 1B",
			"11 22 33 44 55 66 77 88",
			"03 25 1E 14 F9 D2 8A CB"
		],
		[
			[0x75, 0x71, 0x31, 0x34, 0xB6, 0x0F, 0xEC, 0x45, 
			 0xA6, 0x07, 0xBB, 0x83, 0xAA, 0x37, 0x46, 0xAF,
			 0x4F, 0xF9, 0x9D, 0xA6, 0xD1, 0xB5, 0x3B, 0x5B,
			 0x1B, 0x40, 0x2A, 0x1B, 0xAA, 0x03, 0x0D, 0x1B],
			[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
			[0x03, 0x25, 0x1E, 0x14, 0xF9, 0xD2, 0x8A, 0xCB]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.gost('gost');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");
		
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});


QUnit.module('KISA Hight');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00],
			[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
			[0x23, 0xce, 0x9f, 0x72, 0xe5, 0x43, 0xe6, 0xd8]
		],
		[
			[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
			[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
			[0x7a, 0x6f, 0xb2, 0xa2, 0x8d, 0x23, 0xf4, 0x66]
		],
		[
			[0x28, 0xdb, 0xc3, 0xbc, 0x49, 0xff, 0xd8, 0x7d, 0xcf, 0xa5, 0x09, 0xb1, 0x1d, 0x42, 0x2b, 0xe7],
			[0xb4, 0x1e, 0x6b, 0xe2, 0xeb, 0xa8, 0x4a, 0x14],
			[0xcc, 0x04, 0x7a, 0x75, 0x20, 0x9c, 0x1f, 0xc6]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.hight('hight');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});


QUnit.module('Idea');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
			[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
			[0xF5, 0x26, 0xAB, 0x9A, 0x62, 0xC0, 0xD2, 0x58]
		],
		[
			[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0xB1, 0xF5, 0xF7, 0xF8, 0x79, 0x01, 0x37, 0x0F]
		],
		[
			[0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48],
			[0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84],
			[0xC8, 0xFB, 0x51, 0xD3, 0x51, 0x66, 0x27, 0xA8]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.idea('idea');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Lea');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			128,
			"0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0",
			"10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
			"9f c8 4e 35 28 c6 c6 18 55 32 c7 a7 04 64 8b fd"
		],
		[
			192,
			"0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0 f0 e1 d2 c3 b4 a5 96 87",
			"20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f",
			"6f b9 5e 32 5a ad 1b 87 8c dc f5 35 76 74 c6 f2"
		],
		[
			256,
			"0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0 f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b 3c 2d 1e 0f",
			"30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f",
			"d6 51 af f6 47 b1 89 c1 3a 89 00 ca 27 f9 e1 97"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.lea('lea');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('RC2');
QUnit.test("Vector Test", function(assert) {
/*
https://tools.ietf.org/html/rfc2268

5. Test vectors

   Test vectors for encryption with RC2 are provided below.
   All quantities are given in hexadecimal notation.

   Key length (bytes) = 8
   Effective key length (bits) = 63
   Key = 00000000 00000000
   Plaintext = 00000000 00000000
   Ciphertext = ebb773f9 93278eff

   Key length (bytes) = 8
   Effective key length (bits) = 64
   Key = ffffffff ffffffff
   Plaintext = ffffffff ffffffff
   Ciphertext = 278b27e4 2e2f0d49

   Key length (bytes) = 8
   Effective key length (bits) = 64
   Key = 30000000 00000000
   Plaintext = 10000000 00000001
   Ciphertext = 30649edf 9be7d2c2

   Key length (bytes) = 1
   Effective key length (bits) = 64
   Key = 88
   Plaintext = 00000000 00000000
   Ciphertext = 61a8a244 adacccf0

   Key length (bytes) = 7
   Effective key length (bits) = 64
   Key = 88bca90e 90875a
   Plaintext = 00000000 00000000
   Ciphertext = 6ccf4308 974c267f

   Key length (bytes) = 16
   Effective key length (bits) = 64
   Key = 88bca90e 90875a7f 0f79c384 627bafb2
   Plaintext = 00000000 00000000
   Ciphertext = 1a807d27 2bbe5db1

   Key length (bytes) = 16
   Effective key length (bits) = 128
   Key = 88bca90e 90875a7f 0f79c384 627bafb2
   Plaintext = 00000000 00000000
   Ciphertext = 2269552a b0f85ca6

   Key length (bytes) = 33
   Effective key length (bits) = 129
   Key = 88bca90e 90875a7f 0f79c384 627bafb2 16f80a6f 85920584
         c42fceb0 be255daf 1e
   Plaintext = 00000000 00000000
   Ciphertext = 5b78d3a4 3dfff1f1
*/
	var testVectors = [
		{
			key_length: 8,
			effective_key_length: 63,
			key: '00000000 00000000',
			plaintext: '00000000 00000000',
			ciphertext: 'ebb773f9 93278eff'
		},
		{
			key_length: 8,
			effective_key_length: 64,
			key: 'ffffffff ffffffff',
			plaintext: 'ffffffff ffffffff',
			ciphertext: '278b27e4 2e2f0d49'
		},
		{
			key_length: 8,
			effective_key_length: 64,
			key: '30000000 00000000',
			plaintext: '10000000 00000001',
			ciphertext: '30649edf 9be7d2c2'
		},
		{
			key_length: 1,
			effective_key_length: 64,
			key: '88',
			plaintext: '00000000 00000000',
			ciphertext: '61a8a244 adacccf0'
		},
		{
			key_length: 7,
			effective_key_length: 64,
			key: '88bca90e 90875a',
			plaintext: '00000000 00000000',
			ciphertext: '6ccf4308 974c267f'
		},
		{
			key_length: 16,
			effective_key_length: 64,
			key: '88bca90e 90875a7f 0f79c384 627bafb2',
			plaintext: '00000000 00000000',
			ciphertext: '1a807d27 2bbe5db1'
		},
		{
			key_length: 16,
			effective_key_length: 128,
			key: '88bca90e 90875a7f 0f79c384 627bafb2',
			plaintext: '00000000 00000000',
			ciphertext: '2269552a b0f85ca6'
		},
		{
			key_length: 33,
			effective_key_length: 129,
			key: '88bca90e 90875a7f 0f79c384 627bafb2 16f80a6f 85920584'+
				'c42fceb0 be255daf 1e',
			plaintext: '00000000 00000000',
			ciphertext: '5b78d3a4 3dfff1f1'
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector.plaintext.replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector.ciphertext.replace(/[ \:]/g, ''), 'hex');

		var cipher = new jCastle.algorithm.rc2('rc2', {
			effectiveKeyBits: vector.effective_key_length
		});

		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('RC4');
QUnit.test("Vector Test", function(assert) {
	// rfc 6229
	var testVectors = [
		[
			"0102030405", // 40bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"b2 39 63 05  f0 3d c0 27   cc c3 52 4a  0a 11 18 a8",
		],
		[
			"01020304050607", // 56bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"29 3f 02 d4  7f 37 c9 b6   33 f2 af 52  85 fe b4 6b"
		],
		[
			"0102030405060708", // 64bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"97 ab 8a 1b  f0 af b9 61   32 f2 f6 72  58 da 15 a8"
		],
		[
			"0102030405060708090a", // 80bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"ed e3 b0 46  43 e5 86 cc   90 7d c2 18  51 70 99 02"
		],
		[
			"0102030405060708090a0b0c0d0e0f10", // 128bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"9a c7 cc 9a  60 9d 1e f7   b2 93 28 99  cd e4 1b 97"
		],
        [
			"0102030405060708090a0b0c0d0e0f101112131415161718", // 192bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"05 95 e5 7f  e5 f0 bb 3c   70 6e da c8  a4 b2 db 11"
		],
		[
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", // 256bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"ea a6 bd 25  88 0b f9 3d   3f 5d 1e 4c  a2 61 1d 91"
		],
        [
			"833222772a", // 40bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"80 ad 97 bd  c9 73 df 8a   2e 87 9e 92  a4 97 ef da",
		],
		[
			"1910833222772a", // 56bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"bc 92 22 db  d3 27 4d 8f   c6 6d 14 cc  bd a6 69 0b"
		],
		[
			"641910833222772a", // 64bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"bb f6 09 de  94 13 17 2d   07 66 0c b6  80 71 69 26"
		],
		[
			"8b37641910833222772a", // 80bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"ab 65 c2 6e  dd b2 87 60   0d b2 fd a1  0d 1e 60 5c"
		],
		[
			"ebb46227c6cc8b37641910833222772a", // 128bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"72 0c 94 b6  3e df 44 e1   31 d9 50 ca  21 1a 5a 30"
		],
        [
			"c109163908ebe51debb46227c6cc8b37641910833222772a", // 192bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"54 b6 4e 6b  5a 20 b5 e2   ec 84 59 3d  c7 98 9d a7"
		],
		[
			"1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a", // 256bits
			"00 00 00 00  00 00 00 00   00 00 00 00  00 00 00 00",
			"dd 5b cb 00  18 e9 22 d4   94 75 9d 7c  39 5d 02 d3"
		],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');

		var cipher = new jCastle.algorithm.rc4('rc4');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		// it's a stream cipher!
		var cipher = new jCastle.algorithm.rc4('rc4');
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);


		assert.ok(dt.equals(pt), "Decryption passed!");
	}

	// streaming test
	// https://tools.ietf.org/html/rfc6229
	var key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
	var pt =  "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"

	var testVectors = [
		{
			pos: 0, 
			expected: "ea a6 bd 25  88 0b f9 3d   3f 5d 1e 4c  a2 61 1d 91"
		}, {
			pos: 16,
			expected: "cf a4 5c 9f  7e 71 4b 54   bd fa 80 02  7c b1 43 80"
		}, {
			pos: 240,
			expected: "11 4a e3 44  de d7 1b 35   f2 e6 0f eb  ad 72 7f d8"
		}, {
			pos: 256,
			expected: "02 e1 e7 05  6b 0f 62 39   00 49 64 22  94 3e 97 b6"
		}, {
			pos: 496,
			expected: "91 cb 93 c7  87 96 4e 10   d9 52 7d 99  9c 6f 93 6b"
		}, {
			pos: 512,
			expected: "49 b1 8b 42  f8 e8 36 7c   be b5 ef 10  4b a1 c7 cd"
		}, {
			pos: 752,
			expected: "87 08 4b 3b  a7 00 ba de   95 56 10 67  27 45 b3 74"
		}, {
			pos: 768,
			expected: "e7 a7 b9 e9  ec 54 0d 5f   f4 3b db 12  79 2d 1b 35"
		}, {
			pos: 1008,
			expected: "c7 99 b5 96  73 8f 6b 01   8c 76 c7 4b  17 59 bd 90"
		}, {
			pos: 1024,
			expected: "7f ec 5b fd  9f 9b 89 ce   65 48 30 90  92 d7 e9 58"
		}, {
			pos: 1520,
			expected: "40 f2 50 b2  6d 1f 09 6a   4a fd 4c 34  0a 58 88 15"
		}, {
			pos: 1536,
			expected: "3e 34 13 5c  79 db 01 02   00 76 76 51  cf 26 30 73"
		}, {
			pos: 2032,
			expected: "f6 56 ab cc  f8 8d d8 27   02 7b 2c e9  17 d4 64 ec"
		}, {
			pos: 2048,
			expected: "18 b6 25 03  bf bc 07 7f   ba bb 98 f2  0d 98 ab 34"
		}, {
			pos: 3056,
			expected: "8a ed 95 ee  5b 0d cb fb   ef 4e b2 1d  3a 3f 52 f9"
		}, {
			pos: 3072,
			expected: "62 5a 1a b0  0e e3 9a 53   27 34 6b dd  b0 1a 9c 18"
		}, {
			pos: 4080,
			expected: "a1 3a 7c 79  c7 e1 19 b5   ab 02 96 ab  28 c3 00 b9"
		}, {
			pos: 4096,
			expected: "f3 e4 c0 a2  e0 2d 1d 01   f7 f0 a7 46  18 af 2b 48"
		}
	];

	key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
	pt = Buffer.from(pt.replace(/[ \:]/g, ''), 'hex');
	var current_pos = 0;
	var vector_pos = 0;
	var finish = false;

	var cipher = new jCastle.algorithm.rc4('rc4');
	cipher.keySchedule(key, true);

	var vector = testVectors[vector_pos];

	var pos = vector.pos;
	var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');

	while (!finish) {
		var ct = cipher.encryptBlock(pt);

		if (current_pos == pos) {
			assert.ok(ct.equals(expected) , "Encryption passed!");

			vector_pos++;

			if (vector_pos == testVectors.length) {
				finish = true;
			} else {
				var vector = testVectors[vector_pos];

				var pos = vector.pos;
				var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');
			}
		}

		current_pos += 16;
	}

});

QUnit.module('RC5');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0x91, 0x5f, 0x46, 0x19, 0xbe, 0x41, 0xb2, 0x51,
			 0x63, 0x55, 0xa5, 0x01, 0x10, 0xa9, 0xce, 0x91],
			[0x21, 0xa5, 0xdb, 0xee, 0x15, 0x4b, 0x8f, 0x6d],
			[0xf7, 0xc0, 0x13, 0xac, 0x5b, 0x2b, 0x89, 0x52]
		], [
			[0x78, 0x33, 0x48, 0xe7, 0x5a, 0xeb, 0x0f, 0x2f,
			 0xd7, 0xb1, 0x69, 0xbb, 0x8d, 0xc1, 0x67, 0x87],
			[0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52],
			[0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92]
		], [
			[0xDC, 0x49, 0xdb, 0x13, 0x75, 0xa5, 0x58, 0x4f,
			 0x64, 0x85, 0xb4, 0x13, 0xb5, 0xf1, 0x2b, 0xaf],
			[0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92],
			[0x65, 0xc1, 0x78, 0xb2, 0x84, 0xd1, 0x97, 0xcc]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[0]);
		var pt = Buffer.from(vector[1]);
		var expected = Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.rc5('rc5');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('RC6');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78, 0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48, 0xa4, 0x1e]
		], [
			[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78],
			[0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1],
			[0x52, 0x4e, 0x19, 0x2f, 0x47, 0x15, 0xc6, 0x23, 0x1f, 0x51, 0xf6, 0x36, 0x7e, 0xa4, 0x3f, 0x18]
		], [
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"6c d6 1b cb 19 0b 30 38 4e 8a 3f 16 86 90 ae 82"
		], [
			"01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0",
			"02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
			"68 83 29 d0 19 e5 05 04 1e 52 e9 2a f9 52 91 d4"
		], [
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"8f 5f bd 05 10 d1 5f a8 93 fa 3f da 6e 85 7e c2"
		], [
			"01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe",
			"02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
			"c8 24 18 16 f0 d7 e4 89 20 ad 16 a1 67 4e 5d 48"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.rc6('rc6');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Rijndael');
QUnit.test("Vector Test", function(assert) {
/*
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-128-128.unverified.test-vectors 
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-192-128.unverified.test-vectors 
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-128.unverified.test-vectors 
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-192.unverified.test-vectors 
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-256.unverified.test-vectors 
*/
	var testVectors = [
		[
			128,
			"000102030405060708090A0B0C0D0E0F",
			"762A5AB50929189CEFDB99434790AAD8",
			"00112233445566778899AABBCCDDEEFF"
		], [
			128,
			"2BD6459F82C5B300952C49104881FF48",
			"E99388EED41AD8058D6162B0CF4667E6",
			"EA024714AD5C4D84EA024714AD5C4D84"
		], [
			192,
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"3369EB82973635E9C2E96D687724C790",
			"00112233445566778899AABBCCDDEEFF"
		], [
			192,
			"2BD6459F82C5B300952C49104881FF482BD6459F82C5B300",
			"A4C5C1F3858A5A596189E928B4469EA2",
			"EA024714AD5C4D84EA024714AD5C4D84"
		], [
			256,
			"000102030405060708090A0B0C0D0E0F"+
			"101112131415161718191A1B1C1D1E1F",
			"EAB487E68EC92DB4AC288A24757B0262",
			"00112233445566778899AABBCCDDEEFF"
		], [
			256,
			"2BD6459F82C5B300952C49104881FF48"+
			"2BD6459F82C5B300952C49104881FF48",
			"DFC295E9D04A30DB25940E4FCC64516F",
			"EA024714AD5C4D84EA024714AD5C4D84"
		], [
			256,
			"000102030405060708090A0B0C0D0E0F"+
			"101112131415161718191A1B1C1D1E1F",
			"F0DF284C813516FD16C662A54EF2D1F8ED1D4D021BAA7FDA",
			"00112233445566778899AABBCCDDEEFF1021324354657687"
		], [
			256,
			"2BD6459F82C5B300952C49104881FF48"+
			"2BD6459F82C5B300952C49104881FF48",
			"3E394DA6539E820353ABDA8079B31C6134368CF1EA6EA121",
			"EA024714AD5C4D84EA024714AD5C4D84EA024714AD5C4D84"
		], [
			256,
			"000102030405060708090A0B0C0D0E0F"+
			"101112131415161718191A1B1C1D1E1F",
			"C2B1712FD46284E84721E66824123A39"+
			"3CE9301F44BA1BE8FF3408DB708FA45B",
			"00112233445566778899AABBCCDDEEFF"+
			"102132435465768798A9BACBDCEDFE0F"
		], [
			256,
			"2BD6459F82C5B300952C49104881FF48"+
			"2BD6459F82C5B300952C49104881FF48",
			"2ECAB2ACDCCEE8BA3858A3750A2BFA5C"+
			"D839397B445DBD9367052108F7D7548E",
			"EA024714AD5C4D84EA024714AD5C4D84"+
			"EA024714AD5C4D84EA024714AD5C4D84"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.rijndael('rijndael');

		//
		// when you use fast version of rijndael be careful!
		// fast version needs second parameter!
		// and it supports only 16 block size.
		//
		// for test we will use generalized version
		//
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Safer(safer-k64/safer-sk64/safer-sk128)');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			'safer-k64',
			[8, 7, 6, 5, 4, 3, 2, 1],
			[1, 2, 3, 4, 5, 6, 7, 8],
			[200, 242, 156, 221, 135, 120, 62, 217]
		], [
			'safer-sk64',
			[1, 2, 3, 4, 5, 6, 7, 8],
			[1, 2, 3, 4, 5, 6, 7, 8],
			[95, 206, 155, 162, 5, 132, 56, 199] // 6 rounds
			//[0x60, 0xd0, 0x4a, 0xd7, 0xc4, 0x9b, 0x8d, 0xed ] // 8 rounds
			, 6
		], [
			'safer-sk64',
			[1, 2, 3, 4, 5, 6, 7, 8],
			[1, 2, 3, 4, 5, 6, 7, 8],
			// [95, 206, 155, 162, 5, 132, 56, 199] // 6 rounds
			[0x60, 0xd0, 0x4a, 0xd7, 0xc4, 0x9b, 0x8d, 0xed ] // 8 rounds		
		], [
			'safer-sk128',
			[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0],
			[1, 2, 3, 4, 5, 6, 7, 8],
			[255, 120, 17, 228, 179, 167, 46, 113]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);
		var rounds = 0;
		if (typeof vector[4] != 'undefined') rounds = vector[4];

		var cipher = new jCastle.algorithm.safer(vector[0], {rounds: rounds});
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");
		
		cipher.keySchedule(key, false);

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('SaferPlus');
QUnit.test("Vector Test", function(assert) {

	var pt = Buffer.alloc(16);
	for (var i = 0; i < pt.length; i++) {
		pt[i] = i % 256;
	}

	var key = Buffer.alloc(32);
	for (var i = 0; i < key.length; i++) {
		key[i] = (i * 2 + 10) % 256;
	}

	var expected = Buffer.from("97fa76704bf6b578549f65c6f75b228b", 'hex');

	var cipher = new jCastle.algorithm.saferplus('saferplus');
	
	cipher.keySchedule(key, true);

	var ct = cipher.encryptBlock(pt);

	assert.ok(ct.equals(expected) , "Encryption passed!");

	cipher.keySchedule(key, false);
	
	var dt = cipher.decryptBlock(ct);

	assert.ok(dt.equals(pt), "Decryption passed!");

});

QUnit.module('Seed-128');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
			"5E BA C6 E0 05 4E 16 68 19 AF F1 CC 6D 34 6C DB"
		], [
			"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"C1 1F 22 F2 01 40 50 50 84 48 35 97 E4 37 0F 43"
		], [
			"47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85",
			"83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D ",
			"EE 54 D1 3E BC AE 70 6D 22 6B C3 14 2C D4 0D 4A"
		], [
			"28 DB C3 BC 49 FF D8 7D CF A5 09 B1 1D 42 2B E7",
			"B4 1E 6B E2 EB A8 4A 14 8E 2E ED 84 59 3C 5E C7",
			"9B 9B 7B FC D1 81 3C B9 5D 0B 36 18 F4 0F 51 22"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.seed('seed-128');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

/*
// OpenSSL's Seed does not support 256 key bits.
// if you want to test this code then use KISA's Seed.
QUnit.module('Seed-256');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"+
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
			"C6 09 21 4B E6 4E 38 CB EC 8E 8F 0A FE BA 74 DF"
		], [
			"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"+
			"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			"5F 72 82 2F 0B 1F 45 CF 4E 81 E4 D3 66 06 00 81"
		], [
			"47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85"+
			"A7 08 C1 28 17 E8 CB 45 41 A1 B7 15 ED A1 B2 A3",
			"83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D ",
			"C0 E2 21 52 BE FB 62 B2 FB 02 06 A4 37 1E EE D7"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.seed('seed-256');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});
*/

// https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Serpent-128-128.verified.test-vectors
// https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Serpent-192-128.verified.test-vectors
QUnit.module('Serpent');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			128,
			"000102030405060708090A0B0C0D0E0F",
			"33B3DC87EDDD9B0F6A1F407D14919365",
			"00112233445566778899AABBCCDDEEFF"
		], [
			128,
			"2BD6459F82C5B300952C49104881FF48",
			"BEB6C069393822D3BE73FF30525EC43E",
			"EA024714AD5C4D84EA024714AD5C4D84"
		], [
			192,
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"4528CACCB954D450655E8CFD71CBFAC7",
			"00112233445566778899AABBCCDDEEFF"
		], [
			192,
			"2BD6459F82C5B300952C49104881FF482BD6459F82C5B300",
			"E0208BE278E21420C4B1B9747788A954",
			"EA024714AD5C4D84EA024714AD5C4D84"
		], [
			256,
			"000102030405060708090A0B0C0D0E0F"+
			"101112131415161718191A1B1C1D1E1F",
			"3DA46FFA6F4D6F30CD258333E5A61369",
			"00112233445566778899AABBCCDDEEFF"
		], [
			256,
			"2BD6459F82C5B300952C49104881FF48"+
			"2BD6459F82C5B300952C49104881FF48",
			"677C8DFAA08071743FD2B415D1B28AF2",
			"EA024714AD5C4D84EA024714AD5C4D84"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var pt = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var expected = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);

		var cipher = new jCastle.algorithm.serpent('serpent');
		
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});


/*
http://git.distorted.org.uk/~mdw/catacomb/blobdiff/fe371977a223059f0b28e6edae1458d6c1c6f3a2..277e2a643e24c87de974a32ff9105433fdbde47c:/tests/skipjack

# --- The official Skipjack test vector ---
#
# It's a bit piss-poor that they only provide one test-vector here.

   00998877665544332211 33221100ddccbbaa 2587cae27a12d300;

# --- From KEA test vectors ---
#
# The Skipjack algorithm is used by the KEA to derive the final key.
# Unfortunately, the test vectors given in the Skipjack/KEA spec don't
# match my (or anyone else's!) implementation.  These are the values
# which seem to be generally agreed.

e7496e99e4628b7f9ffb 99ccfe2b90fd550b 60a73d387b517fca; 
e7496e99e4628b7f9ffb 60a73d387b517fca 24c90cb05d668b27;
e5caf4dcc70e55f1dd90 b71cb0d009af2765 64f4877ae68a8a62;
e5caf4dcc70e55f1dd90 64f4877ae68a8a62 fee778a838a601cd;

# --- These are the results expected from the KEA spec ---
#
# A `?' indicates that I don't know what that digit's meant to be.  I've
# derived the top 16 bits of the intermediate results from the spec.

# e7496e99e4628b7f9ffb 99ccfe2b90fd550b 2f30????????????;
# e7496e99e4628b7f9ffb 2f30???????????? 740839dee833add4;
# e5caf4dcc70e55f1dd90 b71cb0d009af2765 8e27????????????;
# e5caf4dcc70e55f1dd90 8e27???????????? 97fd1c6bd86bc439;

# --- Some more test vectors ---
#
# These are dreamed up by me.  The above tests don't actually exhaustively
# test the F-table.  There are 16 entries unaccounted for.  The keys and
# plaintexts were generated using fibrand with seed 0.

cde4bef260d7bcda1635 47d348b7551195e7 f17b3070144aebea;
7022907dd1dff7dac5c9 941d26d0c6eb14ad a055d02c5e0eae8d;
568f86edd1dc9268eeee 533285a6ed810c9b b4c22f4fb74c35dc;
689daaa9060d2d4b6003 062365b0a54364c7 08698d8786f80d16;
6c160f11896c4794846e cfa14a7130c9f137 d6db848b7cecdd39;
*/
QUnit.module('Skipjack');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			[0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
			[0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa],
			[0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00]
		],/*
got from here:
https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Skipjack-80-64.unverified.test-vectors
but vector test fails!
Seems it goes well with php mcrypt function.

more...
I've searched the code from https://github.com/cantora/avr-crypto-lib, and it has a different routine.

		[
			"00010203040506070809",
			"7D4787EE2C30C0D6",
			"0011223344556677"
		],
		[
			"2BD6459F82C5B300952C",
			"2CA29033DC205943",
			"EA024714AD5C4D84"
		] */
		[
			"e7496e99e4628b7f9ffb",
			"99ccfe2b90fd550b",
			"60a73d387b517fca"
		],
		[
			"cde4bef260d7bcda1635",
			"47d348b7551195e7",
			"f17b3070144aebea"
		],
		[
			"7022907dd1dff7dac5c9",
			"941d26d0c6eb14ad",
			"a055d02c5e0eae8d"
		],
		[
			"568f86edd1dc9268eeee",
			"533285a6ed810c9b",
			"b4c22f4fb74c35dc"
		],
		[
			"689daaa9060d2d4b6003",
			"062365b0a54364c7",
			"08698d8786f80d16"
		],
		[
			"6c160f11896c4794846e",
			"cfa14a7130c9f137",
			"d6db848b7cecdd39"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.skipjack('skipjack');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Threefish');
QUnit.test("Vector Test", function(assert) {
	// bits, key, tweak, pt, expected
	var testVectors = [
		[
			256,
			'0000000000000000000000000000000000000000000000000000000000000000',
			'00000000000000000000000000000000',
			'0000000000000000000000000000000000000000000000000000000000000000',
			'84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8'
		],
		[
			256,
			'101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
			'000102030405060708090a0b0c0d0e0f',
			'FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0',
			'e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df'
		],
		[
			512,
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000',
			'00000000000000000000000000000000',
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000',
			'b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b'+
			'7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe'
		],
		[
			512,
			'101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'+
			'303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
			'000102030405060708090a0b0c0d0e0f',
			'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0'+
			'dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0',
			'e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779'+
			'272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d'
		],
		[
			1024,
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000',
			'00000000000000000000000000000000',
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000'+
			'0000000000000000000000000000000000000000000000000000000000000000',
			'f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90d'+
			'f0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a2'+
			'0b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa'+
			'9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e'
		],
		[
			1024,
			'101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'+
			'303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'+
			'505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f'+
			'707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
			'000102030405060708090a0b0c0d0e0f',
			'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0'+
			'dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0'+
			'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0'+
			'9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180',
			'a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c'+
			'94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd'+
			'8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c8'+
			'3313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde'
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var keybits = vector[0];
		var key = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var tweak = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);
		var pt = typeof vector[3] == 'string' ? Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[3]);
		var expected = typeof vector[4] == 'string' ? Buffer.from(vector[4].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[4]);

		var cipher = new jCastle.algorithm.threefish('threefish-'+keybits, {tweak: tweak});
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, false);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

// https://www.schneier.com/code/ecb_ival.txt
QUnit.module('Twofish');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"9F589F5CF6122C32B6BFEC2F2AE8C35A"
		],
		[
			"9F589F5CF6122C32B6BFEC2F2AE8C35A",
			"D491DB16E7B1C39E86CB086B789F5419",
			"019F9809DE1711858FAAC3A3BA20FBC3"
		],
		[
			"BCA724A54533C6987E14AA827952F921",
			"6B459286F3FFD28D49F15B1581B08E42",
			"5D9D4EEFFA9151575524F115815A12E0"
		], [
			"0123456789ABCDEFFEDCBA98765432100011223344556677",
			"00000000000000000000000000000000",
			"CFD1D2E5A9BE9CDF501F13B892BD2248"
		], [
			"3AF6F7CE5BD35EF18BEC6FA787AB506BD1079B789F666649",
			"AE8109BFDA85C1F2C5038B34ED691BFF",
			"893FD67B98C550073571BD631263FC78"
		], [
			"AE8109BFDA85C1F2C5038B34ED691BFF3AF6F7CE5BD35EF1",
			"893FD67B98C550073571BD631263FC78",
			"16434FC9C8841A63D58700B5578E8F67"		
		], [
			"0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
			"00000000000000000000000000000000",
			"37527BE0052334B89F0CFCCAE87CFA20"
		], [
			"2E2158BC3E5FC714C1EEECA0EA696D48D2DED73E59319A8138E0331F0EA149EA",
			"248A7F3528B168ACFDD1386E3F51E30C",
			"431058F4DBC7F734DA4F02F04CC4F459"
		], [
			"248A7F3528B168ACFDD1386E3F51E30C2E2158BC3E5FC714C1EEECA0EA696D48",
			"431058F4DBC7F734DA4F02F04CC4F459",
			"37FE26FF1CF66175F5DDF4C33B97A205"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.twofish('twofish');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('VMPC');
QUnit.test("Vector Test", function(assert) {

	var key = Buffer.from('9661410AB797D8A9EB767C21172DF6C7', 'hex');
	var iv = Buffer.from('4B5C2F003E67F39557A8D26F3DA2B155', 'hex');
	var pt = Buffer.alloc(1024 * 1024);
	var engine = new jCastle.algorithm.vmpc('vmpc');

	engine.setInitialVector(iv);
	engine.keySchedule(key, true);

	var ct = engine.cryptBlock(pt);

	assert.ok(ct[0] == 0xA8, "byte test passed!");
	assert.ok(ct[1] == 0x24, "byte test passed!");
	assert.ok(ct[2] == 0x79, "byte test passed!");
	assert.ok(ct[3] == 0xF5, "byte test passed!");
	assert.ok(ct[252] == 0xB8, "byte test passed!");
	assert.ok(ct[253] == 0xFC, "byte test passed!");
	assert.ok(ct[254] == 0x66, "byte test passed!");
	assert.ok(ct[255] == 0xA4, "byte test passed!");
	assert.ok(ct[1020] == 0xE0, "byte test passed!");
	assert.ok(ct[1021] == 0x56, "byte test passed!");
	assert.ok(ct[1022] == 0x40, "byte test passed!");
	assert.ok(ct[1023] == 0xA5, "byte test passed!");
	assert.ok(ct[102396] == 0x81, "byte test passed!");
	assert.ok(ct[102397] == 0xCA, "byte test passed!");
	assert.ok(ct[102398] == 0x49, "byte test passed!");
	assert.ok(ct[102399] == 0x9A, "byte test passed!");


	var engine2 = new jCastle.algorithm.vmpc('vmpc-ksa3');
	engine2.setInitialVector(iv);
	engine2.keySchedule(key, true);
	var ct = engine2.cryptBlock(pt);

	assert.ok(ct[0] == 0xB6, "byte test passed!");
	assert.ok(ct[1] == 0xEB, "byte test passed!");
	assert.ok(ct[2] == 0xAE, "byte test passed!");
	assert.ok(ct[3] == 0xFE, "byte test passed!");
	assert.ok(ct[252] == 0x48, "byte test passed!");
	assert.ok(ct[253] == 0x17, "byte test passed!");
	assert.ok(ct[254] == 0x24, "byte test passed!");
	assert.ok(ct[255] == 0x73, "byte test passed!");
	assert.ok(ct[1020] == 0x1D, "byte test passed!");
	assert.ok(ct[1021] == 0xAE, "byte test passed!");
	assert.ok(ct[1022] == 0xC3, "byte test passed!");
	assert.ok(ct[1023] == 0x5A, "byte test passed!");
	assert.ok(ct[102396] == 0x1D, "byte test passed!");
	assert.ok(ct[102397] == 0xA7, "byte test passed!");
	assert.ok(ct[102398] == 0xE1, "byte test passed!");
	assert.ok(ct[102399] == 0xDC, "byte test passed!");

});

// http://tayloredge.com/reference/Mathematics/XTEA.pdf
QUnit.module('XTea');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"27F917B1 C1DA8993 60E2ACAA A6EB923D",
			"AF20A390 547571AA",
			"D26428AF 0A202283"
		], [
			"DEADBEEF DEADBEEF DEADBEEF DEADBEEF",
			"9647A918 9EC565D5",
			"DEADBEEF DEADBEEF",
		], [
			"1234ABC1 234ABC12 34ABC123 4ABC1234",
			"ABC1234A BC1234AB",
			"5C0754C1 F6F0BD9B",
		], [
			"ABC1234A BC1234AB C1234ABC 1234ABC1",
			"234ABC12 34ABC123",
			"CDFCC72C 24BC116B",
		], [
			"31415926 53589793 23846264 33832795",
			"02884197 16939937",
			"46E2007D 58BBC2EA"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = typeof vector[0] == 'string' ? Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[0]);
		var pt = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var expected = typeof vector[2] == 'string' ? Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[2]);

		var cipher = new jCastle.algorithm.xtea('xtea');
		cipher.keySchedule(key, true);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		cipher.keySchedule(key, true);
		
		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

QUnit.module('Rabbit');
QUnit.test("Vector Test", function(assert) {

	var plaintext = Buffer.alloc(512).fill(0x00);

	var testVectors = [
		{// 1
			pt: plaintext,
			key: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			ct: "02 F7 4A 1C 26 45 6B F5 EC D6 A5 36 F0 54 57 B1" +
			"A7 8A C6 89 47 6C 69 7B 39 0C 9C C5 15 D8 E8 88" +
			"96 D6 73 16 88 D1 68 DA 51 D4 0C 70 C3 A1 16 F4" +
			"9D 69 38 8C 10 78 39 93 25 80 6D D5 30 37 65 1B" +
			"ED B7 05 67 37 5D CD 7C D8 95 54 F8 5E 27 A7 C6" +
			"8D 4A DC 70 32 29 8F 7B D4 EF F5 04 AC A6 29 5F" +
			"66 8F BF 47 8A DB 2B E5 1E 6C DE 29 2B 82 DE 2A" +
			"B4 8D 2A C6 56 59 79 22 0E C9 09 A7 E7 57 60 98" +
			"39 24 A1 8E B9 E6 45 E6 BA 0A 8A 64 51 09 E3 53" +
			"D1 D1 FA 6E CD FA A3 9D D9 7E AE 20 94 30 C2 8D" +
			"D2 39 05 53 FC 02 3E 78 85 15 8F 86 13 42 3B 62" +
			"81 2D B4 11 7A 9B 3D 56 C4 FC 05 4F 4B E3 E6 3B" +
			"4F EF 65 7E 2F 81 A5 2F 65 D4 4A AD 0A CE 94 61" +
			"1E 41 3D C7 5E 10 89 5C 70 CE A1 07 70 E6 ED 87" +
			"A3 6A B0 D4 95 49 8B 3D 10 27 C6 F9 C1 51 75 DC" +
			"78 92 FE C3 54 D1 59 40 A5 33 16 58 3C 84 55 52" +
			"70 66 30 D4 C4 31 BC 49 E0 7D 9C BF 98 FA B9 46" +
			"71 08 29 9D D9 B3 58 BB B4 AE E6 4A F6 7F 1E 5F" +
			"EC 3D BA 07 A0 CE E1 BE 2E 2F 0A AB 10 BB 81 06" +
			"35 F4 03 DA 20 B8 AC AA CD E4 D8 55 46 D0 A8 20" +
			"B3 5D B6 14 A3 20 70 FE 8C AC 67 B3 78 18 4C 45" +
			"35 47 53 D3 7E E6 D0 57 EC B3 6E 0D 5B E5 DA C4" +
			"11 CC 36 DA 10 A2 B6 70 BC 20 1B 2C 88 04 37 7F" +
			"25 C5 99 ED 29 29 4F 3E 26 7C 86 6D CC 68 27 6B" +
			"4F F0 0C E6 CC 34 57 6C 7E AD 6B 1D DF 60 92 2A" +
			"D4 19 8A CC 61 4A DE 65 03 24 E3 89 EC 97 C5 83" +
			"28 10 B2 46 1D EB B3 C4 18 E3 C9 92 ED FE BA 6D" +
			"D5 B5 11 2C 49 26 A8 2D 53 FB 76 A3 A1 CD B5 82" +
			"B3 96 C7 32 37 B8 CF FA 30 D4 18 12 28 D6 EB 36" +
			"3D 55 47 5F 36 F1 1C 8F 14 1C 7F D7 C2 49 83 7E" +
			"85 FE DB 07 0F 54 A5 5A DF 2A 72 58 42 C2 A3 19" +
			"EF 9A 69 71 8B 82 49 A1 A7 3C 5A 6E 5B 90 45 95"
		},

		{ // 2
			pt: plaintext,
			key: "C2 1F CF 38 81 CD 5E E8 62 8A CC B0 A9 89 0D F8",
			ct: "3D 02 E0 C7 30 55 91 12 B4 73 B7 90 DE E0 18 DF" +
			"CD 6D 73 0C E5 4E 19 F0 C3 5E C4 79 0E B6 C7 4A" +
			"B0 BB 1B B7 86 0A 68 5A BF 9C 8F AF 26 3C CA 09" +
			"72 AB CC FE 11 A2 7C 90 9A 7F 10 FF F9 6F B4 89" +
			"77 C3 D4 52 26 FA CD D4 C1 A4 32 2D 52 E9 08 1B" +
			"C3 71 4C B4 22 DE BB 84 B4 43 47 6D F9 8B 71 53" +
			"10 D0 90 37 67 6C E4 D0 6D 89 90 E8 67 79 52 F0" +
			"9D 39 3B 5C 58 D6 11 F1 A1 6A FB 20 0C 44 A7 E6" +
			"63 33 1F 32 C1 14 71 86 26 4E 0F 79 47 B7 A9 4F" +
			"AF 9C 31 DD 5F 54 42 06 53 F1 17 A7 1F 40 B8 1F" +
			"1A 86 5C 7B 1D 80 75 39 34 A8 D9 B0 E6 F0 74 39" +
			"8B EF 74 7E 8A A0 21 0A 92 67 44 D4 E9 52 E1 30" +
			"15 4F 72 57 3C 5E 7A 61 30 25 F2 54 5A 2E 62 89" +
			"EF 83 EB FC 44 20 50 4E 02 56 4F C1 B9 03 71 7B" +
			"9D F9 ED 6C FA 75 9B BE 6C 29 E0 D8 FA F4 6D 67" +
			"81 60 7A 03 30 B8 1F 8E 30 2F A2 A0 04 25 83 C5" +
			"DF 3F 51 1D 91 E1 5F 9B FA C6 C5 AC 30 DB EE 78" +
			"89 3E 02 66 4C B8 1F 8F EA 03 60 DC 86 56 5A 1D" +
			"7A 19 53 47 E9 81 12 96 A1 8F B7 8D CB 73 8B D7" +
			"77 DB EA B3 43 69 3C 6B 95 12 1D A8 98 19 03 34" +
			"E7 CA 81 6F 72 DC 49 37 D0 DC 14 47 70 D4 1D A7" +
			"48 9E D7 27 20 24 41 DB FD 30 84 4D 5C D0 08 A7" +
			"D1 31 58 D4 2D 70 4A B7 96 4E F9 47 A9 39 95 C4" +
			"71 A9 DA 5F 04 BD 4F E1 36 AC 1F EA 3E 96 E8 37" +
			"5D 52 B6 CB 29 E6 05 13 C5 9C 04 39 AD F1 68 F0" +
			"7F 63 A2 90 85 B1 D5 B0 C5 A7 95 33 9D 3A EF 69" +
			"45 43 54 3D 47 3E 41 9F E9 33 3A 84 60 D0 53 46" +
			"76 12 5C AA 1B 3E 80 3A 27 84 02 A3 9A 2A A2 DE" +
			"68 C2 5E 41 74 26 0D FB 2D E5 F3 F1 8C B5 39 9D" +
			"8B 81 CD DB A8 3A 30 21 3F 92 43 F2 5E 99 22 4F" +
			"98 69 3C 6C B1 51 98 83 8F E2 7D 55 A0 88 9A E1" +
			"9F B4 92 E1 B5 40 36 3A E3 83 C0 1F 9F A2 26 1A"
		},

		{ // 3
			pt: plaintext,
			key: "1D 27 2C 6A 2D 8E 3D FC AC 14 05 6B 78 D6 33 A0",
			ct: "A3 A9 7A BB 80 39 38 20 B7 E5 0C 4A BB 53 82 3D" +
			"C4 42 37 99 C2 EF C9 FF B3 A4 12 5F 1F 4C 99 A8" +
			"AE 95 3E 56 D3 8B D2 67 67 C3 64 9E EF 34 D9 19" +
			"C3 AC E8 0B CF 72 A4 07 3D DC 6A 02 36 C7 F8 DC" +
			"EB 17 70 19 26 FB 53 6E F5 48 15 A6 18 B6 2D 33" +
			"DE DA FB 4F 0B B2 9E DB 56 96 84 1D A4 69 97 55" +
			"E2 C9 42 98 6D 2E 1A 61 5C 0A 49 09 0F 4D 08 34" +
			"DB 92 6B 88 5A B5 B7 80 D3 62 CB 1E 9F D7 F0 3A" +
			"B2 EE 48 9D 93 ED FF A4 C9 09 03 16 90 C4 E6 97" +
			"D7 22 0B 53 B7 F2 CF 22 DA 21 1A 04 5A CD D5 87" +
			"DF 87 E6 A7 4C E6 3A 72 49 36 9E 8F FA 6F 85 51" +
			"F8 55 DB 18 AB 8B EF EF 63 82 B4 21 2D DF E2 9A" +
			"36 9C BF 83 23 60 3F 5C A8 66 45 CA 74 A2 A2 16" +
			"96 5F 9B BE 99 68 6F 30 47 67 01 FF 18 73 C9 00" +
			"28 99 2C 70 15 93 B2 DC 22 73 9B 01 02 73 2C 27" +
			"79 9C 5B 07 32 6E A1 A1 3D B2 B2 57 5C B7 FC 10" +
			"5D 29 F7 EE A8 92 33 49 E0 D0 CB 38 3D 73 53 5A" +
			"9A FE 32 99 1F C9 CD 01 50 8A B9 EA 16 0D 06 82" +
			"2B 1F 6C BA ED D0 13 EF 64 7C 9B 29 17 EB 22 90" +
			"27 90 B5 5E 5D C7 5E 85 6F 22 0D 58 0F 39 F1 F0" +
			"06 E5 1C D9 77 D7 19 8B 37 44 8B 56 62 C9 8C D6" +
			"88 71 4C E1 14 11 6D 43 1D BE D0 3D 5A 55 04 14" +
			"3C 92 77 73 A1 41 FA C0 C3 DE D7 52 D3 ED F6 A6" +
			"6B 47 C7 1C EB EE 16 8A 1F D3 35 9E F0 B6 98 A5" +
			"AF EA 62 94 5F A1 8B 00 89 E7 A4 4E 3D 5A DA 15" +
			"CA 71 FC 88 5D 2E 58 D6 1A 3A 50 63 D0 1B EA 84" +
			"D4 51 C0 EA C4 4A 53 72 A4 E3 48 FF 05 47 22 CA" +
			"AD 0F 9D 6D D6 B4 86 E9 BA 11 4D 2F 08 AC 31 D0" +
			"BB C7 15 7B 12 CB D3 75 43 FB 08 CF 96 D7 A8 0F" +
			"45 AC 39 FC AF 86 A1 CB 66 AE F8 44 52 F3 9E B5" +
			"B5 23 2E F2 D1 F9 D4 FE 68 97 16 18 3B D4 AF C2" +
			"97 C0 73 3F F1 F1 8D 25 6A 59 E2 BA AB C1 F4 F1"
		},

		{ // 4
			pt: "00000000000000000000000000000000",
			key: "00000000000000000000000000000000",
			ct: "02f74a1c26456bf5ecd6a536f05457b1"
		},

		{ // 5
			pt: "00000000000000000000000000000000",
			key: "c21fcf3881cd5ee8628accb0a9890df8",
			ct: "3d02e0c730559112b473b790dee018df"
		},

		{ // 6
			pt: "00000000000000000000000000000000",
			key: "1d272c6a2d8e3dfcac14056b78d633a0",
			ct: "a3a97abb80393820b7e50c4abb53823d"
		},

		{ // 7
			pt: "00000000000000000000000000000000",
			key: "0053a6f94c9ff24598eb3e91e4378add",
			iv: "0d74db42a91077de",
			ct: "75d186d6bc6905c64f1b2dfdd51f7bfc"
		},

		{ // 8
			pt: "00000000000000000000000000000000",
			key: "0558abfe51a4f74a9df04396e93c8fe2",
			iv: "167de44bb21980e7",
			ct: "476e2750c73856c93563b5f546f56a6a"
		},

		{ // 9
			pt: "00000000000000000000000000000000",
			key: "0a5db00356a9fc4fa2f5489bee4194e7",
			iv: "1f86ed54bb2289f0",
			ct: "921fcf4983891365a7dc901924b5e24b"
		},

		{ // 10
			pt: "00000000000000000000000000000000",
			key: "0f62b5085bae0154a7fa4da0f34699ec",
			iv: "288ff65dc42b92f9",
			ct: "613cb0ba96aff6cacf2a459a102a7f78"
		}
	];


//console.log(plaintext.toHex());

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];
		
		var iv = null;

		var key = typeof vector.key == 'string' ? Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector.key);
		var expected = typeof vector.ct == 'string' ? Buffer.from(vector.ct.replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector.ct);
		var pt = typeof vector.pt == 'string' ? Buffer.from(vector.pt.replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector.pt);
		if (vector.iv) {
			iv = typeof vector.iv == 'string' ? Buffer.from(vector.iv.replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector.iv);
		}

		var cipher = new jCastle.algorithm.rabbit('rabbit');

		if (iv) cipher.setInitialVector(iv);
		
		cipher.keySchedule(key, true);

		var ct = cipher.crypt(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		// decription
		
		if (iv) cipher.setInitialVector(iv);
		
		cipher.keySchedule(key, false);

		var dt = cipher.crypt(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");

	}

});
