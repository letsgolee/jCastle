/**
 * jCastle, The Pure Javascript Crypto Library 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const UINT64 = require('./uint64');
const UINT32 = require('./uint32');
const INT64 = require('./int64');

require('./bigint-extend');

const jCastle = {
    version: '2.0.0',
    algorithm: {},
    hash: {},
    lang: {
        i18n: {}
    },
    encoding: {},
    math: {
        uint32: UINT32,
        uint64: UINT64,
        int64: INT64
    },
    _algorithmInfo: {},
    _pkiInfo: {},
    options: {
        debug: false,
        lang: 'en'
    }
};

jCastle.lang.set = l => {
    if (l in jCastle.lang.i18n) {
        jCastle.options.lang = l;
        return true;
    }
    return false;
};

jCastle.lang.text = t => {
    return t in jCastle.lang.i18n[jCastle.options.lang] ? jCastle.lang.i18n[jCastle.options.lang][t] : t;
};

module.exports = jCastle;