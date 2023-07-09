/**
 * jCastle - Exception & Assert
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./lang/en');
require('./lang/ko');

jCastle.log = function(...args)
{
	if (jCastle.options.debug) console.log(...args);
};

/**
 * get an error message.
 * 
 * @public
 * @param {string} error 
 * @param {string} eCode 
 * @returns error message
 */
jCastle.message = function(error, eCode)
{
	var msg = jCastle.lang.text(error);
	if (eCode) msg += '\n(Error Code: ' + eCode + ')';
	return msg;
};

/**
 * throws an error.
 * 
 * @public
 * @param {string} error error message
 * @param {string} eCode error code
 * @param {string} type error type
 * @returns error.
 */
jCastle.exception = function(error, eCode, type)
{
	type = type || 'error';

	var msg = jCastle.message(error, eCode);

//	if (jCastle.options.debug) {
//		msg += '\n\n' + jCastle.exception.stackTrace();
//	} else {
//		msg += ' (' + jCastle.lang.text('LOCATION') + ': ' + arguments.callee.caller.name + ')';
//	}

    if (jCastle.options.debug) {
        jCastle.log(msg);
    }

	switch (type.toLowerCase()) {
		case 'eval':		return new EvalError(msg);
		case 'ranage':		return new RangeError(msg);
		case 'reference':	return new ReferenceError(msg);
		case 'syntax':		return new SyntaxError(msg);
		case 'type':		return new TypeError(msg);
		case 'uri':			return new URIError(msg);
		case 'error':
		default:			return new Error(msg);
	}
};

/**
 * compares the original with the check value and if not the same then throws an error.
 * 
 * @public
 * @param {mixed} a target 
 * @param {mixed} b check value
 * @param {string} msg error message
 * @param {string} eCode error code
 * @param {string} type error type
 * @returns an error if comparing fails.
 */
jCastle.assert = function(a, b, msg, eCode, type)
{
/*    
	if (typeof a !== typeof b) throw jCastle.exception(msg, type);
	if (a == null && b == null) return;
	if (typeof a == 'string' || typeof a == 'number' || typeof a == 'boolean') {
		if (a !== b) throw jCastle.exception(msg, eCode, type);
	} else if (!jCastle.util.equals(a, b)) {
		throw jCastle.exception(msg, eCode, type);
	}
*/
    if (!Object.is(a, b)) throw jCastle.exception(msg, eCode, type);
};

/*
The Error object in all browsers support the following two properties:

name: The name of the error, or more specifically, the name of the constructor function the error belongs to.
message: A description of the error, with this description varying depending on the browser.

try{
    document.body.filters[0].apply()
}
catch(e){
    alert(e.name + "\n" + e.message)
}

Six possible values can be returned by the name property, 
which as mentioned correspond to the names of the error's constructors. They are:

----------------+---------------------------------------------------------------------------------------------
Error Name      | Description
----------------+---------------------------------------------------------------------------------------------
EvalError       | An error in the eval() function has occurred.
----------------+---------------------------------------------------------------------------------------------
RangeError      | Out of range number value has occurred.
----------------+---------------------------------------------------------------------------------------------
ReferenceError  | An illegal reference has occurred.
----------------+---------------------------------------------------------------------------------------------
SyntaxError     | A syntax error within code inside the eval() function has occurred.
                | All other syntax errors are not caught by try/catch/finally, 
				| and will trigger the default browser error message associated with the error. 
				| To catch actual syntax errors, you may use the onerror event.
----------------+---------------------------------------------------------------------------------------------
TypeError       | An error in the expected variable type has occurred.
----------------+---------------------------------------------------------------------------------------------
URIError        | An error when encoding or decoding the URI has occurred (ie: when calling encodeURI()).
----------------+---------------------------------------------------------------------------------------------



http://stackoverflow.com/questions/591857/how-can-i-get-a-javascript-stack-trace-when-i-throw-an-exception

ie and safari doesn't support stack.

function stackTrace(caller) { // caller should be arguments.callee.caller
	function st2(f) {
		return !f ? [] : 
        st2(f.caller).concat([f.toString().split('(')[0].substring(9) + '(' + f.arguments.join(',') + ')']);
	}
	
	var err = new Error();
	return typeof err.stack == 'undefined' ? st2(caller) : err.stack;
}

function stacktrace() { 
  function st2(f) {
    return !f ? [] : 
        st2(f.caller).concat([f.toString().split('(')[0].substring(9) + '(' + f.arguments.join(',') + ')']);
  }
  return st2(arguments.callee.caller);
}

function stackTrace() {
    var err = new Error();
    return err.stack;
}
*/

/*
chrome:

TypeError: Cannot read property 'dont' of undefined
    at Object.jCastle.stackTrace (error.js:164)
    at Object.jCastle.exception (error.js:213)
    at jCastle.Mcrypt.start (mcrypt.js:346)
    at Object.<anonymous> (error_test.html:84)
    at Object.Test.run (qunit-1.19.0.js:810)
    at qunit-1.19.0.js:942
    at process (qunit-1.19.0.js:624)
    at begin (qunit-1.19.0.js:606)
    at qunit-1.19.0.js:666


Opera: same with chrome

TypeError: Cannot read property 'dont' of undefined
    at Object.jCastle.stackTrace (error.js:164)
    at Object.jCastle.exception (error.js:213)
    at jCastle.Mcrypt.start (mcrypt.js:346)
    at Object.<anonymous> (error_test.html:84)
    at Object.Test.run (qunit-1.19.0.js:810)
    at qunit-1.19.0.js:942
    at process (qunit-1.19.0.js:624)
    at begin (qunit-1.19.0.js:606)
    at qunit-1.19.0.js:666

firefox:

jCastle.stackTrace@http://localhost/test/http_openssl/jCastle/error.js:164:3
jCastle.exception@http://localhost/test/http_openssl/jCastle/error.js:213:19
jCastle.Mcrypt.prototype.start@http://localhost/test/http_openssl/jCastle/mcrypt.js:346:1
@http://localhost/test/http_openssl/jCastle/tests/error_test.html:84:1
Test.prototype.run@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:810:14
run/<@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:942:6
process@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:624:4
begin@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:606:2
resumeProcessing/<@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:666:4
setTimeout handler*resumeProcessing@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:658:3
.load@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:561:4
EventListener.handleEvent*addEvent@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:3266:3
@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:3956:3
@http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:3150:2


ie 11:

TypeError: Unable to get property 'dont' of undefined or null reference
   at jCastle.stackTrace (http://localhost/test/http_openssl/jCastle/error.js:164:3)
   at jCastle.exception (http://localhost/test/http_openssl/jCastle/error.js:213:3)
   at jCastle.Mcrypt.prototype.start (http://localhost/test/http_openssl/jCastle/mcrypt.js:346:3)
   at Anonymous function (http://localhost/test/http_openssl/jCastle/tests/error_test.html:84:3)
   at Test.prototype.run (http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:810:4)
   at Anonymous function (http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:942:6)
   at process (http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:624:4)
   at begin (http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:606:2)
   at Anonymous function (http://localhost/test/http_openssl/jCastle/tests/qunit/qunit-1.19.0.js:666:4)


*/
// got from: http://www.eriwen.com/javascript/js-stack-trace/
// updated & bug fixed
/*
jCastle.exception.stackTrace = function()
{
	var callstack = [];
	var isCallstackPopulated = false;

	try {
		i.dont.exist += 0; //doesn't exist- that's the point
	} catch(e) {
		if (e.stack) {
			var lines = e.stack.split('\n');
			for (var i = 0, len = lines.length; i < len; i++) {
				if (lines[i].match(/^\s*(at )?[A-Za-z0-9\-_\.\$]+(@|\s*\()/) && !lines[i].match(/jCastle\.exception/)) {
					callstack.push(lines[i].trim());
				}
			}
			//Remove call to printStackTrace()
			callstack.shift();
			isCallstackPopulated = true;
		} else if ('undefined' !== typeof window && window.opera && e.message) { //Opera
			var lines = e.message.split('\n');
			for (var i = 0, len = lines.length; i < len; i++) {
				if (lines[i].match(/^\s*[A-Za-z0-9\-_\$]+\(/) && !lines[i].match(/jCastle\.exception/)) {
					var entry = lines[i].trim();
					//Append next line also since it has the file info
					if (lines[i+1]) {
						entry += ' at ' + lines[i + 1];
						i++;
					}
					callstack.push(entry);
				}
			}
			//Remove call to printStackTrace()
			callstack.shift();
			isCallstackPopulated = true;
		}
	}
	if (!isCallstackPopulated) { //IE and Safari
		var currentFunction = arguments.callee.caller;
		while (currentFunction) {
			var fn = currentFunction.toString();
			var fname = fn.substring(fn.indexOf("function") + 8, fn.indexOf('(')).trim() || 'anonymous';
			callstack.push(fname);
			currentFunction = currentFunction.caller;
		}
	}

	return callstack.join('\n');
};
*/