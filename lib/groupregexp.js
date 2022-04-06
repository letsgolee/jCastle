/**
 * GroupRegExp - JavaScript Group RegExp Implimentation
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2016-2022 Jacob Lee.
 * http://jCastle.net
 * version 1.0
 */


var GroupRegExp = (function() {

//
// ----------------------------------------------------------------------------
// GroupRegExp class
// ----------------------------------------------------------------------------
//

	var GroupRegExp = function(flags)
	{
		this.global = flags ? /g/.test(flags) : true;
		this.ignoreCase = flags ? /i/.test(flags) : false;
		this.multiline = flags ? /m/.test(flags) : false;
		this.unicode = flags ? /u/.test(flags) : false;

		this.patterns = [];
		this.constructed = false;
	};

	GroupRegExp.prototype =	{
		reset: function()
		{
			this.patterns = [];
		},

		add: function(pattern, replacement)
		{
			// number of groups
			// http://stackoverflow.com/questions/16046620/regex-to-count-the-number-of-capturing-groups-in-a-regex
			var num_groups = new RegExp(pattern + '|').exec('').length - 1;

			var info = {
				pattern: pattern,
				numGroups: num_groups,
				replacement: replacement
			};

			this.patterns.push(info);
			return this;
		},

		_buildFlags: function()
		{
			return (this.global ? 'g' : '') + (this.ignoreCase ? 'i' : '') + (this.multiline ? 'm' : '') + (this.unicode ? 'u' : '');
		},

		_buildPattern: function()
		{
			var index = 1, groupreg = '';

			// change remplacement
			// '$&' --> '$'+(num_groups + 1)
			// '$\d' --> '$' + (num_groups + \d + 1)
			// ...

			var groupReplacement = function(match, p1, p2)
			{
				if (p2 == '&') return '\$' + index;
				return '\$' + (parseInt(p2) + index);
			};

			for (var i = 0; i < this.patterns.length; i++) {
				groupreg += '(' + this.patterns[i].pattern + ')|';

				this.patterns[i].groupReplacement = this.patterns[i].replacement.replace(/(\$(&|\d+))/g, groupReplacement);

				index += this.patterns[i].numGroups + 1;
			}
			groupreg = groupreg.substr(0, groupreg.length - 1);

			return groupreg;
		},

		match: function(str)
		{
			var groupreg = this._buildPattern();
			var flags = this._buildFlags();

			return str.match(new RegExp(groupreg, flags));
		},

		exec: function(str)
		{
			return this.match(str);
		},

		test: function(str)
		{
			var groupreg = this._buildPattern();
			var flags = this._buildFlags();

			return new RegExp(groupreg, flags).test(str);
		},

		replace: function(str, func)
		{
			var groupreg = this._buildPattern();
			var flags = this._buildFlags();
			var self = this;

			if (func && typeof func !== 'function') func = null;

//console.log(groupreg);

/*
RegExp custom function arguments:

-----------------------------------------------------------------------------------------------------
match       | The matched substring. (Corresponds to $& above.)
------------+----------------------------------------------------------------------------------------
p1, p2, ... | The nth parenthesized submatch string, provided the first argument to replace() was a
            | RegExp object. (Corresponds to $1, $2, etc. above.) For example, if /(\a+)(\b+)/, was
			| given, p1 is the match for \a+, and p2 for \b+.
------------+----------------------------------------------------------------------------------------
offset      | The offset of the matched substring within the whole string being examined. (For 
            | example, if the whole string was 'abcd', and the matched substring was 'bc', then this
			| argument will be 1.)
------------+----------------------------------------------------------------------------------------
string      | The whole string being examined.
-----------------------------------------------------------------------------------------------------
*/
			var groupReplace = function()
			{
				var index = 1, replacement;
				var args = arguments;

				if (func) return func.apply(null, args);

				var matchCallback = function(match, p1)
				{
					var res = args[parseInt(p1)];
					return res ? res : '';
				};

				// remove match, offset and string parameters
				for (var i = 0; i < self.patterns.length; i++) {
					var p = args[index];
					if (p) {
						replacement = self.patterns[i].groupReplacement;
						return replacement.replace(/\$(\d+)/g, matchCallback);
					}
					index += self.patterns[i].numGroups + 1;
				}
				return args[0];
			};

			str = str.replace(new RegExp(groupreg, flags), groupReplace);

			return str;
		},

		toString: function()
		{
			return this._buildPattern();
		}
	};
})();

module.exports = GroupRegExp;