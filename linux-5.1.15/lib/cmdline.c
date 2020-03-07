/*
 * linux/lib/cmdline.c
 * Helper functions generally used for parsing kernel command line
 * and module options.
 *
 * Code and copyrights come from init/main.c and arch/i386/kernel/setup.c.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 *
 * GNU Indent formatting options for this file: -kr -i8 -npsl -pcs
 *
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>

/*
 *	If a hyphen was found in get_option, this will handle the
 *	range of numbers, M-N.  This will expand the range and insert
 *	the values[M, M+1, ..., N] into the ints array in get_options.
 */

static int get_range(char **str, int *pint, int n)
{
	int x, inc_counter, upper_range;

	(*str)++;
	upper_range = simple_strtol((*str), NULL, 0);
	inc_counter = upper_range - *pint;
	for (x = *pint; n && x < upper_range; x++, n--)
		*pint++ = x;
	return inc_counter;
}

/**
 *	get_option - Parse integer from an option string
 *	@str: option string
 *	@pint: (output) integer value parsed from @str
 *
 *	Read an int from an option string; if available accept a subsequent
 *	comma as well.
 *
 *	Return values:
 *	0 - no int in string
 *	1 - int found, no subsequent comma
 *	2 - int found including a subsequent comma
 *	3 - hyphen found to denote a range
 */

int get_option(char **str, int *pint)
{
	char *cur = *str;

	if (!cur || !(*cur))
		return 0;
	*pint = simple_strtol(cur, str, 0);
	if (cur == *str)
		return 0;
	if (**str == ',') {
		(*str)++;
		return 2;
	}
	if (**str == '-')
		return 3;

	return 1;
}
EXPORT_SYMBOL(get_option);

/**
 *	get_options - Parse a string into a list of integers
 *	@str: String to be parsed
 *	@nints: size of integer array
 *	@ints: integer array
 *
 *	This function parses a string containing a comma-separated
 *	list of integers, a hyphen-separated range of _positive_ integers,
 *	or a combination of both.  The parse halts when the array is
 *	full, or when no more numbers can be retrieved from the
 *	string.
 *
 *	Return value is the character in the string which caused
 *	the parse to end (typically a null terminator, if @str is
 *	completely parseable).
 */

char *get_options(const char *str, int nints, int *ints)
{
	int res, i = 1;

	while (i < nints) {
		res = get_option((char **)&str, ints + i);
		if (res == 0)
			break;
		if (res == 3) {
			int range_nums;
			range_nums = get_range((char **)&str, ints + i, nints - i);
			if (range_nums < 0)
				break;
			/*
			 * Decrement the result by one to leave out the
			 * last number in the range.  The next iteration
			 * will handle the upper number in the range
			 */
			i += (range_nums - 1);
		}
		i++;
		if (res == 1)
			break;
	}
	ints[0] = i - 1;
	return (char *)str;
}
EXPORT_SYMBOL(get_options);

/**
 *	memparse - parse a string with mem suffixes into a number
 *	@ptr: Where parse begins
 *	@retptr: (output) Optional pointer to next char after parse completes
 *
 *	Parses a string into a number.  The number stored at @ptr is
 *	potentially suffixed with K, M, G, T, P, E.
 */
/*
   	memparse() : 단위를 포함한 숫자를 파싱하여 값을 리턴하고,
				 retptr에는 파싱 완료한 다음 문자열을 가리킨다.
*/
unsigned long long memparse(const char *ptr, char **retptr)
{
	char *endptr;	/* local pointer to end of parsed string */

	/*	
		ptr 문자열을 unsigned long long으로 변환하여 리턴한다.
		retptr에는 변환에 필요한 문자열의 끝+1이 담긴다.

		ex) ptr="10G"

			-> ret=10ULL
			   retptr="G"
	*/
	unsigned long long ret = simple_strtoull(ptr, &endptr, 0);

	/*
		단위를 나타내는 문자열을 비교하여 
		일치하는 경우 해당 case 문부터 break 될 때까지 수행한다.
	 */
	switch (*endptr) {
	case 'E':
	case 'e':
		ret <<= 10;
	case 'P':
	case 'p':
		ret <<= 10;
	case 'T':
	case 't':
		ret <<= 10;
	case 'G':
	case 'g':
		ret <<= 10;
	case 'M':
	case 'm':
		ret <<= 10;
	case 'K':
	case 'k':
		ret <<= 10;
		endptr++;
	default:
		break;
	}

	if (retptr)
		*retptr = endptr;

	return ret;
}
EXPORT_SYMBOL(memparse);

/**
 *	parse_option_str - Parse a string and check an option is set or not
 *	@str: String to be parsed
 *	@option: option name
 *
 *	This function parses a string containing a comma-separated list of
 *	strings like a=b,c.
 *
 *	Return true if there's such option in the string, or return false.
 */
bool parse_option_str(const char *str, const char *option)
{
	while (*str) {
		if (!strncmp(str, option, strlen(option))) {
			str += strlen(option);
			if (!*str || *str == ',')
				return true;
		}

		while (*str && *str != ',')
			str++;

		if (*str == ',')
			str++;
	}

	return false;
}

/*
 * Parse a string to get a param value pair.
 * You can use " around spaces, but can't escape ".
 * Hyphens and underscores equivalent in parameter names.
 */
/*
	1) "foo=bar"
	2) foo="bar"
	3) foo=bar
*/
char *next_arg(char *args, char **param, char **val)
{
	unsigned int i, equals = 0;
	int in_quote = 0, quoted = 0;
	char *next;

	if (*args == '"') {
		args++;
		in_quote = 1;
		quoted = 1;
	}
	/*
		1) in_quote = 1, quoted = 1
		2),3)  		= 0, 		= 0
	*/


	for (i = 0; args[i]; i++) {
		if (isspace(args[i]) && !in_quote) // in_quote 변수는 현재 args[]가 " " 안에 있는 지를
			break;
		if (equals == 0) {
			if (args[i] == '=')
				equals = i;
		}
		if (args[i] == '"')
			in_quote = !in_quote;
	}

	*param = args;
	if (!equals)
		*val = NULL;
	else {
		args[equals] = '\0';
		*val = args + equals + 1;

		/* Don't include quotes in value. */
		if (**val == '"') {
			(*val)++;
			if (args[i-1] == '"')
				args[i-1] = '\0';
		}
	}
	
	// 1)의 경우 마지막 "를 '\0'로 치환
	if (quoted && args[i-1] == '"')
		args[i-1] = '\0';

	if (args[i]) {
		args[i] = '\0';
		next = args + i + 1;
	} else
		next = args + i;

	/* Chew up trailing spaces. */
	return skip_spaces(next);
}
