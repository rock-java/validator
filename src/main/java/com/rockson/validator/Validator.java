package com.rockson.validator;

import java.io.InputStream;
import java.math.BigDecimal;
import java.util.Date;
import java.util.Locale;
import java.util.regex.Pattern;

public class Validator {

	/**
	 * Validators
	 */

	/**
	 * check if the string matches the comparison.
	 * 
	 * @param str
	 * @param comparison
	 * @return
	 */
	public static boolean equals(String str, Number comparison) {
		return false;
	}

	/**
	 * check if the string contains the seed.
	 * 
	 * @param str
	 * @param seed
	 * @return
	 */
	public static boolean contains(String str, String seed) {
		return false;
	}

	/**
	 * check if string matches the pattern. Either matches('foo', /foo/i) or matches('foo', 'foo', 'i').
	 * 
	 * @param str
	 * @param pattern
	 * @param modifiers
	 * @return
	 */
	public static boolean matches(String str, String pattern, int flags) {
		return Pattern.compile(pattern, flags).matcher(str).matches();
	}

	/**
	 * check if the string is an email. options is an object which defaults to { allow_display_name: false,
	 * allow_utf8_local_part: true }. If allow_display_name is set to true, the validator will also match Display Name
	 * <email-address>. If allow_utf8_local_part is set to false, the validator will not allow any non-English UTF8
	 * character in email address' local part.
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isEmail(String str) {
		return false;
	}

	public static boolean isEmail(String str, EmailOptions options) {
		return false;
	}

	/**
	 * check if the string is an URL. options is an object which defaults to { protocols: ['http','https','ftp'],
	 * require_tld: true, require_protocol: false, allow_underscores: false, host_whitelist: false, host_blacklist:
	 * false, allow_trailing_dot: false, allow_protocol_relative_urls: false }.
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isURL(String str) {
		return false;
	}

	public static boolean isURL(String str, URLOptions options) {
		return false;
	}

	/**
	 * check if the string is a fully qualified domain name (e.g. domain.com). options is an object which defaults to {
	 * require_tld: true, allow_underscores: false, allow_trailing_dot: false }.
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isFQDN(String str) {
		return false;
	}

	public static boolean isFQDN(String str, FQDNOptions options) {
		return false;
	}

	/**
	 * check if the string is an IP (version 4 or 6).
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isIP(String str) {
		return false;
	}

	public static boolean isIP(String str, IPVersion version) {
		return false;
	}

	/**
	 * check if the string contains only letters (a-zA-Z).
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isAlpha(String str) {
		return false;
	}

	public static boolean isNumeric(String str) {
		return false;
	}

	public static boolean isAlphanumeric(String str) {
		return false;
	}

	public static boolean isBase64(String str) {
		return false;
	}

	public static boolean isHexadecimal(String str) {
		return false;
	}

	public static boolean isHexColor(String str) {
		return false;
	}

	public static boolean isLowercase(String str) {
		return false;
	}

	public static boolean isUppercase(String str) {
		return false;
	}

	public static boolean isInt(String str) {
		return false;
	}

	public static boolean isFloat(String str) {
		return false;
	}

	public static boolean isDivisibleBy(String str, int number) {
		return false;
	}

	public static boolean isNull(String str) {
		return false;
	}

	public static boolean isLength(String str, int min, int max) {
		return false;
	}

	public static boolean isLength(String str, int min) {
		return false;
	}

	public static boolean isByteLength(String str, int min, int max) {
		return false;
	}

	public static boolean isByteLength(String str, int min) {
		return false;
	}

	public static boolean isUUID(String str) {
		return false;
	}

	public static boolean isUUID(String str, UUIDVersion version) {
		return false;
	}

	public static boolean isDate(String str) {
		return false;
	}

	public static boolean isAfter(String str, Date date) {
		return false;
	}

	public static boolean isBefore(String str, Date date) {
		return false;
	}

	public static boolean isIn(String str, String[] values) {
		return false;
	}

	public static boolean isCreditCard(String str) {
		return false;
	}

	public static boolean isISIN(String str) {
		return false;
	}

	public static boolean isISBN(String str) {
		return false;
	}

	public static boolean isMobilePhone(String str, Locale locale) {
		return false;
	}

	public static boolean isJSON(String str) {
		return false;
	}

	public static boolean isMultibyte(String str) {
		return false;
	}

	public static boolean isAscii(String str) {
		return false;
	}

	public static boolean isFullWidth(String str) {
		return false;
	}

	public static boolean isHalfWidth(String str) {
		return false;
	}

	public static boolean isVariableWidth(String str) {
		return false;
	}

	public static boolean isSurrogatePair(String str) {
		return false;
	}

	public static boolean isMongoId(String str) {
		return false;
	}

	public static boolean isCurrency(String str, CurrencyOptions options) {
		return false;
	}

	public static boolean diff(String num, double value, String d) {
		BigDecimal n1 = new BigDecimal(num);
		BigDecimal n2 = new BigDecimal(value);
		BigDecimal n3 = new BigDecimal(d).abs();
		return n1.subtract(n2).abs().compareTo(n3) < 0;
	}

	public static boolean diff(String num, double value, double d) {
		BigDecimal n1 = new BigDecimal(num);
		BigDecimal n2 = new BigDecimal(value);
		BigDecimal n3 = new BigDecimal(d).abs();
		return n1.subtract(n2).abs().compareTo(n3) < 0;
	}

	/**
	 * Sanitizers
	 */

	public static Date toDate(String str, String format) {
		return null;
	}

	public static int toInt(String str) {
		return 0;
	}

	public static float toFloat(String str) {
		return 0f;
	}

	public static double toDouble(String str) {
		return 0;
	}

	public static boolean toBoolean(String str) {
		return false;
	}

	public static boolean trim(String str) {
		return false;
	}

	public static boolean ltrim(String str) {
		return false;
	}

	public static boolean rtrim(String str) {
		return false;
	}

	public static String escape(String str) {
		return null;
	}

	public static String stripLow(String str) {
		return null;
	}

	public static String whitelist(String str) {
		return null;
	}

	public static String blacklist(String str) {
		return null;
	}

	public static String normalizeEmail(String email) {
		return null;
	}

	public static String md5(String str) {
		return null;
	}

	public static String sha1(String str) {
		return null;
	}

	public static String md5(InputStream in) {
		return null;
	}

	public static String sha1(InputStream in) {
		return null;
	}

	public static String sig(SigAlogorithm alg, String str) {
		return null;
	}

	public static String encodeBase64(byte[] bs) {
		return null;
	}

	public static byte[] decodeBase64(String str) {
		return null;
	}

}
