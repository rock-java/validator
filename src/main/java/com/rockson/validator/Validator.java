package com.rockson.validator;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javafx.scene.input.DataFormat;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.hamcrest.core.IsNot;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Validator {

	public static final String VERSION = "0.0.1";

	public static final Pattern EMAIL_USER = Pattern
			.compile(
					"^((([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~])+(\\.([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e])|(\\\\[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f])))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))$",
					Pattern.CASE_INSENSITIVE);

	public static final Pattern EMAIL_USER_UTF8 = Pattern
			.compile(
					"^((([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\\.([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))$",
					Pattern.CASE_INSENSITIVE);

	public static final Pattern EMAIL_DISPLAY_NAME = Pattern
			.compile(
					"^(?:[a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~\\.]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(?:[a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~\\.]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]|\\s)*<(.+)>$",
					Pattern.CASE_INSENSITIVE);

	public static final Pattern CREDIT_CARD = Pattern
			.compile("^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$");

	public static final Pattern ISIN = Pattern.compile("^[A-Z]{2}[0-9A-Z]{9}[0-9]$");

	public static final Pattern ISBN10_MAYBE = Pattern.compile("^(?:[0-9]{9}X|[0-9]{10})$");
	public static final Pattern ISBN13_MAYBE = Pattern.compile("^(?:[0-9]{13})$");

	public static final Pattern IPV4_MAYBE = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$");
	public static final Pattern IPV6_BLOCK = Pattern.compile("^[0-9A-F]{1,4}$", Pattern.CASE_INSENSITIVE);

	public static final Pattern UUID3 = Pattern.compile(
			"^[0-9A-F]{8}-[0-9A-F]{4}-3[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$", Pattern.CASE_INSENSITIVE);
	public static final Pattern UUID4 = Pattern.compile(
			"^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$", Pattern.CASE_INSENSITIVE);
	public static final Pattern UUID5 = Pattern.compile(
			"^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$", Pattern.CASE_INSENSITIVE);
	public static final Pattern UUID = Pattern.compile(
			"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$", Pattern.CASE_INSENSITIVE);

	public static final Pattern ALPHA = Pattern.compile("^[A-Z]+$", Pattern.CASE_INSENSITIVE);
	public static final Pattern ALPHA_NUMERIC = Pattern.compile("^^[0-9A-Z]+$", Pattern.CASE_INSENSITIVE);
	public static final Pattern NUMERIC = Pattern.compile("^^[-+]?[0-9]+$");
	public static final Pattern INT_REG = Pattern.compile("^^(?:[-+]?(?:0|[1-9][0-9]*))$");
	public static final Pattern FLOAT_REG = Pattern
			.compile("^^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$");
	public static final Pattern HEXADECIMAL = Pattern.compile("^^[0-9A-F]+$", Pattern.CASE_INSENSITIVE);
	public static final Pattern HEXCOLOR = Pattern.compile("^^#?([0-9A-F]{3}|[0-9A-F]{6})$", Pattern.CASE_INSENSITIVE);

	public static final Pattern ASCII = Pattern.compile("^[\\x00-\\x7F]+$");
	public static final Pattern MULTIBYTE = Pattern.compile("[^\\x00-\\x7F]");
	public static final Pattern FULL_WIDTH = Pattern
			.compile("[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]");
	public static final Pattern HALF_WIDTH = Pattern
			.compile("[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]");

	public static final Pattern SURROGATE_PAIR = Pattern.compile("[\uD800-\uDBFF][\uDC00-\uDFFF]");

	public static final Pattern BASE64 = Pattern.compile(
			"^(?:[A-Z0-9+\\/]{4})*(?:[A-Z0-9+\\/]{2}==|[A-Z0-9+\\/]{3}=|[A-Z0-9+\\/]{4})$", Pattern.CASE_INSENSITIVE);
	public static Map<PhoneLocale, Pattern> PHONES_REGS = new HashMap<PhoneLocale, Pattern>();
	static {
		PHONES_REGS.put(PhoneLocale.zh_CN, Pattern.compile("(\\+?0?86\\-?)?1[345789]\\d{9}$"));
		PHONES_REGS.put(PhoneLocale.en_GB, Pattern.compile("^(\\+?44|0)7\\d{9}$"));
		PHONES_REGS.put(PhoneLocale.en_ZA, Pattern.compile("^(\\+?27|0)\\d{9}$"));
		PHONES_REGS.put(PhoneLocale.en_AU, Pattern.compile("(\\+?0?86\\-?)?1[345789]\\d{9}$"));
		PHONES_REGS.put(PhoneLocale.en_HK, Pattern.compile("^(\\+?852\\-?)?[569]\\d{3}\\-?\\d{4}$"));
		PHONES_REGS.put(PhoneLocale.fr_FR, Pattern.compile("^(\\+?33|0)[67]\\d{8}$"));
		PHONES_REGS.put(PhoneLocale.pt_PT, Pattern.compile("^(\\+351)?9[1236]\\d{7}$"));
		PHONES_REGS.put(PhoneLocale.el_GR, Pattern.compile("^(\\+30)?((2\\d{9})|(69\\d{8}))$"));
	}

	/**
	 * Validators
	 */
	/**
	 * <p>
	 * Checks if a CharSequence is empty ("") or null.
	 * </p>
	 *
	 * <pre>
	 * StringUtils.isEmpty(null)      = true
	 * StringUtils.isEmpty("")        = true
	 * StringUtils.isEmpty(" ")       = false
	 * StringUtils.isEmpty("bob")     = false
	 * StringUtils.isEmpty("  bob  ") = false
	 * </pre>
	 *
	 * <p>
	 * NOTE: This method changed in Lang version 2.0. It no longer trims the CharSequence. That functionality is
	 * available in isBlank().
	 * </p>
	 *
	 * @param cs
	 *            the CharSequence to check, may be null
	 * @return {@code true} if the CharSequence is empty or null
	 * @since 3.0 Changed signature from isEmpty(String) to isEmpty(CharSequence)
	 */
	public static boolean isEmpty(CharSequence str) {
		return str == null || str.length() == 0;
	}

	/**
	 * <p>
	 * Checks if a CharSequence is whitespace, empty ("") or null.
	 * </p>
	 *
	 * <pre>
	 * StringUtils.isBlank(null)      = true
	 * StringUtils.isBlank("")        = true
	 * StringUtils.isBlank(" ")       = true
	 * StringUtils.isBlank("bob")     = false
	 * StringUtils.isBlank("  bob  ") = false
	 * </pre>
	 *
	 * @param cs
	 *            the CharSequence to check, may be null
	 * @return {@code true} if the CharSequence is null, empty or whitespace
	 * @since 2.0
	 * @since 3.0 Changed signature from isBlank(String) to isBlank(CharSequence)
	 */
	public static boolean isBlank(CharSequence str) {
		int strLen;
		if (str == null || (strLen = str.length()) == 0) {
			return true;
		}
		for (int i = 0; i < strLen; i++) {
			if (Character.isWhitespace(str.charAt(i)) == false) {
				return false;
			}
		}
		return true;
	}

	/**
	 * check if the string contains the seed.
	 * 
	 * @param str
	 * @param seed
	 * @return
	 */
	public static boolean contains(String str, String seed) {
		return str.contains(seed);
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
		return isEmail(str, new EmailOptions());
	}

	public static boolean isEmail(String str, EmailOptions options) {
		if (options.isAllowDisplayName()) {
			Matcher displayEmail = EMAIL_DISPLAY_NAME.matcher(str);
			if (displayEmail.matches()) {
				str = displayEmail.group(1);
			}
		} else if (isEmpty(str)) {
			return false;
		}
		int atIndex = str.indexOf('@');
		if (0 >= atIndex) {
			return false;
		}
		String domain = str.substring(0, atIndex);
		String user = str.substring(atIndex + 1);

		FQDNOptions fqdnOptions = new FQDNOptions();
		fqdnOptions.setRequireTld(false);
		if (isBlank(str) || !isFQDN(domain, fqdnOptions)) {
			return false;
		}

		return options.isAllowUtf8LocalPart() ? EMAIL_USER_UTF8.matcher(user).matches() : EMAIL_USER.matcher(user)
				.matches();
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
		return isURL(str, new URLOptions(), new FQDNOptions());
	}

	public static boolean isURL(String url, URLOptions options, FQDNOptions fqdnOptions) {
		if (isBlank(url) || url.length() >= 2083) {
			return false;
		}
		if (url.indexOf("mailto:") == 0) {
			return false;
		}
		// String protocol, auth, host, hostname, port,
		// port_str;
		// String[] split = url.split("://");
		// protocol = url.substring(url.indexOf("://"));
		String cur = url;
		int protocolIndex = cur.indexOf("://");
		if (-1 != protocolIndex) {
			String protocol = cur.substring(0, protocolIndex);
			if (!isBlank(protocol)) {
				if (!options.getProtocols().contains(protocol)) {
					return false;
				}
				cur = cur.substring(protocolIndex + 4);
			}
			int authIndex = cur.indexOf('@');
			if (-1 != authIndex) {
				String auth = cur.substring(0, authIndex);
				cur = cur.substring(authIndex + 1);
				int indexSemicolon = auth.indexOf(':');
				if (-1 == indexSemicolon || indexSemicolon != auth.lastIndexOf(':')) {
					return false;
				}
			}
		} else if (options.isRequireProtocol()) {
			return false;
		} else if (options.isAllowProtocolRelativeUrls() && "//".equals(url.substring(0, 2))) {
			cur = url.substring(2);
		}
		int anchorIndex = cur.indexOf('#');
		if (-1 != anchorIndex) {
			// String anchor = cur.substring(anchorIndex+1);
			cur = cur.substring(0, anchorIndex);
		}
		int paramIndex = cur.indexOf('?');
		if (-1 != anchorIndex) {
			// String param = cur.substring(paramIndex+1);
			cur = cur.substring(0, paramIndex);
		}

		int pathIndex = cur.indexOf('/');
		if (-1 != pathIndex) {
			// String path = cur.substring(pathIndex+1);
			cur = cur.substring(0, pathIndex);
		}

		int portIndex = cur.indexOf(':');
		if (-1 != portIndex) {
			String portStr = cur.substring(portIndex + 1);
			cur = cur.substring(0, portIndex);
			if (!portStr.matches("^[0-9]+$")) {
				return false;
			}
			int port = Integer.valueOf(portStr);
			if (0 >= port || 65535 < port) {
				return false;
			}
		}
		if (0 == cur.length() && options.isAllowEmptyHost()) {
			return true;
		}
		if (!isIP(cur) && !isFQDN(cur, fqdnOptions) && "localhost" != cur) {
			return false;
		}
		if (null != options.getHostWhitelist() && !options.getHostWhitelist().contains(cur)) {
			return false;
		}
		if (null != options.getHostBlacklist() && options.getHostBlacklist().contains(cur)) {
			return false;
		}
		return true;
	}

	/**
	 * check if the string is a fully qualified domain name (e.g. domain.com). options is an object which defaults to {
	 * require_tld: true, allow_underscores: false, allow_trailing_dot: false }.
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isFQDN(String str) {
		return isFQDN(str, new FQDNOptions());
	}

	public static boolean isFQDN(String str, FQDNOptions options) {
		/* Remove the optional trailing dot before checking validity */
		if (options.isAllowTrailingDot() && str.charAt(str.length() - 1) == '.') {
			str = str.substring(0, str.length() - 1);
		}
		String[] parts = str.split("\\.");
		if (options.isRequireTld()) {
			String tld = parts[0];
			if (parts.length < 1
					|| !Pattern.compile("^([a-z\u00a1-\uffff]{2,}|xn[a-z0-9-]{2,})$", Pattern.CASE_INSENSITIVE)
							.matcher(tld).matches()) { // /i.test(tld)
				return false;
			}
		}
		String part;
		for (int i = 0; i < parts.length; i++) {
			part = parts[i];
			if (options.isAllowUnderscores()) {
				if (part.indexOf("__") >= 0) {
					return false;
				}
				part = part.replaceAll("_", "");
			}
			if (!Pattern.compile("^[a-z\u00a1-\uffff0-9-]+$", Pattern.CASE_INSENSITIVE).matcher(part).matches()) {
				return false;
			}
			if (part.charAt(0) == '-' || part.charAt(part.length() - 1) == '-' || part.indexOf("---") >= 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * check if the string is an IP (version 4 or 6).
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isIP(String str) {
		return isIP(str, IPVersion.ipv4) || isIP(str, IPVersion.ipv6);
	}

	public static boolean isIP(String str, IPVersion version) {
		if (IPVersion.ipv4.equals(version)) {
			if (!IPV4_MAYBE.matcher(str).matches()) {
				return false;
			}
			for (String i : str.split("\\.")) {
				if (Integer.valueOf(i) > 255) {
					return false;
				}
			}
			return true;
		} else if (IPVersion.ipv6.equals(version)) {
			boolean foundOmissionBlock = false; // marker to indicate ::
			int scount = 0;
			for (int i = 0; i < str.length(); i++) {
				if (':' == str.charAt(i)) {
					scount++;
				}
			}
			if (scount > 8)
				return false;

			// initial or final ::
			if ("::".equals(str)) {
				return true;
			}
			String cur = str;
			if ("::".equals(cur.substring(0, 2))) {
				cur = ltrim(str, "::");
				foundOmissionBlock = true;
			}
			if ("::".equals(cur.substring(cur.length() - 2))) {
				cur = rtrim(str, "::");
				foundOmissionBlock = true;
			}
			String[] blocks = cur.split(":");

			for (int i = 0; i < blocks.length; ++i) {
				// test for a :: which can not be at the string start/end
				// since those cases have been handled above
				if ("" == blocks[i] && i > 0 && i < blocks.length - 1) {
					if (foundOmissionBlock)
						return false; // multiple :: in address
					foundOmissionBlock = true;
				} else if (!IPV6_BLOCK.matcher(blocks[i]).matches()) {
					return false;
				}
			}

			if (foundOmissionBlock) {
				return blocks.length >= 1;
			} else {
				return blocks.length == 8;
			}
		}
		return false;
	}

	/**
	 * check if the string contains only letters (a-zA-Z).
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isAlpha(String str) {
		return ALPHA.matcher(str).matches();
	}

	public static boolean isNumeric(String str) {
		return NUMERIC.matcher(str).matches();
	}

	public static boolean isAlphanumeric(String str) {
		return ALPHA_NUMERIC.matcher(str).matches();
	}

	public static boolean isBase64(String str) {
		return BASE64.matcher(str).matches();
	}

	public static boolean isHexadecimal(String str) {
		return HEXADECIMAL.matcher(str).matches();
	}

	public static boolean isHexColor(String str) {
		return HEXCOLOR.matcher(str).matches();
	}

	public static boolean isLowercase(String str) {
		return str.equals(str.toLowerCase());
	}

	public static boolean isUppercase(String str) {
		return str.equals(str.toUpperCase());
	}

	public static boolean isInt(String str) {
		return INT_REG.matcher(str).matches();
	}

	public static boolean isFloat(String str) {
		return FLOAT_REG.matcher(str).matches();
	}

	public static boolean isDivisibleBy(String str, int number) {
		return toFloat(str) % number == 0;
	}

	public static boolean isLength(String str, int min, int max) {
		return str.length() >= min && str.length() <= max;
	}

	public static boolean isLength(String str, int min) {
		return str.length() >= min;
	}

	public static boolean isByteLength(String str, String charset, int min, int max)
			throws UnsupportedEncodingException {
		int len = str.getBytes(charset).length;
		return len >= min && len <= max;
	}

	public static boolean isByteLength(String str, String charset, int min) throws UnsupportedEncodingException {
		return str.getBytes(charset).length <= min;
	}

	public static boolean isUUID(String str) {
		return UUID.matcher(str).matches();
	}

	public static boolean isUUID(String str, UUIDVersion version) {
		switch (version) {
		case uuidv3:
			return UUID3.matcher(str).matches();
		case uuidv4:
			return UUID4.matcher(str).matches();
		case uuidv5:
			return UUID5.matcher(str).matches();
		}
		return false;
	}

	public static boolean isDate(String str) {
		DateFormat dateFormat = DateFormat.getDateInstance();
		try {
			return null == dateFormat.parse(str);
		} catch (ParseException e) {
			return false;
		}
	}

	public static boolean isAfter(String str, Date date) {
		return false;
	}

	public static boolean isBefore(String str, Date date) {
		return false;
	}

	public static <T> boolean isIn(T v, T[] values) {
		for (T t : values) {
			if (v.equals(t)) {
				return true;
			}
		}
		return false;
	}

	public static boolean isCreditCard(String str) {
		String sanitized = str;// .replaceAll("[^0-9]+", "");
		if (!CREDIT_CARD.matcher(sanitized).matches()) {
			return false;
		}
		int sum = 0, tmpNum;
		String digit;
		boolean shouldDouble = false;
		for (int i = sanitized.length() - 1; i >= 0; i--) {
			digit = sanitized.substring(i, (i + 1));
			tmpNum = Integer.valueOf(digit);// parseInt(digit, 10);
			if (shouldDouble) {
				tmpNum *= 2;
				if (tmpNum >= 10) {
					sum += ((tmpNum % 10) + 1);
				} else {
					sum += tmpNum;
				}
			} else {
				sum += tmpNum;
			}
			shouldDouble = !shouldDouble;
		}
		return !!((sum % 10) == 0 ? !isBlank(sanitized) : false);
	}

	public static boolean isISIN(String str) {
		if (!ISIN.matcher(str).matches()) {
			return false;
		}

		Matcher matcher = Pattern.compile("[A-Z]").matcher(str);
		StringBuffer sb = new StringBuffer();
		while (matcher.find()) {
			matcher.appendReplacement(sb, Integer.valueOf(matcher.group(), 36).toString());
		}
		String checksumStr = sb.toString();

		int sum = 0, tmpNum;
		String digit;
		boolean shouldDouble = true;
		for (int i = checksumStr.length() - 2; i >= 0; i--) {
			digit = checksumStr.substring(i, (i + 1));
			tmpNum = Integer.valueOf(digit);
			if (shouldDouble) {
				tmpNum *= 2;
				if (tmpNum >= 10) {
					sum += tmpNum + 1;
				} else {
					sum += tmpNum;
				}
			} else {
				sum += tmpNum;
			}
			shouldDouble = !shouldDouble;
		}

		return Integer.valueOf(str.substring(str.length() - 1), 10) == (10000 - sum) % 10;
	}

	public static boolean isISBN(String str) {
		return isISBN(str, ISBNVersion.isbn10) || isISBN(str, ISBNVersion.isbn13);
	}

	public static boolean isISBN(String str, ISBNVersion version) {
		String sanitized = str.replaceAll("[\\s-]+", "");
		int checksum = 0, i;
		if (ISBNVersion.isbn10.equals(version)) {
			if (!ISBN10_MAYBE.matcher(sanitized).matches()) {
				return false;
			}
			for (i = 0; i < 9; i++) {
				checksum += (i + 1) * sanitized.charAt(i);
			}
			if (sanitized.charAt(9) == 'X') {
				checksum += 10 * 10;
			} else {
				checksum += 10 * sanitized.charAt(9);
			}
			if ((checksum % 11) == 0) {
				return !isBlank(sanitized);
			}
		} else if (ISBNVersion.isbn13.equals(version)) {
			if (!ISBN13_MAYBE.matcher(sanitized).matches()) {
				return false;
			}
			int[] factor = new int[] { 1, 3 };
			for (i = 0; i < 12; i++) {
				checksum += factor[i % 2] * sanitized.charAt(i);
			}
			if (sanitized.charAt(12) - ((10 - (checksum % 10)) % 10) == 0) {
				return true;
			}
		}
		return false;
	}

	public static boolean isMobilePhone(String str, PhoneLocale locale) {
		return PHONES_REGS.get(locale).matcher(str).matches();
	}

	public static boolean isJSON(String str) {
		return false;
	}

	public static boolean isMultibyte(String str) {
		return MULTIBYTE.matcher(str).matches();
	}

	public static boolean isAscii(String str) {
		return ASCII.matcher(str).matches();
	}

	public static boolean isFullWidth(String str) {
		return FULL_WIDTH.matcher(str).matches();
	}

	public static boolean isHalfWidth(String str) {
		return HALF_WIDTH.matcher(str).matches();
	}

	public static boolean isVariableWidth(String str) {
		return isFullWidth(str) && isHalfWidth(str);
	}

	public static boolean isSurrogatePair(String str) {
		return SURROGATE_PAIR.matcher(str).matches();
	}

	public static boolean isMongoId(String str) {
		return isHexadecimal(str) && 24 == str.length();
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

	/**
	 * 
	 * @param str
	 * @param format
	 * @return
	 * @throws ParseException
	 */
	public static Date parseDate(String str, String format) throws ParseException {
		return new SimpleDateFormat(format).parse(str);
	}
	public static String formatDate(Date date, String format) throws ParseException {
		return new SimpleDateFormat(format).format(date);
	}

	public static int toInt(String str) {
		return Integer.valueOf(str);
	}

	public static int toInt(String str, int radix) {
		return Integer.valueOf(str, radix);
	}

	public static float toFloat(String str) {
		return Float.valueOf(str);
	}

	public static double toDouble(String str) {
		return Double.valueOf(str);
	}

	public static boolean toBoolean(String str) {
		if ("true".equalsIgnoreCase(str) || "1".equals(str)) {
			return true;
		}
		return false;
	}

	public static boolean trim(String str) {
		return false;
	}

	public static String ltrim(String str) {
		return null;
	}

	public static String ltrim(String str, String part) {
		if (0 == str.indexOf(part)) {
			return str.substring(part.length());
		}
		return str;
	}

	public static String rtrim(String str) {
		return null;
	}

	public static String rtrim(String str, String part) {
		int i = str.lastIndexOf(part);
		if (i == str.length() - part.length()) {
			return str.substring(0, i);
		}
		return str;
	}

	public static String escape(String str) {
		Matcher matcher = Pattern.compile("").matcher(str);
		Map<String, String> map = new HashMap<String, String>();
		map.put("&", "&amp;");
		map.put("\"", "quot;");
		map.put("'", "&#x27;");
		map.put("<", "&lt;");
		map.put(">", "&gt;");
		map.put("\\/", "&#x2F;");
		map.put("\\`", "&#96;");
		StringBuffer sb = new StringBuffer(str.length());
		while (matcher.find()) {
			matcher.appendReplacement(sb, map.get(matcher.group()));
		}
		return sb.toString();
	}

	public static String stripLow(String str) {
		return stripLow(str, false);
	}

	public static String stripLow(String str, boolean keepNewLines) {
		String chars = keepNewLines ? "\\x00-\\x09\\x0B\\x0C\\x0E-\\x1F\\x7F" : "\\x00-\\x1F\\x7F";
		return blacklist(str, chars);
	}

	public static String whitelist(String str, String chars) {
		return str.replaceAll("[^" + chars + "]+", "");
	}

	public static String blacklist(String str, String chars) {
		return str.replaceAll("[" + chars + "]+", "");
	}

	static String toHexString(byte[] bs) {
		char[] strDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		int l = bs.length;
		char r[] = new char[l * 2];
		int k = 0;
		for (int i = 0; i < l; i++) {
			byte byte0 = bs[i];
			r[k++] = strDigits[byte0 >>> 4 & 0xf];
			r[k++] = strDigits[byte0 & 0xf];
		}
		return new String(r);

	}

	public static String md5(String str) {
		try {
			return sig("MD5", str);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sha1(String str) {
		try {
			return sig("SHA1", str);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String md5(InputStream in) throws IOException {
		try {
			return sig("MD5", in);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sha1(InputStream in) throws IOException {
		try {
			return sig("SHA1", in);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sig(String alg, String str) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(alg);
		digest.update(str.getBytes());
		return toHexString(digest.digest());
	}

	public static String sig(String alg, InputStream in) throws NoSuchAlgorithmException, IOException {
		MessageDigest digest = MessageDigest.getInstance(alg);
		byte[] buffer = new byte[1024];
		int len;
		while (-1 != (len = in.read(buffer))) {
			digest.update(buffer, 0, len);
		}
		return toHexString(digest.digest());
	}

	public static String encodeBase64(String str) {
		return encodeBase64(str.getBytes());
	}

	public static String encodeBase64(byte[] bs) {
		return new BASE64Encoder().encode(bs);
	}

	public static String encodeBase64(ByteBuffer bs) {
		return new BASE64Encoder().encode(bs);
	}

	public static byte[] decodeBase64(String str) throws IOException {
		return new BASE64Decoder().decodeBuffer(str);
	}

	public static String decodeBase64AsString(String str) throws IOException {
		return new String(decodeBase64(str));
	}

}
