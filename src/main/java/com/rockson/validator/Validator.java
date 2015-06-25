package com.rockson.validator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
	 * @param str
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
	 * @param str
	 *            the CharSequence to check, may be null
	 * @return {@code true} if the CharSequence is null, empty or whitespace
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
	 *            a string
	 * @param seed
	 *            contained part
	 * @return true if str contains seed
	 */
	public static boolean contains(String str, String seed) {
		if(null == str) return false;
		return str.contains(seed);
	}

	/**
	 * check if string matches the pattern。
	 * 
	 * @param str
	 *            the string to matches
	 * @param pattern
	 *            the match pattern
	 * @return true if matched
	 */
	public static boolean matches(String str, String pattern) {
		if(null == str) return false;
		return Pattern.compile(pattern).matcher(str).matches();
	}

	/**
	 * check if string matches the pattern。
	 * 
	 * @param str
	 *            the string to matches
	 * @param pattern
	 *            the match pattern
	 * @param flags
	 *            the pattern modifiers
	 * @return {@code true} if matched
	 */
	public static boolean matches(String str, String pattern, int flags) {
		if(null == str) return false;
		return Pattern.compile(pattern, flags).matcher(str).matches();
	}

	/**
	 * check if the string is an email.
	 * 
	 * @param str
	 *            email string
	 * @return {@code true} if matched
	 */
	public static boolean isEmail(String str) {
		if(null == str) return false;
		return isEmail(str, new EmailOptions());
	}

	/**
	 * check if the string is an email. options is an object which defaults to { allowDisplayName: false,
	 * allowUtf8LocalPart: true }. If allowDisplayName is set to true, the validator will also match Display Name
	 * &lt;email-address&gt;. If allow_utf8_local_part is set to false, the validator will not allow any non-English
	 * UTF8 character in email address' local part. {@code true} if matched
	 * 
	 * @param str
	 *            email string
	 * @param options
	 *            email options
	 * @return {@code true} if str is email format.
	 */
	public static boolean isEmail(String str, EmailOptions options) {
		if(null == str) return false;
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
	 * check if the string is an URL. using default options;
	 * 
	 * @param str
	 *            a url string
	 * @return true if matched
	 */
	public static boolean isURL(String str) {
		if(null == str) return false;
		return isURL(str, new URLOptions(), new FQDNOptions());
	}

	/**
	 * check if the string is an URL. options is an object which defaults to { protocols: ['http','https','ftp'],
	 * requireTld: true, requireProtocol: false, allowUnderscores: false, hostWhitelist: null, hostBlacklist: null,
	 * allowTrailingDot: false, allowProtocolRelativeUrls: false }.
	 * 
	 * @param url
	 *            a url string
	 * @param options
	 *            urloptions
	 * @param fqdnOptions
	 *            the fqdn option of the url
	 * @return true if matched
	 */
	public static boolean isURL(String url, URLOptions options, FQDNOptions fqdnOptions) {
		if(null == url) return false;
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
	 * check if the string is a fully qualified domain name (e.g. domain.com).
	 * 
	 * @param str
	 *            domain string
	 * @return true if matched
	 */
	public static boolean isFQDN(String str) {
		if(null == str) return false;
		return isFQDN(str, new FQDNOptions());
	}

	/**
	 * check if the string is a fully qualified domain name (e.g. domain.com). options is an object which defaults to {
	 * requireTld: true, allowUnderscores: false, allowTrailing_dot: false }.
	 * 
	 * @param str
	 *            domain
	 * @param options
	 *            domain options
	 * @return true if matched
	 */
	public static boolean isFQDN(String str, FQDNOptions options) {
		if(null == str) return false;
		/* Remove the optional trailing dot before checking validity */
		if (options.isAllowTrailingDot() && str.charAt(str.length() - 1) == '.') {
			str = str.substring(0, str.length() - 1);
		}
		String[] parts = str.split("\\.");
		if (options.isRequireTld()) {
			String tld = parts[0];
			if (parts.length < 1
					|| !Pattern.compile("^([a-z\u00a1-\uffff]{2,}|xn[a-z0-9-]{2,})$", Pattern.CASE_INSENSITIVE)
							.matcher(tld).matches()) {
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
	 *            ip string
	 * @return true if matched
	 */
	public static boolean isIP(String str) {
		if(null == str) return false;
		return isIP(str, IPVersion.ipv4) || isIP(str, IPVersion.ipv6);
	}

	/**
	 * check if the string is an IP with specified ip version.
	 * 
	 * @param str
	 *            ip string
	 * @param version
	 *            ip version
	 * @return true if matched
	 */
	public static boolean isIP(String str, IPVersion version) {
		if(null == str) return false;
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
	 *            alpha string
	 * @return true if matched
	 */
	public static boolean isAlpha(String str) {
		if(null == str) return false;
		return ALPHA.matcher(str).matches();
	}

	/**
	 * check if the string contains only numbers.
	 * 
	 * @param str
	 *            numeric string
	 * @return true if matched
	 */
	public static boolean isNumeric(String str) {
		if(null == str) return false;
		return NUMERIC.matcher(str).matches();
	}

	/**
	 * check if the string contains only letters and numbers.
	 * 
	 * @param str
	 *            letter and number string
	 * @return true if matched
	 */
	public static boolean isAlphanumeric(String str) {
		if(null == str) return false;
		return ALPHA_NUMERIC.matcher(str).matches();
	}

	/**
	 * check if a string is base64 encoded.
	 * 
	 * @param str
	 *            base64 encoded string
	 * @return true if matched
	 */
	public static boolean isBase64(String str) {
		if(null == str) return false;
		return BASE64.matcher(str).matches();
	}

	/**
	 * check if the string is a hexadecimal number.
	 * 
	 * @param str
	 *            hexadecimal string
	 * @return true if matched
	 */
	public static boolean isHexadecimal(String str) {
		if(null == str) return false;
		return HEXADECIMAL.matcher(str).matches();
	}

	/**
	 * check if the string is a hexadecimal color.
	 * 
	 * @param str
	 *            hexadecimal color string
	 * @return true if matched
	 */
	public static boolean isHexColor(String str) {
		if(null == str) return false;
		return HEXCOLOR.matcher(str).matches();
	}

	/**
	 * check if the string is lowercase.
	 * 
	 * @param str
	 *            whole lowercase string
	 * @return true if matched
	 */
	public static boolean isLowercase(String str) {
		if(null == str) return false;
		return str.equals(str.toLowerCase());
	}

	/**
	 * check if the string is uppercase.
	 * 
	 * @param str
	 *            whole uppercase string
	 * @return true if matched
	 */
	public static boolean isUppercase(String str) {
		if(null == str) return false;
		return str.equals(str.toUpperCase());
	}

	/**
	 * check if the string is an integer.
	 * 
	 * @param str
	 *            integer string
	 * @return true if matched
	 */
	public static boolean isInt(String str) {
		if(null == str) return false;
		return INT_REG.matcher(str).matches();
	}

	/**
	 * check if the string is a float.
	 * 
	 * @param str
	 *            float number string
	 * @return true if matched
	 */
	public static boolean isFloat(String str) {
		if(null == str) return false;
		return FLOAT_REG.matcher(str).matches();
	}

	/**
	 * check if the string is a number that's divisible by another.
	 * 
	 * @param str
	 *            a number
	 * @param number
	 *            divisibled number
	 * @return true if matched
	 */
	public static boolean isDivisibleBy(String str, int number) {
		if(null == str || 0 == number) return false;
		return toFloat(str) % number == 0;
	}

	/**
	 * check if the string's length falls in a range.
	 * 
	 * @param str
	 *            a string
	 * @param min
	 *            minimum length of the string
	 * @param max
	 *            maximum length of the string
	 * @return true if matched
	 */
	public static boolean isLength(String str, int min, int max) {
		if(null == str) return false;
		return str.length() >= min && str.length() <= max;
	}

	/**
	 * check if the string's length falls in a range.
	 * 
	 * @param min
	 *            minimum length of the string
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isLength(String str, int min) {
		if(null == str) return false;
		return str.length() >= min;
	}

	/**
	 * check if the string bytes's length falls in a range.
	 * 
	 * @param str
	 *            a string
	 * @param charset
	 *            sttring charset
	 * @param min
	 *            minimum length of the string
	 * @param max
	 *            maximum length of the string
	 * @return true if matched
	 * @throws UnsupportedEncodingException
	 *             if charset not support
	 */
	public static boolean isByteLength(String str, String charset, int min, int max)
			throws UnsupportedEncodingException {
		if(null == str) return false;
		int len = str.getBytes(charset).length;
		return len >= min && len <= max;
	}

	/**
	 * check if the string bytes's length falls in a range.
	 * 
	 * @param str
	 *            a string
	 * @param charset
	 *            sttring charset
	 * @param min
	 *            minimum length of the string
	 * @return true if matched
	 * @throws UnsupportedEncodingException
	 *             if charset not support
	 */
	public static boolean isByteLength(String str, String charset, int min) throws UnsupportedEncodingException {
		if(null == str) return false;
		return str.getBytes(charset).length <= min;
	}

	/**
	 * check if the string is a UUID (version 3, 4 or 5).
	 * 
	 * @param str
	 *            uuid string
	 * @return true if matched
	 */
	public static boolean isUUID(String str) {
		if(null == str) return false;
		return UUID.matcher(str).matches();
	}

	/**
	 * check if the string is a UUID with specified version
	 * 
	 * @param str
	 *            uuid string
	 * @param version
	 *            uuid version
	 * @return true if matched
	 */
	public static boolean isUUID(String str, UUIDVersion version) {
		if(null == str) return false;
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

	/**
	 * check if the string is a date.
	 * 
	 * @param str
	 *            date string
	 * @return true if matched
	 */
	public static boolean isDate(String str) {
		if(isBlank(str)) return false;
		DateFormat dateFormat = DateFormat.getDateInstance();
		try {
			return null == dateFormat.parse(str);
		} catch (ParseException e) {
			return false;
		}
	}

	/**
	 * check if the string is in a array of allowed values
	 * 
	 * @param <T>
	 *            the value type
	 * @param v
	 *            value
	 * @param values
	 *            allowed values
	 * @return true if v in values
	 */
	public static <T> boolean isIn(T v, T[] values) {
		for (T t : values) {
			if (v.equals(t)) {
				return true;
			}
		}
		return false;
	}

	// /**
	// *
	// * @param str
	// * @return true if matched
	// */
	// public static boolean isCreditCard(String str) {
	// String sanitized = str;// .replaceAll("[^0-9]+", "");
	// if (!CREDIT_CARD.matcher(sanitized).matches()) {
	// return false;
	// }
	// int sum = 0, tmpNum;
	// String digit;
	// boolean shouldDouble = false;
	// for (int i = sanitized.length() - 1; i >= 0; i--) {
	// digit = sanitized.substring(i, (i + 1));
	// tmpNum = Integer.valueOf(digit);// parseInt(digit, 10);
	// if (shouldDouble) {
	// tmpNum *= 2;
	// if (tmpNum >= 10) {
	// sum += ((tmpNum % 10) + 1);
	// } else {
	// sum += tmpNum;
	// }
	// } else {
	// sum += tmpNum;
	// }
	// shouldDouble = !shouldDouble;
	// }
	// return !!((sum % 10) == 0 ? !isBlank(sanitized) : false);
	// }
	//
	// /**
	// *
	// * @param str
	// * @return true if matched
	// */
	// public static boolean isISIN(String str) {
	// if (!ISIN.matcher(str).matches()) {
	// return false;
	// }
	//
	// Matcher matcher = Pattern.compile("[A-Z]").matcher(str);
	// StringBuffer sb = new StringBuffer();
	// while (matcher.find()) {
	// matcher.appendReplacement(sb, Integer.valueOf(matcher.group(), 36).toString());
	// }
	// String checksumStr = sb.toString();
	//
	// int sum = 0, tmpNum;
	// String digit;
	// boolean shouldDouble = true;
	// for (int i = checksumStr.length() - 2; i >= 0; i--) {
	// digit = checksumStr.substring(i, (i + 1));
	// tmpNum = Integer.valueOf(digit);
	// if (shouldDouble) {
	// tmpNum *= 2;
	// if (tmpNum >= 10) {
	// sum += tmpNum + 1;
	// } else {
	// sum += tmpNum;
	// }
	// } else {
	// sum += tmpNum;
	// }
	// shouldDouble = !shouldDouble;
	// }
	//
	// return Integer.valueOf(str.substring(str.length() - 1), 10) == (10000 - sum) % 10;
	// }
	//
	// /**
	// *
	// * @param str
	// * @return true if matched
	// */
	// public static boolean isISBN(String str) {
	// return isISBN(str, ISBNVersion.isbn10) || isISBN(str, ISBNVersion.isbn13);
	// }

	// public static boolean isISBN(String str, ISBNVersion version) {
	// String sanitized = str.replaceAll("[\\s-]+", "");
	// int checksum = 0, i;
	// if (ISBNVersion.isbn10.equals(version)) {
	// if (!ISBN10_MAYBE.matcher(sanitized).matches()) {
	// return false;
	// }
	// for (i = 0; i < 9; i++) {
	// checksum += (i + 1) * sanitized.charAt(i);
	// }
	// if (sanitized.charAt(9) == 'X') {
	// checksum += 10 * 10;
	// } else {
	// checksum += 10 * sanitized.charAt(9);
	// }
	// if ((checksum % 11) == 0) {
	// return !isBlank(sanitized);
	// }
	// } else if (ISBNVersion.isbn13.equals(version)) {
	// if (!ISBN13_MAYBE.matcher(sanitized).matches()) {
	// return false;
	// }
	// int[] factor = new int[] { 1, 3 };
	// for (i = 0; i < 12; i++) {
	// checksum += factor[i % 2] * sanitized.charAt(i);
	// }
	// if (sanitized.charAt(12) - ((10 - (checksum % 10)) % 10) == 0) {
	// return true;
	// }
	// }
	// return false;
	// }

	/**
	 * 
	 * @param str
	 *            mobile phone string
	 * @param locale
	 *            phone locale
	 * @return true if matched
	 */
	public static boolean isMobilePhone(String str, PhoneLocale locale) {
		if(isBlank(str)) return false;
		return PHONES_REGS.get(locale).matcher(str).matches();
	}

	/**
	 * check if the string contains one or more multibyte chars.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isMultibyte(String str) {
		if(null == str) return false;
		return MULTIBYTE.matcher(str).matches();
	}

	/**
	 * check if the string contains ASCII chars only.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isAscii(String str) {
		if(null == str) return false;
		return ASCII.matcher(str).matches();
	}

	/**
	 * check if the string contains any full-width chars.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isFullWidth(String str) {
		if(null == str) return false;
		return FULL_WIDTH.matcher(str).matches();
	}

	/**
	 * check if the string contains any half-width chars.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isHalfWidth(String str) {
		if(null == str) return false;
		return HALF_WIDTH.matcher(str).matches();
	}

	/**
	 * check if the string contains a mixture of full and half-width chars.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isVariableWidth(String str) {
		if(null == str) return false;
		return isFullWidth(str) && isHalfWidth(str);
	}

	/**
	 * check if the string contains any surrogate pairs chars.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isSurrogatePair(String str) {
		if(null == str) return false;
		return SURROGATE_PAIR.matcher(str).matches();
	}

	/**
	 * check if the string is a valid hex-encoded representation of a MongoDB ObjectId.
	 * 
	 * @param str
	 *            a string
	 * @return true if matched
	 */
	public static boolean isMongoId(String str) {
		if(null == str) return false;
		return isHexadecimal(str) && 24 == str.length();
	}

	/**
	 * check the |num - value| &lt;= d
	 * 
	 * @param num
	 *            a number
	 * @param value
	 *            another number
	 * @param d
	 *            distance
	 * @return true if |num - value| &lt;= d
	 */
	public static boolean diff(String num, double value, String d) {
		if(null == num) return false;
		BigDecimal n1 = new BigDecimal(num);
		BigDecimal n2 = new BigDecimal(value);
		BigDecimal n3 = new BigDecimal(d).abs();
		return n1.subtract(n2).abs().compareTo(n3) < 0;
	}

	/**
	 * check the |num - value| &lt;= d
	 * 
	 * @param num
	 *            a number
	 * @param value
	 *            another number
	 * @param d
	 *            distance
	 * @return true if |num - value| &lt;= d
	 */
	public static boolean diff(String num, String value, String d) {
		if(null == num) return false;
		BigDecimal n1 = new BigDecimal(num);
		BigDecimal n2 = new BigDecimal(value);
		BigDecimal n3 = new BigDecimal(d).abs();
		return n1.subtract(n2).abs().compareTo(n3) <= 0;
	}

	/**
	 * check the |num - value| &lt;= d
	 * 
	 * @param num
	 *            a number
	 * @param value
	 *            another number
	 * @param d
	 *            distance
	 * @return true if |num - value| &lt;= d
	 */
	public static boolean diff(String num, double value, double d) {
		if(null == num) return false;
		BigDecimal n1 = new BigDecimal(num);
		BigDecimal n2 = new BigDecimal(value);
		BigDecimal n3 = new BigDecimal(d).abs();
		return n1.subtract(n2).abs().compareTo(n3) < 0;
	}

	/**
	 * Sanitizers
	 */

	/**
	 * parse data with specified format
	 * 
	 * @param str
	 *            data string
	 * @param format
	 *            date format
	 * @return str's date
	 * @throws ParseException
	 *             bad date string or format
	 */
	public static Date parseDate(String str, String format) throws ParseException {
		if(null == str) return null;
		return new SimpleDateFormat(format).parse(str);
	}

	/**
	 * format a date to string date string
	 * 
	 * @param date
	 *            a date
	 * @param format
	 *            a date format
	 * @return the string of the date
	 * @throws ParseException
	 *             bad date format
	 */
	public static String formatDate(Date date, String format) throws ParseException {
		return new SimpleDateFormat(format).format(date);
	}

	/**
	 * convert number string to int
	 * 
	 * @param str
	 *            integer string
	 * @return Integer
	 */
	public static Integer toInt(String str) {
		if(null == str) return null;
		return Integer.valueOf(str);
	}

	/**
	 * convert number string to int in specified radix
	 * 
	 * @param str
	 *            number string
	 * @param radix
	 *            the radix of the number string
	 * @return Integer
	 */
	public static Integer toInt(String str, int radix) {
		if(null == str) return null;
		return Integer.valueOf(str, radix);
	}

	/**
	 * convert number string to float
	 * 
	 * @param str
	 *            a float string
	 * @return float
	 */
	public static Float toFloat(String str) {
		if(null == str) return null;
		return Float.valueOf(str);
	}

	/**
	 * convert number string to double
	 * 
	 * @param str
	 *            a double string
	 * @return Double
	 */
	public static Double toDouble(String str) {
		if(null == str) return null;
		return Double.valueOf(str);
	}

	/**
	 * convert true string to boolean
	 * 
	 * @param str
	 *            a string
	 * @return true if "true" equals str(ignore case) or "1" equals str
	 */
	public static Boolean toBoolean(String str) {
		if(null == str) return null;
		if ("true".equalsIgnoreCase(str) || "1".equals(str)) {
			return true;
		}
		return false;
	}

	/**
	 * trim whitespaces from both sides of the input.
	 * 
	 * @param str
	 *            a string
	 * @return trimed string
	 */
	public static String trim(String str) {
		if(null == str) return null;
		return str.trim();
	}

	/**
	 * trim characters from both sides of the input.
	 * 
	 * @param str
	 *            a string
	 * @param chars
	 *            trim part
	 * @return trimed string
	 */
	public static String trim(String str, String chars) {
		if(null == str) return null;
		return rtrim(ltrim(str, chars), chars);
	}

	/**
	 * trim whitespaces from the left-side of the input.
	 * 
	 * @param str
	 *            a string
	 * @return trimed string
	 */
	public static String ltrim(String str) {
		if(null == str) return null;
		return str.replaceFirst("\\s+", "");
	}

	/**
	 * trim characters from the left-side of the input.
	 * 
	 * @param str
	 *            a string
	 * @param chars
	 *            trim part
	 * @return trimed string
	 */
	public static String ltrim(String str, String chars) {
		if(null == str) return null;
		if (0 == str.indexOf(chars)) {
			return str.substring(chars.length());
		}
		return str;
	}

	/**
	 * trim whitespaces from the right-side of the input.
	 * 
	 * @param str
	 *            a string
	 * @return trimed string
	 */
	public static String rtrim(String str) {
		if(null == str) return null;
		return str.replaceAll("\\s+$", "");
	}

	/**
	 * trim characters from the right-side of the input.
	 * 
	 * @param str
	 *            a string
	 * @param chars
	 *            trim part
	 * @return the trimed string
	 */
	public static String rtrim(String str, String chars) {
		if(null == str) return null;
		int i = str.lastIndexOf(chars);
		if (i == str.length() - chars.length()) {
			return str.substring(0, i);
		}
		return str;
	}

	/**
	 * replace &lt;, &gt;, &amp;, ', " and / with HTML entities.
	 * 
	 * @param str
	 *            a string
	 * @return the escpaed string
	 */
	public static String escape(String str) {
		if(null == str) return null;
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

	/**
	 * remove characters with a numerical value &lt; 32 and 127, mostly control characters
	 * 
	 * @param str
	 *            a string
	 * @return the striped string
	 */
	public static String stripLow(String str) {
		if(null == str) return null;
		return stripLow(str, false);
	}

	/**
	 * remove characters with a numerical value &lt; 32 and 127, mostly control characters. If keepNewLines is true,
	 * newline characters are preserved (\n and \r, hex 0xA and 0xD)
	 * 
	 * @param str
	 *            a string
	 * @param keepNewLines
	 *            If keepNewLines is true, newline characters are preserved (\n and \r, hex 0xA and 0xD)
	 * @return the striped string
	 */
	public static String stripLow(String str, boolean keepNewLines) {
		if(null == str) return null;
		String chars = keepNewLines ? "\\x00-\\x09\\x0B\\x0C\\x0E-\\x1F\\x7F" : "\\x00-\\x1F\\x7F";
		return blacklist(str, chars);
	}

	/**
	 * remove characters that do not appear in the whitelist. The characters are used in a RegExp and so you will need
	 * to escape some chars, e.g. whitelist(input, '\[\]').
	 * 
	 * @param str
	 *            a string
	 * @param chars
	 *            The characters are used in a RegExp
	 * @return a filtered string
	 */
	public static String whitelist(String str, String chars) {
		if(null == str) return null;
		return str.replaceAll("[^" + chars + "]+", "");
	}

	/**
	 * 
	 * remove characters that appear in the blacklist. The characters are used in a RegExp and so you will need to
	 * escape some chars, e.g. blacklist(input, '\[\]').
	 * 
	 * @param str
	 *            a string
	 * @param chars
	 *            The characters are used in a RegExp
	 * @return a filtered string
	 */
	public static String blacklist(String str, String chars) {
		if(null == str) return null;
		return str.replaceAll("[" + chars + "]+", "");
	}

	/**
	 * used for MessageDigest
	 * 
	 * @param bs
	 * @return
	 */
	static String toHexString(byte[] bs) {
		if(null == bs) return null;
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

	/**
	 * md5 a string
	 * 
	 * @param str
	 *            a string
	 * @return the hexadecimal string of the md5 result
	 */
	public static String md5(String str) {
		if(null == str) return null;
		try {
			return sig("MD5", str);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * sha1 a string
	 * 
	 * @param str
	 *            a string
	 * @return the hexadecimal string of the sha1 result
	 */
	public static String sha1(String str) {
		if(null == str) return null;
		try {
			return sig("SHA1", str);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * md5 a InputStream,stream not closed
	 * 
	 * @param in
	 *            a inputstream
	 * @return the hexadecimal string of the md5 result
	 * @throws IOException
	 *             bad InputStream
	 */
	public static String md5(InputStream in) throws IOException {
		if(null == in) return null;
		try {
			return sig("MD5", in);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * sha1 a InputStream,stream not closed
	 * 
	 * @param in
	 *            a InputStream
	 * @return the hexadecimal string of the sha1 result
	 * @throws IOException
	 *             bad InputStream
	 */
	public static String sha1(InputStream in) throws IOException {
		if(null == in) return null;
		try {
			return sig("SHA1", in);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * generate a signature for the string with specified algorithm.
	 * 
	 * @param alg
	 *            a supported algorithm , such as 'md5','sha1'
	 * @param str
	 *            a string
	 * @return the hexadecimal string of the encrypted result
	 * @throws NoSuchAlgorithmException
	 *             if algorithm not to be supported
	 */
	public static String sig(String alg, String str) throws NoSuchAlgorithmException {
		if(null == str) return null;
		MessageDigest digest = MessageDigest.getInstance(alg);
		digest.update(str.getBytes());
		return toHexString(digest.digest());
	}

	/**
	 * generate a signature for the InputStream with specified algorithm.
	 * 
	 * @param alg
	 *            a supported algorithm , such as 'md5','sha1'
	 * @param in
	 *            a InputStream
	 * @return the hexadecimal string of the encrypted result
	 * @throws NoSuchAlgorithmException
	 *             if algorithm not to be supported
	 * @throws IOException
	 *             bad InputStream
	 */
	public static String sig(String alg, InputStream in) throws NoSuchAlgorithmException, IOException {
		if(null == in) return null;
		MessageDigest digest = MessageDigest.getInstance(alg);
		byte[] buffer = new byte[1024];
		int len;
		while (-1 != (len = in.read(buffer))) {
			digest.update(buffer, 0, len);
		}
		return toHexString(digest.digest());
	}

	/**
	 * encode a string to base64 string
	 * 
	 * @param str
	 *            a string
	 * @return base64 encoded string
	 */
	public static String encodeBase64(String str) {
		if(null == str) return null;
		return encodeBase64(str.getBytes());
	}

	/**
	 * encode a byte array to base64 string
	 * 
	 * @param bs
	 *            a byte array
	 * @return base64 encoded string
	 */
	public static String encodeBase64(byte[] bs) {
		if(null == bs) return null;
		return new BASE64Encoder().encode(bs);
	}

	/**
	 * encode a ByteBuffer to base64 string
	 * 
	 * @param bs
	 *            a ByteBuffer
	 * @return base64 encoded string
	 */
	public static String encodeBase64(ByteBuffer bs) {
		if(null == bs) return null;
		return new BASE64Encoder().encode(bs);
	}

	/**
	 * encode a InputStream to base64 string , InputStream not close.
	 * 
	 * @param in
	 *            a InputStream
	 * @return base64 encoded string
	 * @throws IOException
	 *             bad InputStream
	 */
	public static String encodeBase64(InputStream in) throws IOException {
		if(null == in) return null;
		BASE64Encoder encoder = new BASE64Encoder();
		OutputStream out = new ByteArrayOutputStream();
		encoder.encode(in, out);
		return out.toString();
	}

	/**
	 * decode a base64 encoded string
	 * 
	 * @param str
	 *            a base64 encoded string
	 * @return a decoded bytes
	 * @throws IOException
	 *             bad base64 encoded string
	 */
	public static byte[] decodeBase64(String str) throws IOException {
		if(null == str) return null;
		return new BASE64Decoder().decodeBuffer(str);
	}

	/**
	 * decode a base64 encoded string to string
	 * 
	 * @param str
	 *            a base64 encoded string
	 * @return a decoded string
	 * @throws IOException
	 *             bad base64 encoded string
	 */
	public static String decodeBase64AsString(String str) throws IOException {
		if(null == str) return null;
		return new String(decodeBase64(str));
	}

}
