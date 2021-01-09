package org.deking.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.translate.UnicodeUnescaper;

import com.feilong.core.lang.StringUtil;
import com.feilong.core.text.MessageFormatUtil;
import com.feilong.tools.slf4j.Slf4jUtil;

@SuppressWarnings("deprecation")
public class simpleTextUtil {
	/**
	 * @Title: formatString
	 * @Description: 格式化函數
	 * @return String
	 * @param formatType
	 * @param stringBody
	 * @param args
	 * @return
	 * @date 2020年2月7日 下午6:00:24
	 */
	@SuppressWarnings("unchecked")
	public static final String formatString(int formatType, String stringBody, Object... args) {
		switch (formatType) {
		case 1:
			return stringBody + (args.length == 1 ? args[0] : StringUtils.join(args));
		case 2:
			return String.format(stringBody, args);
		case 3:
			StringBuilder sb = new StringBuilder(stringBody);
			for (Object s : args) {
				sb.append(s);
			}
			return sb.toString();
		case 4:
			StringBuffer sf = new StringBuffer(stringBody);
			for (Object s : args) {
				sf.append(s);
			}
			return sf.toString();
		case 5:
			return Slf4jUtil.format(stringBody, args);
		case 6:
			return MessageFormatUtil.format(stringBody, args);
		case 7:
			return StringUtil.replace(stringBody, (HashMap<String, String>) args[0]);// ${account}
		case 8:
			return StringUtil.format(stringBody, args);
//		case 9:
//			 velocityUtil
//             .parseString(stringBody, new HashMap<String, String>() {
//				{
//					put("account", args.toString());
//				}
//			});
		default:
			return stringBody;
		}
	}

	public static final String textMatcher(String response, Object patternObject, int... groupIndex)
			throws java.lang.IllegalStateException {
		Matcher m = patternObject instanceof String ? Pattern.compile(patternObject.toString()).matcher(response)
				: ((Pattern) patternObject).matcher(response);
		m.find();
		if (groupIndex.length != 0) {
			return m.group(groupIndex[0]);
		}
		return m.group(0);
	}

	public static final boolean contain(String response, Object succesStr) {

		return succesStr instanceof String ? response.contains((String) succesStr)
				: ((Pattern) succesStr).matcher(response).find();

	}

	public static final boolean isUnicode(String text) {
		return text.startsWith("\\u");
	}

	public static final String unicodeToChinese(String text, boolean... isValidate) {
		if (isValidate.length != 0) {
			if (isValidate[0] && isUnicode(text)) {
				return new UnicodeUnescaper().translate(text);
			}
			return text;
		}
		return new UnicodeUnescaper().translate(text);

	}

	public static final boolean isBase64(String str) {

		return contain(str, "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
				|| str.startsWith("data:image/") || str.startsWith("/") || str.endsWith("=");

	}

	public static final String getOriginFromUrl(String url) {
		return textMatcher(url, "http(s)?://.+?(?=/)");
	}

	public static final String getHostFromUrl(String url) {
		return textMatcher(url, "(?<=//|)((\\w)+\\.)+\\w+(:\\d*)?");
	}

	public static final String getMainHostFromUrl(String url) {
		return textMatcher(url, "(?<=\\.)+(\\w)+\\.+\\w+");
	}

	public static final String decodeURIComponent(String s) {

		try {
			return s == null ? null : URLDecoder.decode(s, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			return s;
		}
	}

	/**
	 * Encodes the passed String as UTF-8 using an algorithm that's compatible with
	 * JavaScript's <code>encodeURIComponent</code> function. Returns
	 * <code>null</code> if the String is <code>null</code>.
	 * 
	 * @param s The String to be encoded
	 * @return the encoded String
	 */
	public static final String encodeURIComponent(String s) {
		try {
			return URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20").replaceAll("\\%21", "!")
					.replaceAll("\\%27", "'").replaceAll("\\%28", "(").replaceAll("\\%29", ")").replaceAll("\\%7E", "~")
					.replaceAll("%3D", "=");
		}
		// This exception should never occur.
		catch (UnsupportedEncodingException e) {
			return s;
		}
	}

	public static final String btoa(String s) {
		return new String(Base64.getEncoder().encode(s.getBytes()));
	}

	public static final String atob(String encoded) {
		return new String(Base64.getDecoder().decode(encoded));
	}

	public static final String escape(String src) {
		int i;
		char j;
		StringBuffer tmp = new StringBuffer();
		tmp.ensureCapacity(src.length() * 6);
		for (i = 0; i < src.length(); i++) {
			j = src.charAt(i);
			if (Character.isDigit(j) || Character.isLowerCase(j) || Character.isUpperCase(j))
				tmp.append(j);
			else if (j < 256) {
				tmp.append("%");
				if (j < 16)
					tmp.append("0");
				tmp.append(Integer.toString(j, 16));
			} else {
				tmp.append("%u").append(Integer.toString(j, 16));
			}
		}
		return tmp.toString();
	}

	public static final String unescape(String src) {
		StringBuffer tmp = new StringBuffer();
		tmp.ensureCapacity(src.length());
		int lastPos = 0, pos = 0;
		char ch;
		while (lastPos < src.length()) {
			pos = src.indexOf("%", lastPos);
			if (pos == lastPos) {
				if (src.charAt(pos + 1) == 'u') {
					ch = (char) Integer.parseInt(src.substring(pos + 2, pos + 6), 16);
					tmp.append(ch);
					lastPos = pos + 6;
				} else {
					ch = (char) Integer.parseInt(src.substring(pos + 1, pos + 3), 16);
					tmp.append(ch);
					lastPos = pos + 3;
				}
			} else {
				if (pos == -1) {
					tmp.append(src.substring(lastPos));
					lastPos = src.length();
				} else {
					tmp.append(src.substring(lastPos, pos));
					lastPos = pos;
				}
			}
		}
		return tmp.toString();
	}

	public static final String RSAPublicDecrypt(String data, String publicKey) {
		// base64编码的公钥
		byte[] decoded = Base64.getDecoder().decode(publicKey);
		RSAPublicKey pubKey;
		try {
			pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes("UTF-8")));
		} catch (InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("加密失败！");
		}

	}

	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	public static final String getDate(String... args) {

		return args.length == 0 ? dateFormat.format(new Date()).toString()
				: new SimpleDateFormat(args[0]).format(new Date()).toString();

	}

	public static final Date parseDate(String time) {
		try {
			return dateFormat.parse(time);
		} catch (ParseException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static final String dateToString(Date date, String... args) {
		return args.length == 0 ? dateFormat.format(date).toString()
				: new SimpleDateFormat(args[0]).format(date).toString();

	}

	public static final String getClassName(Object o) {
		String s = o.getClass().getName();
		return s.substring(s.lastIndexOf(".") + 1, s.length());
	}

	public static final String MD5Encrypt(String s) {
		char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		try {
			MessageDigest mdInst = MessageDigest.getInstance("MD5");
			mdInst.update(s.getBytes());
			byte[] md = mdInst.digest();
			int j = md.length;
			char str[] = new char[j * 2];
			for (int i = 0, k = 0; i < j; i++) {
				byte byte0 = md[i];
				str[k++] = hexDigits[byte0 >>> 4 & 0xf];
				str[k++] = hexDigits[byte0 & 0xf];
			}
			return new String(str);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static final boolean checkMobile(String mobile) {
		return contain(mobile, Pattern.compile("^1[3456789]\\d{9}$"));
	}

	public static final boolean checkEmail(String email) {
		return contain(email, Pattern
				.compile("^([a-z0-9A-Z]+[-|_|\\.]?)+[a-z0-9A-Z]@([a-z0-9A-Z]+(-[a-z0-9A-Z]+)?\\.)+[a-zA-Z]{2,}$"));

	}
}
