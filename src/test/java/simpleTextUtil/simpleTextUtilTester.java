package simpleTextUtil;

import org.deking.utils.simpleTextUtil;
import org.deking.utils.simpleTextUtil.FormatStringEnum;

public class simpleTextUtilTester {
public static void main(String[] args) {
//	System.out.println(simpleTextUtil.getOriginFromUrl("https://www.acfun.cn/login/forgot"));
	System.out.println(simpleTextUtil.formatString(FormatStringEnum.MESSAGE_FORMATTER,  "email&key={}&{}captcha=", "123", "456" )); 
}
}
