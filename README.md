# validator
validator for Java , inspired by chriso's [validator.js](https://github.com/chriso/validator.js)


```java
import com.rockson.validator.Validator;
import org.junit.Assert;
import org.junit.Test;

public void test(){
	Assert.assertTrue(Validator.isURL("http://www.google.com"));
	Assert.assertTrue(Validator.isEmail("xxx@gmail.com"));
	Assert.assertTrue(Validator.isFQDN("www.google.com"));
	Assert.assertTrue(Validator.md5("www.google.com"));
	
	Assert.assertTrue("5d41402abc4b2a76b9719d911017c592".equals(Validator.md5("hello")));
}

```