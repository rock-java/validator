package com.rockson.validator;

import org.junit.Assert;
import org.junit.Test;

public class ValidatorTest {

	@Test
	public void isUrlTrue() {
		Assert.assertTrue(Validator.isURL("http://www.google.com"));
		Assert.assertTrue(Validator.isURL("https://www.google.com"));
		Assert.assertTrue(Validator.isURL("ftp://www.google.com"));
		Assert.assertTrue(Validator.isURL("www.google.com"));
		Assert.assertTrue(Validator.isURL("google.com"));
		Assert.assertTrue(Validator.isURL("google"));
		Assert.assertTrue(Validator.isURL("http://jim:tom@www.google.com:80/search/gg?q=hello#123"));
	}

	@Test
	public void isUrlTestFailed() {
		Assert.assertFalse(Validator.isURL(null));
		Assert.assertFalse(Validator.isURL(""));
		Assert.assertFalse(Validator.isURL("htp://www.google.com"));
		Assert.assertFalse(Validator.isURL("htp://www.google.com#123?ere"));
	}

	@Test
	public void isFQDNTrue() {
		Assert.assertTrue(Validator.isFQDN("www.google.com"));
		Assert.assertTrue(Validator.isFQDN("google.com"));
		Assert.assertTrue(Validator.isFQDN("google"));
	}
	
	@Test
	public void isEmailTrue(){
		Assert.assertTrue(Validator.isEmail("rocksonzeta@gmail.com"));
		Assert.assertTrue(Validator.isEmail("rocksonzeta@gmail.com.cn"));
		Assert.assertTrue(Validator.isEmail("rocksonzeta@163.com"));
		Assert.assertTrue(Validator.isEmail("rocksonzeta@163"));
	}
	@Test
	public void isEmailFalse(){
		Assert.assertFalse(Validator.isEmail("xx"));
		Assert.assertFalse(Validator.isEmail("@gmail.com"));
		Assert.assertFalse(Validator.isEmail("xx x@gmail.com"));
		Assert.assertFalse(Validator.isEmail("xx@.com"));
	}
	@Test
	public void isCreditCardTrue(){
		Assert.assertTrue(Validator.isCreditCard("6225880170957022"));
	}
	@Test
	public void isISBNTrue(){
		Assert.assertTrue(Validator.isISBN("9787040396638"));
	}
}
