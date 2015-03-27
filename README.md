# validator
[![Build Status](https://travis-ci.org/rock-java/validator.svg)](https://travis-ci.org/rock-java/validator)
[![Coverage Status](https://coveralls.io/repos/rock-java/validator/badge.svg?branch=master)](https://coveralls.io/r/rock-java/validator?branch=master)

validator for Java , inspired by chriso's [validator.js](https://github.com/chriso/validator.js)


## Examples
```java
import com.rockson.validator.Validator;

public void test(){
	Validator.isURL("http://www.google.com")); //should to be true
	Validator.isEmail("xxx@gmail.com"));	//should to be true
	Validator.isFQDN("www.google.com"));	//should to be true
	Validator.md5("hello"));				//should to be 5d41402abc4b2a76b9719d911017c592
}

```

##License (MIT)