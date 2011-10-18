package com.itv.cas.digest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.itv.digest.DigestValidatorProperties;
import com.itv.digest.LocalDigestValidator;

public class MostSpecificSecretTest {

	private LocalDigestValidator validator;
	private DigestValidatorProperties props;
	
	@Before
	public void setUp() {
		props = new DigestValidatorProperties();
		props.getParameters().setProperty("shared_secret","shared_secret");
		props.getParameters().setProperty("shared_secret_incoming","shared_secret_incoming");
		props.getParameters().setProperty("shared_secret_response.paywizard.com","shared_secret_response.paywizard.com");
		props.getParameters().setProperty("shared_secret.http://paywizard.com","shared_secret.http://paywizard.com");
		validator = new LocalDigestValidator();
		validator.setProps(props);
	}
	
	@Test
	public void testSpecificIncoming() {
		String secret = validator.getMostSpecificSecret("http://paywizard.com", "incoming");
		Assert.assertEquals("shared_secret.http://paywizard.com",secret);
	}
	
	@Test
	public void testGeneralIncoming() {
		String secret = validator.getMostSpecificSecret("notknown", "incoming");
		Assert.assertEquals("shared_secret_incoming",secret);
	}
	
	@Test
	public void testGeneralResponse() {
		String secret = validator.getMostSpecificSecret("notknown", "response");
		Assert.assertEquals("shared_secret",secret);
	}
	
	@Test
	public void testSpecificResponse() {
		String secret = validator.getMostSpecificSecret("paywizard.com", "response");
		Assert.assertEquals("shared_secret_response.paywizard.com",secret);
	}
}
