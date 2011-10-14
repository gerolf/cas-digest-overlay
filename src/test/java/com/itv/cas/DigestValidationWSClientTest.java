package com.itv.cas;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DigestValidationWSClientTest {

	static final String USER = "admin";
	
	private DigestValidationWSClient client = new DigestValidationWSClient("http://107.20.87.153:8080/DigestValidatorMock/validateDigest");

	@Test(expected = InvalidDigestException.class)
	public void serviceReturnsError() throws Exception {
		client.validateDigest("BAD_DIGEST", "ST_something", "myserviceurl", USER);
	}

	@Test
	public void serviceReturnsDigest() throws Exception {
		String result = client.validateDigest("DIGEST_CHALLENGE_FROM_PAYWIZARDSIM", "ST_something", "myserviceurl", USER);
		assertEquals("HASH_FROM_DIGESTVALIDATOR_MOCK", result);
	}

}
