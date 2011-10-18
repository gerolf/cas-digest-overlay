package com.itv.cas.digest;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.itv.cas.InvalidDigestException;
import com.itv.digest.LocalDigestValidator;

public class LocalDigestValidatorTest {

	private String SHARED_SECRET = "@##HRewhvbxcv98q24#*%Y^WEfyi6yZXvcsEIW7RTYQET";
	private String OTHER_SHARED_SECRET = "64641HRsafasdfasfsdfewhvbxcv98q24#*%YWEfyis460ubobe98yRTYQET";

	private static final String TICKET = "ST-TH17535-gd";
	private static final String SERVICE_URL = "http://paywizard.itv.com";
	private static final String USERID = "3";

	private static final String HASHFUNCTION = "SHA-256";
	private static final String ENCODING = "iso-8859-1";

	// test default values good path
	@Test
	public void testDigestCorrect() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(SHARED_SECRET + TICKET + USERID, ENCODING, HASHFUNCTION);
		assertEquals(expected, responseDigest);
	}
		
	// test good path other secret
	@Test
	public void testDigestCorrectWithOtherSecret() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(OTHER_SHARED_SECRET);
		String digest = SHA(OTHER_SHARED_SECRET + TICKET, ENCODING, HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(OTHER_SHARED_SECRET + TICKET + USERID, ENCODING, HASHFUNCTION);
		assertEquals(expected, responseDigest);
	}

	// test different request/response secrets
	@Test
	public void testDigestCorrectWithDifferentSecrets() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(SHARED_SECRET, OTHER_SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(OTHER_SHARED_SECRET + TICKET + USERID, ENCODING, HASHFUNCTION);
		assertEquals(expected, responseDigest);
	}

	// test default values with bad shared secret
	@Test(expected=InvalidDigestException.class)
	public void testDigestFailsWithBadSecret() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(OTHER_SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
	}

	// test SHA-1
	@Test
	public void testDigestCorrectWithSHA1() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(ENCODING, "SHA-1", SHARED_SECRET, SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, "SHA-1");
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(SHARED_SECRET + TICKET + USERID, ENCODING, "SHA-1");
		assertEquals(expected, responseDigest);
	}

	// test MD5
	@Test
	public void testDigestCorrectWithMD5() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(ENCODING, "MD5", SHARED_SECRET, SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, "MD5");
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(SHARED_SECRET + TICKET + USERID, ENCODING, "MD5");
		assertEquals(expected, responseDigest);
	}

	// test UTF8
	@Test
	public void testDigestCorrectWithUTF8() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator("UTF-8", HASHFUNCTION, SHARED_SECRET, SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, "UTF-8", HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
		String expected = SHA(SHARED_SECRET + TICKET + USERID, "UTF-8", HASHFUNCTION);
		assertEquals(expected, responseDigest);
	}

	// test faulty algorithm
	@Test(expected=InvalidDigestException.class)
	public void testFaultyHashFunction() throws InvalidDigestException, NoSuchAlgorithmException, UnsupportedEncodingException {
		LocalDigestValidator ldv = new LocalDigestValidator(ENCODING, "faultyHasher", SHARED_SECRET, SHARED_SECRET);
		String digest = SHA(SHARED_SECRET + TICKET, ENCODING, HASHFUNCTION);
		String responseDigest = ldv.validateDigest(digest, TICKET, SERVICE_URL, USERID);
	}

	// private helpers
	private static String SHA(String text, String encoding, String hashfunction) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md;
		md = MessageDigest.getInstance(hashfunction);
		md.update(text.getBytes(encoding), 0, text.length());
		byte[] shahash = md.digest();
		return toHex(shahash);
	}

	private static String toHex(byte[] data) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			sb.append(Integer.toString((data[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
}
