package com.itv.digest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;

import com.itv.cas.InvalidDigestException;

/**
 * @author gerolf
 * 
 */
public class LocalDigestValidator {
	
	private final Logger logger = Logger.getLogger(LocalDigestValidator.class);

	// default values
	private static final String ENCODING = "iso-8859-1";
	private static final String HASH_FUNCTION = "SHA-256";
	private static final String SHARED_SECRET_INCOMING = "@##HRewhvbxcv98q24#*%Y^WEfyi6yZXvcsEIW7RTYQET";
	private static final String SHARED_SECRET_RESPONSE = "@##HRewhvbxcv98q24#*%Y^WEfyi6yZXvcsEIW7RTYQET";
	
	private DigestValidatorProperties props;
	
	public LocalDigestValidator() {
		// load parameters from property file
		props = new DigestValidatorProperties();
	}
	
	public LocalDigestValidator(String shared_secret) {
		props = new DigestValidatorProperties();
		props.getParameters().put("shared_secret_incoming", shared_secret);
		props.getParameters().put("shared_secret_response", shared_secret);
		props.getParameters().put("encoding", ENCODING);
		props.getParameters().put("hashfunction", HASH_FUNCTION);
	}
	
	public LocalDigestValidator(String shared_secret_incoming, String shared_secret_response) {
		props = new DigestValidatorProperties();
		props.getParameters().put("shared_secret_incoming", shared_secret_incoming);
		props.getParameters().put("shared_secret_response", shared_secret_response);
		props.getParameters().put("encoding", ENCODING);
		props.getParameters().put("hashfunction", HASH_FUNCTION);
	}
	
	public LocalDigestValidator(String encoding, String hash_function, String shared_secret_incoming, String shared_secret_response) {
		props = new DigestValidatorProperties();
		props.getParameters().put("shared_secret_incoming", shared_secret_incoming);
		props.getParameters().put("shared_secret_response", shared_secret_response);
		props.getParameters().put("encoding", encoding);
		props.getParameters().put("hashfunction", hash_function);
	}

	/**
	 * This method computes the incoming digest per the following formula:
	 * SHA-256(shared_secret_request + ticket) and compares this to the given
	 * digest If they match, the returned value is another digest per the
	 * formula: SHA-256(shared_secret_response + ticket + userId) If the
	 * incoming digest does not match the calculated one, an
	 * @Link{InvalidDigestException} is thrown
	 * 
	 * @param digest
	 * @param ticket
	 * @param serviceUrl
	 * @param userId
	 * @return response digest
	 * @throws InvalidDigestException
	 */
	public String validateDigest(String digest, String ticket, String serviceUrl, String userId) throws InvalidDigestException {
		// compute the digest
		try {
			String computedDigest = SHA(props.getParameters().getProperty("shared_secret_incoming") + ticket,props.getParameters().getProperty("encoding"),props.getParameters().getProperty("hashfunction"));
			if (computedDigest.equals(digest)) {
				// incoming digest checks out
				// compute and return the response digest
				return SHA(props.getParameters().getProperty("shared_secret_response")+ticket+userId,props.getParameters().getProperty("encoding"),props.getParameters().getProperty("hashfunction"));
			}
			else {
				logger.warn("specified digest "+digest+" from "+serviceUrl+" is invalid. Ticket="+ticket+", userId="+userId);
				throw new InvalidDigestException();
			}
		} catch (NoSuchAlgorithmException e) {
			logger.error("Specified hash algorithm "+props.getParameters().getProperty("hashfunction")+" not recognized. " +
					"Please use widely recognized hash functions supported by the java cryptogtaphy extensions, such as MD5, SHA-1 or SHA-256.",e);
			throw new InvalidDigestException();
		} catch (UnsupportedEncodingException e) {
			logger.error("Specified character encoding "+props.getParameters().getProperty("encoding")+" not recognized. Please use iso-8859-1, UTF-8 or such.",e);
			throw new InvalidDigestException();
		}
	}
	

	/**
	 * private hash function
	 * 
	 * @param text
	 * @param encoding
	 * @param hashfunction
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
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
