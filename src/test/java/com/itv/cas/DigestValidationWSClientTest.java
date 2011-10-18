package com.itv.cas;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.junit.Before;
import org.junit.Test;

import com.itv.digest.LocalDigestValidator;

public class DigestValidationWSClientTest {

	static final String USER = "admin";
	static final String TICKET = "ST_something";
	
	private static final String SHARED_SECRET="secret";
	private static final String ENCODING = "iso-8859-1";
	private static final String HASH_FUNCTION = "SHA-256";
	
	private String successResponse = "" +
			"<result>" +
				"<digest>" +
				"${digest}" +
				"</digest>" +
				"<error> " +
				"	<error_code></error_code> " +
				"	<error_msg></error_msg> "+
				"</error>" +
			"</result>";
	private String failResponse = "" +
			"<result>" +
			"<digest>" +
			"</digest>" +
			"<error> " +
			"	<error_code>INVALID_DIGEST</error_code> " +
			"	<error_msg>Digest provided is invalid, contact administrator</error_msg> "+
			"</error>" +
		"</result>";
	
	private DigestValidationWSClient client = new DigestValidationWSClient("http://107.20.87.153:8080/DigestValidatorMock/validateDigest");
	
	@Before
	public void setUp() {
		client.setHttpClient(new HttpClientMock());
	}

	@Test(expected = InvalidDigestException.class)
	public void serviceReturnsError() throws Exception {
		client.validateDigest("BAD_DIGEST", TICKET, "myserviceurl", USER);
	}

	@Test
	public void serviceReturnsDigest() throws Exception {
		String digest = LocalDigestValidator.SHA(SHARED_SECRET+TICKET, ENCODING, HASH_FUNCTION);
		String result = client.validateDigest(digest, TICKET, "myserviceurl", USER);
		String responsedigest = LocalDigestValidator.SHA(SHARED_SECRET+TICKET+USER, ENCODING, HASH_FUNCTION);
		assertEquals(responsedigest, result);
	}
	
	private class HttpClientMock implements HttpClient {

		public HttpResponse execute(HttpUriRequest req) throws IOException, ClientProtocolException {
			String digest = req.getLastHeader("Digest").getValue();
			String ticket = TICKET;
			String userId = USER;
			HttpResponse response = new DefaultHttpResponseFactory().newHttpResponse(new ProtocolVersion("1.1",1,1), 200, null);
			// validate the ticket
			try {
				String checkdigest = LocalDigestValidator.SHA(SHARED_SECRET+ticket, ENCODING, HASH_FUNCTION);
				if (checkdigest.equals(digest)) {
					String responsedigest = LocalDigestValidator.SHA(SHARED_SECRET+ticket+userId, ENCODING, HASH_FUNCTION);
					response.setEntity(new StringEntity(successResponse.replace("${digest}",responsedigest)));
				}
				else {
					// return error
					response.setEntity(new StringEntity(failResponse));
				}
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return response;
		}

		public HttpResponse execute(HttpUriRequest arg0, HttpContext arg1) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public HttpResponse execute(HttpHost arg0, HttpRequest arg1) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public <T> T execute(HttpUriRequest arg0, ResponseHandler<? extends T> arg1) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public HttpResponse execute(HttpHost arg0, HttpRequest arg1, HttpContext arg2) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public <T> T execute(HttpUriRequest arg0, ResponseHandler<? extends T> arg1, HttpContext arg2) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public <T> T execute(HttpHost arg0, HttpRequest arg1, ResponseHandler<? extends T> arg2) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public <T> T execute(HttpHost arg0, HttpRequest arg1, ResponseHandler<? extends T> arg2, HttpContext arg3) throws IOException, ClientProtocolException {
			// TODO Auto-generated method stub
			return null;
		}

		public ClientConnectionManager getConnectionManager() {
			// TODO Auto-generated method stub
			return null;
		}

		public HttpParams getParams() {
			// TODO Auto-generated method stub
			return null;
		}
		
	}

}
