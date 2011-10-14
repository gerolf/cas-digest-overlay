package org.jasig.cas.authentication.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DrupalHandler extends AbstractUsernamePasswordAuthenticationHandler {
	
	static final String XML_PACKAGE = Result.class.getPackage().getName();

	private static final Logger logger = LoggerFactory.getLogger(DrupalHandler.class);
	private String URL;
	private static JAXBContext jaxbContext;
	
	
	public DrupalHandler(String URL) {
		super();
		this.URL=URL;
		if (StringUtils.isBlank(this.URL)) {
			logger.error("Invalid URL specified for authentication against Drupal userbase.");
		}
	}

	@SuppressWarnings("serial")
	@Override
	protected boolean authenticateUsernamePasswordInternal(UsernamePasswordCredentials credentials) throws AuthenticationException {
		if (credentials==null || credentials.getUsername()== null || credentials.getPassword()==null) {
			throw new UnsupportedCredentialsException();
		}
		if (StringUtils.isBlank(this.URL)) {
			throw new AuthenticationException("AuthHandlerException") {};
		}
		
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("username", credentials.getUsername()));
		params.add(new BasicNameValuePair("password", credentials.getPassword()));
		UrlEncodedFormEntity entity =null;
		try {
			 //entity = new UrlEncodedFormEntity(params, "UTF-8");
			entity = new UrlEncodedFormEntity(params, "iso-8859-1");
		} catch (IOException ioe) {
			throw new AuthenticationException("AuthHandlerException") {};
		}
		HttpClient httpClient = new DefaultHttpClient();
		HttpPost method = new HttpPost(this.URL);
		method.setEntity(entity);
		method.addHeader("Accept","application/xml");

		HttpResponse response;
		try {
			response = httpClient.execute(method);
		} catch (ClientProtocolException e1) {
			throw new AuthenticationException("AuthHandlerException") {};
		} catch (IOException e1) {
			throw new AuthenticationException("AuthHandlerException") {};
		}
		HttpEntity resultingEntity = response.getEntity();

		// TODO: check HTTP response code and fail gracefully
		try {
			Result result = (Result)getJAXBContext().createUnmarshaller().unmarshal(resultingEntity.getContent());
			if (result.getUid()<=0) {
				return false;
			}
			else {
				return true;
			}
		} catch (Exception e) {
			logger.error("general error trying to authenticate user response",e);
		}
		return false;
	}
	
	private synchronized JAXBContext getJAXBContext() throws JAXBException {
		if (jaxbContext == null) {
			jaxbContext = JAXBContext.newInstance(XML_PACKAGE);
		}
		return jaxbContext;
	}
}
