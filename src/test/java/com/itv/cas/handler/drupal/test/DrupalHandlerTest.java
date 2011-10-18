package com.itv.cas.handler.drupal.test;

import junit.framework.Assert;

import org.jasig.cas.authentication.handler.DrupalHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.junit.Ignore;
import org.junit.Test;


public class DrupalHandlerTest {

	private DrupalHandler client = new DrupalHandler("http://107.20.87.153/drupal/?q=api/user_service/user/auth");

	@Test
	@Ignore
	public void handlerReturnsFailedLogin() throws Exception {
		UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
		credentials.setUsername("johny");
		credentials.setPassword("betty");
		Assert.assertEquals(false,client.authenticate(credentials));
	}

	@Test
	@Ignore
	public void handlerReturnsSucceededLogin() throws Exception {
		UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
		credentials.setUsername("john");
		credentials.setPassword("marina");
		Assert.assertEquals(true,client.authenticate(credentials));
	}

}
