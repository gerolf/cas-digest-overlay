package com.itv.cas;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

public class ValidateServiceResponseWrapperTest {

	private static final String SUCCESS_RESPONSE = "<cas:serviceResponse xmlns:cas='http://cas.itv.com/api'><cas:authenticationSuccess><cas:user>TESTUSER</cas:user></cas:authenticationSucces></cas:serviceResponse>";
	private static final String FAILURE_RESPONSE = "<cas:serviceResponse xmlns:cas='http://cas.itv.com/api'><cas:authenticationFailure code=\"INVALID_TICKET\">Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized</cas:authenticationFailure></cas:serviceResponse>";

	private HttpServletResponse servletResponseMock = new MockHttpServletResponse();

	private ValidateServiceResponseWrapper wrapper = new ValidateServiceResponseWrapper(servletResponseMock);

	@Test
	public void getUserIdFromResponse() throws IOException {
		wrapper.getWriter().write(SUCCESS_RESPONSE);
		assertEquals("TESTUSER", wrapper.getUserId());
	}

	@Test
	public void successResponse() throws IOException {
		wrapper.getWriter().write(SUCCESS_RESPONSE);
		Assert.assertTrue(wrapper.isAuthenticationSuccess());
	}

	@Test
	public void failureResponse() throws IOException {
		wrapper.getWriter().write(FAILURE_RESPONSE);
		Assert.assertFalse(wrapper.isAuthenticationSuccess());
	}

}
