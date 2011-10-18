package com.itv.cas;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.itv.digest.DigestValidatorProperties;
import com.itv.digest.LocalDigestValidator;

public class DigestValidateFilter implements Filter {

	static final String DIGEST_SERVICE_URL_PARAM = "digestServiceURL";

	static final String SERVICE_PARAM = "service";
	static final String TICKET_PARAM = "ticket";
	static final String DIGEST_HEADER = "Digest";

	private final Logger logger = Logger.getLogger(DigestValidateFilter.class);

	private DigestValidatorProperties digestprops;
	private DigestValidationWSClient webservice;
	private LocalDigestValidator localDigestValidator;

	
	public void init(FilterConfig config) throws ServletException {
		digestprops = new DigestValidatorProperties();
		if (digestprops.getParameters().getProperty("validator").equalsIgnoreCase("webservice")) {
			//String digestServiceURL = config.getInitParameter(DIGEST_SERVICE_URL_PARAM);
			String digestServiceURL = digestprops.getParameters().getProperty(DIGEST_SERVICE_URL_PARAM);		
			if (isBlank(digestServiceURL)) {
				throw new ServletException("init-param " + DIGEST_SERVICE_URL_PARAM + " was not set");
			}
			webservice = new DigestValidationWSClient(digestServiceURL);
			logger.info("ITV Digest validate filter init. Digest validation service URL is " + digestServiceURL);
		}
		else {
			localDigestValidator = new LocalDigestValidator();
			logger.info("ITV Digest validate filter init. Using local digest validation.");
		}
		
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		String digest = request.getHeader(DIGEST_HEADER);
		String serviceUrl = request.getParameter(SERVICE_PARAM);
		String ticket = request.getParameter(TICKET_PARAM);

		ValidateServiceResponseWrapper responseWrapper = new ValidateServiceResponseWrapper(response);
		logger.info("Got validate request with digest: "+ digest+" serviceUrl: "+serviceUrl+" and ticket: "+ticket);
		logger.info("doing the filter chain");
		chain.doFilter(req, responseWrapper);
		logger.info(responseWrapper.isAuthenticationSuccess() ? "succesfully checked against CAS" : "CAS does not know you");
		
		if (responseWrapper.isAuthenticationSuccess() && isNotBlank(digest)) {
			validateAndSetDigest(responseWrapper, ticket, digest, serviceUrl);
		} else {
			noDigestValidation(responseWrapper, digest);
		}
	}

	private void noDigestValidation(ValidateServiceResponseWrapper responseWrapper, String digest) throws IOException {
		if (logger.isDebugEnabled()) {
			logger.debug(isBlank(digest) ? "Header not present, not validating digest"
					: "Service ticket validation failed, not validating digest");
		}
		responseWrapper.writeThrough();
	}

	private void validateAndSetDigest(ValidateServiceResponseWrapper responseWrapper, String ticket, String digest, String serviceUrl)
			throws IOException, ServletException {
		logger.info("Validating digest");
		try {
			String resultingDigest;
			if (digestprops.getParameters().getProperty("validator").equalsIgnoreCase("webservice")) {
				resultingDigest = webservice.validateDigest(digest, ticket,serviceUrl, responseWrapper.getUserId());
			}
			else {
				resultingDigest = localDigestValidator.validateDigest(digest, ticket, serviceUrl, responseWrapper.getUserId());
			}
			responseWrapper.setHeader(DIGEST_HEADER, resultingDigest);
			logger.info("succesfully validated digest. returning to client...");
			responseWrapper.writeThrough();
		} catch (InvalidDigestException e) {
			logger.info("Invalid digest provided: " + digest);
			responseWrapper.writeInvalidDigestResponse(digest);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}

}

	