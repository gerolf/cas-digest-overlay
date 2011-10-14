package com.itv.cas;

import static org.apache.commons.lang.StringUtils.isNotBlank;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;

import com.itv.xml.digest.Result;

public class DigestValidationWSClient {
	static final String XML_PACKAGE = Result.class.getPackage().getName();

	static final String USER_PARAM = "SSO_User_id";
	static final String SERVICE_URL_PARAM = "Service_name";
	static final String DIGEST_PARAM = "Digest";
	static final String TICKET_PARAM = "service_ticket";

	private final Logger logger = Logger.getLogger(DigestValidateFilter.class);

	private String url;

	public DigestValidationWSClient(String url) {
		this.url = url;
	}

	public String validateDigest(String digest, String ticket, String serviceUrl, String userId) throws InvalidDigestException,
			IOException, JAXBException {

		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair(DIGEST_PARAM, digest));
		params.add(new BasicNameValuePair(SERVICE_URL_PARAM, serviceUrl));
		params.add(new BasicNameValuePair(USER_PARAM, userId));
		params.add(new BasicNameValuePair(TICKET_PARAM, ticket));
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params, "UTF-8");

		HttpClient httpClient = new DefaultHttpClient();
		HttpPost method = new HttpPost(url);
		method.setEntity(entity);

		method.addHeader("accept","application/xml");
		// set the digest in the header as well
		method.addHeader("Digest",digest);
		
		HttpResponse response = httpClient.execute(method);
		// get the response digest from the header if it exists
		Header header = response.getFirstHeader("Digest");
		String headerDigest = null;
		if(header!=null) {
			headerDigest = header.getValue();
		}
		// parse the body
		HttpEntity resultingEntity = response.getEntity();
		Result result = parseXML(resultingEntity);

		if (hasError(result)) {
			throw new InvalidDigestException();
		}
		if (headerDigest!=null && isNotBlank(headerDigest)) {
			return headerDigest;
		}
		else if (result.getDigest()!=null && isNotBlank(result.getDigest())) {
			return result.getDigest();
		}
		else {
			throw new InvalidDigestException();
		}
	}

	private Result parseXML(HttpEntity resultingEntity) throws JAXBException, IOException {
		// TODO: cache jaxb context for performance
		JAXBContext jaxbContext = JAXBContext.newInstance(XML_PACKAGE);
		return (Result) jaxbContext.createUnmarshaller().unmarshal(resultingEntity.getContent());
	}

	private boolean hasError(Result result) {
		String errorCode = result.getError().getErrorCode();
		logger.debug("Result error code: " + errorCode);
		return isNotBlank(errorCode);
	}

}
