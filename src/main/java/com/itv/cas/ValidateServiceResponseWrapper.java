package com.itv.cas;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

// TODO: use XML mapper
public class ValidateServiceResponseWrapper extends HttpServletResponseWrapper {

	private StringWriter backingWriter;
	
	private PrintWriter printWriter;
	
	private Pattern pattern = Pattern.compile("<cas:user>(.+)</cas:user>");

	public ValidateServiceResponseWrapper(HttpServletResponse response) {
		super(response);
		backingWriter = new StringWriter();
		printWriter = new PrintWriter(backingWriter);
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		return printWriter;
	}

	public String getWrittenContent() {
		return backingWriter.toString();
	}

	public void writeThrough() throws IOException {
		// TODO: change namespace in CAS code/config
		super.getWriter().write(
				getWrittenContent().replace("xmlns:cas='http://www.yale.edu/tp/cas'", 
						"xmlns:cas='http://cas.itv.com/api'"));
	}

	public void writeInvalidDigestResponse(String digest) throws IOException {
		PrintWriter writer = super.getWriter();
		writer.write("<cas:serviceResponse xmlns:cas='http://cas.itv.com/api'><cas:authenticationFailure code=\"INVALID_DIGEST\">");
		writer.write("Digest provided is invalid, contact administrator");
		writer.write("</cas:authenticationFailure></cas:serviceResponse>");
	}

	public boolean isAuthenticationSuccess() {
		return getWrittenContent().contains("<cas:authenticationSuccess>");
	}
	
	public String getUserId() {
		Matcher matcher = pattern.matcher(getWrittenContent());
		return matcher.find() ? matcher.group(1) : null;
	}

}
