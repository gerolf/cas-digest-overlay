package org.jasig.cas.authentication.handler;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="result")
public class Result {

	private Error error;
	private long uid;
	
	public Result() {
		
	}
	
	public Result(Error error, long uid) {
		this.uid=uid;
		this.error=error;
	}
	
	public long getUid() {
		return uid;
	}

	public void setUid(long uid) {
		this.uid = uid;
	}

	public Error getError() {
		return error;
	}

	public void setError(Error error) {
		this.error = error;
	}
}
