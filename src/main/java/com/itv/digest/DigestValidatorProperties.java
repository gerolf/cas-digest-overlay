package com.itv.digest;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DigestValidatorProperties {

	private final Logger logger = LoggerFactory.getLogger(DigestValidatorProperties.class);

	private static final String PROPERTYFILE = "/digestvalidation.properties";
	private static final int MILLISPERSECOND = 1000;
	private static final int DEFAULT_CACHE_MILLIS = 60 * 60 * MILLISPERSECOND;
	
	private RefreshTimer refreshTimer = new RefreshTimer(DEFAULT_CACHE_MILLIS);
	
	/**
	 * The parameters cached in memory.
	 */
	private Properties cachedParams;
	
	public Properties getParameters() {
		if (refreshTimer.requiresRefresh()) {
			refreshParameters();
		}

		return cachedParams;
	}
	
	private void refreshParameters() {
		logger.info("Refreshing parameters");
		Properties props = new Properties();
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		try {
			InputStream ins = classLoader.getResourceAsStream(PROPERTYFILE);
			props.load(ins);
		} catch (IOException e) {
			logger.error("could not load property file! ",e);
		} catch(Exception e) {
			logger.error("could not load property file! ",e);
		}
		cachedParams = props;
		refreshTimer.resetTimer();
	}

	
	/**
	 * RefreshTimer decides if the Parameters need to be refreshed.
	 */
	private static class RefreshTimer {
		/**
		 * Last refresh time.
		 */
		private long lastRefresh = -1;

		/**
		 * How long to cache.
		 */
		private long cacheMillis = -1;

		public RefreshTimer(long cacheMillis) {
			this.cacheMillis = cacheMillis;
		}

		/**
		 * Returns true if the method is invoked the first time or if the
		 * maximum cache time has been exceeded.
		 * 
		 * @return true if the method is invoked the first time or if the
		 *         maximum cache time has been exceeded
		 */
		public boolean requiresRefresh() {
			boolean firstLoad = lastRefresh < 0;
			boolean expired = cacheMillis >= 0 && System.currentTimeMillis() > lastRefresh + cacheMillis;

			return firstLoad || expired;
		}

		/**
		 * Resets the last refresh time.
		 */
		public void resetTimer() {
			lastRefresh = System.currentTimeMillis();
		}
	}
}
