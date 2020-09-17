/*
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vserver.auth;

import com.ncloud.vserver.exception.SdkException;
import okhttp3.Request;

/**
 * The type Default credentials.
 */
public class DefaultCredentials implements Credentials {
	private String apiKey;

	/**
	 * Instantiates a new Default credentials.
	 *
	 * @param apiKey the api key
	 */
	protected DefaultCredentials(String apiKey) {
		if (apiKey == null) {
			throw new SdkException("Api Key cannot be null.");
		}
		this.apiKey = apiKey;
	}

	public void applyCredentials(Request.Builder requestBuilder, boolean isRequiredApiKey) {
		if (isRequiredApiKey == true) {
        	requestBuilder.addHeader("x-ncp-apigw-api-key", apiKey);
		}
    }
}
