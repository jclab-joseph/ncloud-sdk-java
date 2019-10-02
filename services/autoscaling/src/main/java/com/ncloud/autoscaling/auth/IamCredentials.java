/*
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.autoscaling.auth;

import java.net.URI;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.ncloud.autoscaling.exception.SdkException;
import okhttp3.Request;

/**
 * The type Iam credentials.
 */
public class IamCredentials implements Credentials {
	private final String apiKey;
	private final String accessKey;
	private final String secretKey;

	/**
	 * Instantiates a new Iam credentials.
	 *
	 * @param apiKey the api key
	 * @param accessKey the access key
	 * @param secretKey the secret key
	 */
	protected IamCredentials(String apiKey, String accessKey, String secretKey) {
		if (accessKey == null) {
			throw new SdkException("Aeccess Key cannot be null.");
		}
		if (secretKey == null) {
			throw new SdkException("Secret Key cannot be null.");
		}
		this.apiKey = apiKey;
		this.accessKey = accessKey;
		this.secretKey = secretKey;
	}

    public void applyCredentials(Request.Builder requestBuilder, boolean isRequiredApiKey) {
        long timestamp = new Date().getTime();
		if (isRequiredApiKey == true) {
        	requestBuilder.addHeader("x-ncp-apigw-api-key", apiKey);
		}
        requestBuilder.addHeader("x-ncp-apigw-timestamp", String.valueOf(timestamp));
        requestBuilder.addHeader("x-ncp-iam-access-key", accessKey);
        requestBuilder.addHeader("x-ncp-apigw-signature-v2", makeSignature(timestamp, requestBuilder.build()));
    }

    private String makeSignature(long timestamp, Request request) {
        URI uri = request.url().uri();
        String pathWithQuery = uri.getRawPath();
        if (uri.getRawQuery() != null) {
            pathWithQuery = pathWithQuery + "?"+ uri.getRawQuery();
        }
        StringBuilder message = new StringBuilder()
            .append(request.method()).append(" ").append(pathWithQuery).append("\n")
            .append(timestamp).append("\n")
		    .append(accessKey);

        try {
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(message.toString().getBytes("UTF-8"));
            String signature = Base64.encodeBase64String(rawHmac);
            return signature;
        } catch (Exception e) {
            throw new SdkException("Failed to make signature for IAM credentials: " + e.getMessage(), e);
        }
    }
}
