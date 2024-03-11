package com.ncloud.auth;

import java.net.URI;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.ncloud.exception.SdkException;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;

public class NcloudCredentials implements Credentials {
	private final String accessKey;
	private final String secretKey;

	protected NcloudCredentials(String accessKey, String secretKey) {
		if (accessKey == null) {
			throw new SdkException("Aeccess Key cannot be null.");
		} else if (secretKey == null) {
			throw new SdkException("Secret Key cannot be null.");
		} else {
			this.accessKey = accessKey;
			this.secretKey = secretKey;
		}
	}

	public void applyCredentials(SimpleHttpRequest request, boolean isRequiredApiKey) {
		long timestamp = (new Date()).getTime();
		request.addHeader("x-ncp-apigw-timestamp", String.valueOf(timestamp));
		request.addHeader("x-ncp-iam-access-key", this.accessKey);
		request.addHeader("x-ncp-apigw-signature-v2", this.makeSignature(timestamp, request));
	}

	private String makeSignature(long timestamp, SimpleHttpRequest request) {
		URI uri = URI.create(request.getRequestUri());
		String pathWithQuery = uri.getRawPath();
		if (uri.getRawQuery() != null) {
			pathWithQuery = pathWithQuery + "?" + uri.getRawQuery();
		}

		StringBuilder message = (new StringBuilder()).append(request.getMethod()).append(" ").append(pathWithQuery).append("\n").append(timestamp).append("\n").append(this.accessKey);

		try {
			SecretKeySpec signingKey = new SecretKeySpec(this.secretKey.getBytes("UTF-8"), "HmacSHA256");
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(signingKey);
			byte[] rawHmac = mac.doFinal(message.toString().getBytes("UTF-8"));
			String signature = Base64.encodeBase64String(rawHmac);
			return signature;
		} catch (Exception var11) {
			throw new SdkException("Failed to make signature for IAM credentials: " + var11.getMessage(), var11);
		}
	}
}
