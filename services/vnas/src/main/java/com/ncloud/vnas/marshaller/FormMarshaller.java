/*
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vnas.marshaller;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ncloud.vnas.exception.SdkException;

/**
 * The type Form marshaller.
 */
public class FormMarshaller implements Marshaller {
	private static FormMarshaller instance;
	private final String contentType;
	private final ObjectMapper objectMapper;

	private FormMarshaller() {
		contentType = "application/x-www-form-urlencoded";
		objectMapper = new ObjectMapper();
	}

	/**
	 * Gets instance.
	 *
	 * @return the instance
	 */
	public static FormMarshaller getInstance() {
		if (instance == null) {
			instance = new FormMarshaller();
		}
		return instance;
	}

	public String getContentType() {
		return contentType;
	}

	public String writeValueAsString(Object value) throws IOException {
		return get(objectMapper.convertValue(value, Map.class));
	}

	public <T> T readValue(InputStream src, Class clazz) throws IOException {
		throw new SdkException("Unsupported operation");
	}

	private String get(Map<String, Object> formParams) throws UnsupportedEncodingException {
		StringBuilder formParamBuilder = new StringBuilder();
		getUrlencodedParams(formParamBuilder, formParams, null);

		String encodedFormParams = formParamBuilder.toString();
		if (encodedFormParams.endsWith("&")) {
			encodedFormParams = encodedFormParams.substring(0, encodedFormParams.length() - 1);
		}

		return encodedFormParams.toString();
	}

	private void getUrlencodedParams(StringBuilder stringBuilder, Map<String, Object> formParams, String key) throws UnsupportedEncodingException {
		for (Map.Entry<String, Object> param : formParams.entrySet()) {
			String innerKey = (key == null) ? param.getKey() : key + "." + param.getKey();
			appendUrlencodedParam(stringBuilder, innerKey, param.getValue());
		}
	}

	private void appendUrlencodedParam(StringBuilder stringBuilder, String key, Object value) throws UnsupportedEncodingException {
		if (value instanceof Collection) {
			int i = 1;
			for(Object o : ((Collection<?>)value)) {
				appendUrlencodedParam(stringBuilder, key + "." + i++, o);
			}
		}
		else if (value instanceof Map) {
			getUrlencodedParams(stringBuilder, (Map)value, key);
		}
		else if (value != null) {
			String val;
			if (key.equals("userData")) {
				val = Base64.encodeBase64String(String.valueOf(value).getBytes());
			}else {
				val = URLEncoder.encode(String.valueOf(value), "utf8");
			}
			stringBuilder
				.append(URLEncoder.encode(key, "utf8"))
				.append("=")
				.append(val)
				.append("&");
		}
	}
}
