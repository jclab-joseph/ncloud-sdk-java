/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2019-10-17T10:28:43Z
 *
 * NBP corp.
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;

/**
 * InstanceTagParameter
 */
public class InstanceTagParameter {
	private String tagKey = null;

	private String tagValue = null;

	public InstanceTagParameter tagKey(String tagKey) {
		this.tagKey = tagKey;
		return this;
	}

	 /**
	 * 태그키
	 * @return tagKey
	**/
	public String getTagKey() {
		return tagKey;
	}

	public void setTagKey(String tagKey) {
		this.tagKey = tagKey;
	}

	public InstanceTagParameter tagValue(String tagValue) {
		this.tagValue = tagValue;
		return this;
	}

	 /**
	 * 태그값
	 * @return tagValue
	**/
	public String getTagValue() {
		return tagValue;
	}

	public void setTagValue(String tagValue) {
		this.tagValue = tagValue;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		InstanceTagParameter instanceTagParameter = (InstanceTagParameter) o;
		return Objects.equals(this.tagKey, instanceTagParameter.tagKey) &&
				Objects.equals(this.tagValue, instanceTagParameter.tagValue);
	}

	@Override
	public int hashCode() {
		return Objects.hash(tagKey, tagValue);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class InstanceTagParameter {\n");
		
		sb.append("		tagKey: ").append(toIndentedString(tagKey)).append("\n");
		sb.append("		tagValue: ").append(toIndentedString(tagValue)).append("\n");
		sb.append("}");
		return sb.toString();
	}

	/**
	 * Convert the given object to string with each line indented by 4 spaces
	 * (except the first line).
	 */
	private String toIndentedString(java.lang.Object o) {
		if (o == null) {
			return "null";
		}
		return o.toString().replace("\n", "\n		");
	}

}

