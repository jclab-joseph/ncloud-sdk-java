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
 * CreateMemberServerImageRequest
 */
public class CreateMemberServerImageRequest {
	private String memberServerImageDescription = null;

	private String memberServerImageName = null;

	private String serverInstanceNo = null;

	private String responseFormatType = null;

	public CreateMemberServerImageRequest memberServerImageDescription(String memberServerImageDescription) {
		this.memberServerImageDescription = memberServerImageDescription;
		return this;
	}

	 /**
	 * 회원서버이미지설명
	 * @return memberServerImageDescription
	**/
	public String getMemberServerImageDescription() {
		return memberServerImageDescription;
	}

	public void setMemberServerImageDescription(String memberServerImageDescription) {
		this.memberServerImageDescription = memberServerImageDescription;
	}

	public CreateMemberServerImageRequest memberServerImageName(String memberServerImageName) {
		this.memberServerImageName = memberServerImageName;
		return this;
	}

	 /**
	 * 회원서버이미지명
	 * @return memberServerImageName
	**/
	public String getMemberServerImageName() {
		return memberServerImageName;
	}

	public void setMemberServerImageName(String memberServerImageName) {
		this.memberServerImageName = memberServerImageName;
	}

	public CreateMemberServerImageRequest serverInstanceNo(String serverInstanceNo) {
		this.serverInstanceNo = serverInstanceNo;
		return this;
	}

	 /**
	 * 서버인스턴스번호
	 * @return serverInstanceNo
	**/
	public String getServerInstanceNo() {
		return serverInstanceNo;
	}

	public void setServerInstanceNo(String serverInstanceNo) {
		this.serverInstanceNo = serverInstanceNo;
	}

	public CreateMemberServerImageRequest responseFormatType(String responseFormatType) {
		this.responseFormatType = responseFormatType;
		return this;
	}

	 /**
	 * responseFormatType {json, xml}
	 * @return responseFormatType
	**/
	public String getResponseFormatType() {
		return responseFormatType;
	}

	public void setResponseFormatType(String responseFormatType) {
		this.responseFormatType = responseFormatType;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		CreateMemberServerImageRequest createMemberServerImageRequest = (CreateMemberServerImageRequest) o;
		return Objects.equals(this.memberServerImageDescription, createMemberServerImageRequest.memberServerImageDescription) &&
				Objects.equals(this.memberServerImageName, createMemberServerImageRequest.memberServerImageName) &&
				Objects.equals(this.serverInstanceNo, createMemberServerImageRequest.serverInstanceNo) &&
				Objects.equals(this.responseFormatType, createMemberServerImageRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(memberServerImageDescription, memberServerImageName, serverInstanceNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class CreateMemberServerImageRequest {\n");
		
		sb.append("		memberServerImageDescription: ").append(toIndentedString(memberServerImageDescription)).append("\n");
		sb.append("		memberServerImageName: ").append(toIndentedString(memberServerImageName)).append("\n");
		sb.append("		serverInstanceNo: ").append(toIndentedString(serverInstanceNo)).append("\n");
		sb.append("		responseFormatType: ").append(toIndentedString(responseFormatType)).append("\n");
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

