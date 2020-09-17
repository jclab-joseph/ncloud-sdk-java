/*
 * vserver
 * VPC Compute 관련 API<br/>https://ncloud.apigw.ntruss.com/vserver/v2
 *
 * OpenAPI spec version: 2020-09-17T02:28:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vserver.model;

import java.util.Objects;

/**
 * GetMemberServerImageInstanceDetailRequest
 */
public class GetMemberServerImageInstanceDetailRequest {
	private String regionCode = null;

	private String memberServerImageInstanceNo = null;

	private String responseFormatType = null;

	public GetMemberServerImageInstanceDetailRequest regionCode(String regionCode) {
		this.regionCode = regionCode;
		return this;
	}

	 /**
	 * REGION코드
	 * @return regionCode
	**/
	public String getRegionCode() {
		return regionCode;
	}

	public void setRegionCode(String regionCode) {
		this.regionCode = regionCode;
	}

	public GetMemberServerImageInstanceDetailRequest memberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스번호
	 * @return memberServerImageInstanceNo
	**/
	public String getMemberServerImageInstanceNo() {
		return memberServerImageInstanceNo;
	}

	public void setMemberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
	}

	public GetMemberServerImageInstanceDetailRequest responseFormatType(String responseFormatType) {
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
		GetMemberServerImageInstanceDetailRequest getMemberServerImageInstanceDetailRequest = (GetMemberServerImageInstanceDetailRequest) o;
		return Objects.equals(this.regionCode, getMemberServerImageInstanceDetailRequest.regionCode) &&
				Objects.equals(this.memberServerImageInstanceNo, getMemberServerImageInstanceDetailRequest.memberServerImageInstanceNo) &&
				Objects.equals(this.responseFormatType, getMemberServerImageInstanceDetailRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, memberServerImageInstanceNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetMemberServerImageInstanceDetailRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		memberServerImageInstanceNo: ").append(toIndentedString(memberServerImageInstanceNo)).append("\n");
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

