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
 * DeleteAccessControlGroupRequest
 */
public class DeleteAccessControlGroupRequest {
	private String regionCode = null;

	private String vpcNo = null;

	private String accessControlGroupNo = null;

	private String responseFormatType = null;

	public DeleteAccessControlGroupRequest regionCode(String regionCode) {
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

	public DeleteAccessControlGroupRequest vpcNo(String vpcNo) {
		this.vpcNo = vpcNo;
		return this;
	}

	 /**
	 * VPC번호
	 * @return vpcNo
	**/
	public String getVpcNo() {
		return vpcNo;
	}

	public void setVpcNo(String vpcNo) {
		this.vpcNo = vpcNo;
	}

	public DeleteAccessControlGroupRequest accessControlGroupNo(String accessControlGroupNo) {
		this.accessControlGroupNo = accessControlGroupNo;
		return this;
	}

	 /**
	 * ACG번호
	 * @return accessControlGroupNo
	**/
	public String getAccessControlGroupNo() {
		return accessControlGroupNo;
	}

	public void setAccessControlGroupNo(String accessControlGroupNo) {
		this.accessControlGroupNo = accessControlGroupNo;
	}

	public DeleteAccessControlGroupRequest responseFormatType(String responseFormatType) {
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
		DeleteAccessControlGroupRequest deleteAccessControlGroupRequest = (DeleteAccessControlGroupRequest) o;
		return Objects.equals(this.regionCode, deleteAccessControlGroupRequest.regionCode) &&
				Objects.equals(this.vpcNo, deleteAccessControlGroupRequest.vpcNo) &&
				Objects.equals(this.accessControlGroupNo, deleteAccessControlGroupRequest.accessControlGroupNo) &&
				Objects.equals(this.responseFormatType, deleteAccessControlGroupRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, vpcNo, accessControlGroupNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeleteAccessControlGroupRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		vpcNo: ").append(toIndentedString(vpcNo)).append("\n");
		sb.append("		accessControlGroupNo: ").append(toIndentedString(accessControlGroupNo)).append("\n");
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

