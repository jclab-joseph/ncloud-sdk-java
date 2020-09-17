/*
 * vpc
 * VPC Network 관련 API<br/>https://ncloud.apigw.ntruss.com/vpc/v2
 *
 * OpenAPI spec version: 2020-09-17T02:27:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vpc.model;

import java.util.Objects;
import java.util.ArrayList;
import java.util.List;

/**
 * GetVpcListRequest
 */
public class GetVpcListRequest {
	private String regionCode = null;

	private String vpcName = null;

	private String vpcStatusCode = null;

	private List<String> vpcNoList = null;

	private String responseFormatType = null;

	public GetVpcListRequest regionCode(String regionCode) {
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

	public GetVpcListRequest vpcName(String vpcName) {
		this.vpcName = vpcName;
		return this;
	}

	 /**
	 * VPC이름
	 * @return vpcName
	**/
	public String getVpcName() {
		return vpcName;
	}

	public void setVpcName(String vpcName) {
		this.vpcName = vpcName;
	}

	public GetVpcListRequest vpcStatusCode(String vpcStatusCode) {
		this.vpcStatusCode = vpcStatusCode;
		return this;
	}

	 /**
	 * VPC상태코드
	 * @return vpcStatusCode
	**/
	public String getVpcStatusCode() {
		return vpcStatusCode;
	}

	public void setVpcStatusCode(String vpcStatusCode) {
		this.vpcStatusCode = vpcStatusCode;
	}

	public GetVpcListRequest vpcNoList(List<String> vpcNoList) {
		this.vpcNoList = vpcNoList;
		return this;
	}

	public GetVpcListRequest addVpcNoListItem(String vpcNoListItem) {
		if (this.vpcNoList == null) {
			this.vpcNoList = new ArrayList<String>();
		}
		this.vpcNoList.add(vpcNoListItem);
		return this;
	}

	 /**
	 * VPC번호리스트
	 * @return vpcNoList
	**/
	public List<String> getVpcNoList() {
		return vpcNoList;
	}

	public void setVpcNoList(List<String> vpcNoList) {
		this.vpcNoList = vpcNoList;
	}

	public GetVpcListRequest responseFormatType(String responseFormatType) {
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
		GetVpcListRequest getVpcListRequest = (GetVpcListRequest) o;
		return Objects.equals(this.regionCode, getVpcListRequest.regionCode) &&
				Objects.equals(this.vpcName, getVpcListRequest.vpcName) &&
				Objects.equals(this.vpcStatusCode, getVpcListRequest.vpcStatusCode) &&
				Objects.equals(this.vpcNoList, getVpcListRequest.vpcNoList) &&
				Objects.equals(this.responseFormatType, getVpcListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, vpcName, vpcStatusCode, vpcNoList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetVpcListRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		vpcName: ").append(toIndentedString(vpcName)).append("\n");
		sb.append("		vpcStatusCode: ").append(toIndentedString(vpcStatusCode)).append("\n");
		sb.append("		vpcNoList: ").append(toIndentedString(vpcNoList)).append("\n");
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

