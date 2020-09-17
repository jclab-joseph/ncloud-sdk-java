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
import com.ncloud.vpc.model.RemoveNetworkAclRuleParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * RemoveNetworkAclInboundRuleRequest
 */
public class RemoveNetworkAclInboundRuleRequest {
	private String regionCode = null;

	private String networkAclNo = null;

	private List<RemoveNetworkAclRuleParameter> networkAclRuleList = new ArrayList<RemoveNetworkAclRuleParameter>();

	private String responseFormatType = null;

	public RemoveNetworkAclInboundRuleRequest regionCode(String regionCode) {
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

	public RemoveNetworkAclInboundRuleRequest networkAclNo(String networkAclNo) {
		this.networkAclNo = networkAclNo;
		return this;
	}

	 /**
	 * 네트워크ACL번호
	 * @return networkAclNo
	**/
	public String getNetworkAclNo() {
		return networkAclNo;
	}

	public void setNetworkAclNo(String networkAclNo) {
		this.networkAclNo = networkAclNo;
	}

	public RemoveNetworkAclInboundRuleRequest networkAclRuleList(List<RemoveNetworkAclRuleParameter> networkAclRuleList) {
		this.networkAclRuleList = networkAclRuleList;
		return this;
	}

	public RemoveNetworkAclInboundRuleRequest addNetworkAclRuleListItem(RemoveNetworkAclRuleParameter networkAclRuleListItem) {
		this.networkAclRuleList.add(networkAclRuleListItem);
		return this;
	}

	 /**
	 * 네트워크ACLRule리스트
	 * @return networkAclRuleList
	**/
	public List<RemoveNetworkAclRuleParameter> getNetworkAclRuleList() {
		return networkAclRuleList;
	}

	public void setNetworkAclRuleList(List<RemoveNetworkAclRuleParameter> networkAclRuleList) {
		this.networkAclRuleList = networkAclRuleList;
	}

	public RemoveNetworkAclInboundRuleRequest responseFormatType(String responseFormatType) {
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
		RemoveNetworkAclInboundRuleRequest removeNetworkAclInboundRuleRequest = (RemoveNetworkAclInboundRuleRequest) o;
		return Objects.equals(this.regionCode, removeNetworkAclInboundRuleRequest.regionCode) &&
				Objects.equals(this.networkAclNo, removeNetworkAclInboundRuleRequest.networkAclNo) &&
				Objects.equals(this.networkAclRuleList, removeNetworkAclInboundRuleRequest.networkAclRuleList) &&
				Objects.equals(this.responseFormatType, removeNetworkAclInboundRuleRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, networkAclNo, networkAclRuleList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class RemoveNetworkAclInboundRuleRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		networkAclNo: ").append(toIndentedString(networkAclNo)).append("\n");
		sb.append("		networkAclRuleList: ").append(toIndentedString(networkAclRuleList)).append("\n");
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

