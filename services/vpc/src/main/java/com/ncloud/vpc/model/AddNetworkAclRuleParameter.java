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

/**
 * AddNetworkAclRuleParameter
 */
public class AddNetworkAclRuleParameter {
	private String networkAclRuleDescription = null;

	private String ipBlock = null;

	private String ruleActionCode = null;

	private String portRange = null;

	private Integer priority = null;

	private String protocolTypeCode = null;

	public AddNetworkAclRuleParameter networkAclRuleDescription(String networkAclRuleDescription) {
		this.networkAclRuleDescription = networkAclRuleDescription;
		return this;
	}

	 /**
	 * 네트워크ACLRule설명
	 * @return networkAclRuleDescription
	**/
	public String getNetworkAclRuleDescription() {
		return networkAclRuleDescription;
	}

	public void setNetworkAclRuleDescription(String networkAclRuleDescription) {
		this.networkAclRuleDescription = networkAclRuleDescription;
	}

	public AddNetworkAclRuleParameter ipBlock(String ipBlock) {
		this.ipBlock = ipBlock;
		return this;
	}

	 /**
	 * IP블록
	 * @return ipBlock
	**/
	public String getIpBlock() {
		return ipBlock;
	}

	public void setIpBlock(String ipBlock) {
		this.ipBlock = ipBlock;
	}

	public AddNetworkAclRuleParameter ruleActionCode(String ruleActionCode) {
		this.ruleActionCode = ruleActionCode;
		return this;
	}

	 /**
	 * Rule액션코드
	 * @return ruleActionCode
	**/
	public String getRuleActionCode() {
		return ruleActionCode;
	}

	public void setRuleActionCode(String ruleActionCode) {
		this.ruleActionCode = ruleActionCode;
	}

	public AddNetworkAclRuleParameter portRange(String portRange) {
		this.portRange = portRange;
		return this;
	}

	 /**
	 * 포트범위
	 * @return portRange
	**/
	public String getPortRange() {
		return portRange;
	}

	public void setPortRange(String portRange) {
		this.portRange = portRange;
	}

	public AddNetworkAclRuleParameter priority(Integer priority) {
		this.priority = priority;
		return this;
	}

	 /**
	 * 우선순위
	 * @return priority
	**/
	public Integer getPriority() {
		return priority;
	}

	public void setPriority(Integer priority) {
		this.priority = priority;
	}

	public AddNetworkAclRuleParameter protocolTypeCode(String protocolTypeCode) {
		this.protocolTypeCode = protocolTypeCode;
		return this;
	}

	 /**
	 * 프로토콜유형코드
	 * @return protocolTypeCode
	**/
	public String getProtocolTypeCode() {
		return protocolTypeCode;
	}

	public void setProtocolTypeCode(String protocolTypeCode) {
		this.protocolTypeCode = protocolTypeCode;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		AddNetworkAclRuleParameter addNetworkAclRuleParameter = (AddNetworkAclRuleParameter) o;
		return Objects.equals(this.networkAclRuleDescription, addNetworkAclRuleParameter.networkAclRuleDescription) &&
				Objects.equals(this.ipBlock, addNetworkAclRuleParameter.ipBlock) &&
				Objects.equals(this.ruleActionCode, addNetworkAclRuleParameter.ruleActionCode) &&
				Objects.equals(this.portRange, addNetworkAclRuleParameter.portRange) &&
				Objects.equals(this.priority, addNetworkAclRuleParameter.priority) &&
				Objects.equals(this.protocolTypeCode, addNetworkAclRuleParameter.protocolTypeCode);
	}

	@Override
	public int hashCode() {
		return Objects.hash(networkAclRuleDescription, ipBlock, ruleActionCode, portRange, priority, protocolTypeCode);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class AddNetworkAclRuleParameter {\n");
		
		sb.append("		networkAclRuleDescription: ").append(toIndentedString(networkAclRuleDescription)).append("\n");
		sb.append("		ipBlock: ").append(toIndentedString(ipBlock)).append("\n");
		sb.append("		ruleActionCode: ").append(toIndentedString(ruleActionCode)).append("\n");
		sb.append("		portRange: ").append(toIndentedString(portRange)).append("\n");
		sb.append("		priority: ").append(toIndentedString(priority)).append("\n");
		sb.append("		protocolTypeCode: ").append(toIndentedString(protocolTypeCode)).append("\n");
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

