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
import com.ncloud.server.model.CommonCode;

/**
 * AccessControlRule
 */
public class AccessControlRule {
	private String accessControlRuleConfigurationNo = null;

	private CommonCode protocolType = null;

	private String sourceIp = null;

	private String sourceAccessControlRuleConfigurationNo = null;

	private String sourceAccessControlRuleName = null;

	private String destinationPort = null;

	private String accessControlRuleDescription = null;

	public AccessControlRule accessControlRuleConfigurationNo(String accessControlRuleConfigurationNo) {
		this.accessControlRuleConfigurationNo = accessControlRuleConfigurationNo;
		return this;
	}

	 /**
	 * 접근제어RULE설정번호
	 * @return accessControlRuleConfigurationNo
	**/
	public String getAccessControlRuleConfigurationNo() {
		return accessControlRuleConfigurationNo;
	}

	public void setAccessControlRuleConfigurationNo(String accessControlRuleConfigurationNo) {
		this.accessControlRuleConfigurationNo = accessControlRuleConfigurationNo;
	}

	public AccessControlRule protocolType(CommonCode protocolType) {
		this.protocolType = protocolType;
		return this;
	}

	 /**
	 * 프로토콜구분
	 * @return protocolType
	**/
	public CommonCode getProtocolType() {
		return protocolType;
	}

	public void setProtocolType(CommonCode protocolType) {
		this.protocolType = protocolType;
	}

	public AccessControlRule sourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
		return this;
	}

	 /**
	 * 소스IP
	 * @return sourceIp
	**/
	public String getSourceIp() {
		return sourceIp;
	}

	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	public AccessControlRule sourceAccessControlRuleConfigurationNo(String sourceAccessControlRuleConfigurationNo) {
		this.sourceAccessControlRuleConfigurationNo = sourceAccessControlRuleConfigurationNo;
		return this;
	}

	 /**
	 * 소스접근제어그룹번호
	 * @return sourceAccessControlRuleConfigurationNo
	**/
	public String getSourceAccessControlRuleConfigurationNo() {
		return sourceAccessControlRuleConfigurationNo;
	}

	public void setSourceAccessControlRuleConfigurationNo(String sourceAccessControlRuleConfigurationNo) {
		this.sourceAccessControlRuleConfigurationNo = sourceAccessControlRuleConfigurationNo;
	}

	public AccessControlRule sourceAccessControlRuleName(String sourceAccessControlRuleName) {
		this.sourceAccessControlRuleName = sourceAccessControlRuleName;
		return this;
	}

	 /**
	 * 소스접근제어그룹이름
	 * @return sourceAccessControlRuleName
	**/
	public String getSourceAccessControlRuleName() {
		return sourceAccessControlRuleName;
	}

	public void setSourceAccessControlRuleName(String sourceAccessControlRuleName) {
		this.sourceAccessControlRuleName = sourceAccessControlRuleName;
	}

	public AccessControlRule destinationPort(String destinationPort) {
		this.destinationPort = destinationPort;
		return this;
	}

	 /**
	 * 목적지포트
	 * @return destinationPort
	**/
	public String getDestinationPort() {
		return destinationPort;
	}

	public void setDestinationPort(String destinationPort) {
		this.destinationPort = destinationPort;
	}

	public AccessControlRule accessControlRuleDescription(String accessControlRuleDescription) {
		this.accessControlRuleDescription = accessControlRuleDescription;
		return this;
	}

	 /**
	 * 접근제어RULE설명
	 * @return accessControlRuleDescription
	**/
	public String getAccessControlRuleDescription() {
		return accessControlRuleDescription;
	}

	public void setAccessControlRuleDescription(String accessControlRuleDescription) {
		this.accessControlRuleDescription = accessControlRuleDescription;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		AccessControlRule accessControlRule = (AccessControlRule) o;
		return Objects.equals(this.accessControlRuleConfigurationNo, accessControlRule.accessControlRuleConfigurationNo) &&
				Objects.equals(this.protocolType, accessControlRule.protocolType) &&
				Objects.equals(this.sourceIp, accessControlRule.sourceIp) &&
				Objects.equals(this.sourceAccessControlRuleConfigurationNo, accessControlRule.sourceAccessControlRuleConfigurationNo) &&
				Objects.equals(this.sourceAccessControlRuleName, accessControlRule.sourceAccessControlRuleName) &&
				Objects.equals(this.destinationPort, accessControlRule.destinationPort) &&
				Objects.equals(this.accessControlRuleDescription, accessControlRule.accessControlRuleDescription);
	}

	@Override
	public int hashCode() {
		return Objects.hash(accessControlRuleConfigurationNo, protocolType, sourceIp, sourceAccessControlRuleConfigurationNo, sourceAccessControlRuleName, destinationPort, accessControlRuleDescription);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class AccessControlRule {\n");
		
		sb.append("		accessControlRuleConfigurationNo: ").append(toIndentedString(accessControlRuleConfigurationNo)).append("\n");
		sb.append("		protocolType: ").append(toIndentedString(protocolType)).append("\n");
		sb.append("		sourceIp: ").append(toIndentedString(sourceIp)).append("\n");
		sb.append("		sourceAccessControlRuleConfigurationNo: ").append(toIndentedString(sourceAccessControlRuleConfigurationNo)).append("\n");
		sb.append("		sourceAccessControlRuleName: ").append(toIndentedString(sourceAccessControlRuleName)).append("\n");
		sb.append("		destinationPort: ").append(toIndentedString(destinationPort)).append("\n");
		sb.append("		accessControlRuleDescription: ").append(toIndentedString(accessControlRuleDescription)).append("\n");
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

