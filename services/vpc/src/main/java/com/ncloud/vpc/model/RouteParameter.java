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
 * RouteParameter
 */
public class RouteParameter {
	private String destinationCidrBlock = null;

	private String targetTypeCode = null;

	private String targetNo = null;

	private String targetName = null;

	public RouteParameter destinationCidrBlock(String destinationCidrBlock) {
		this.destinationCidrBlock = destinationCidrBlock;
		return this;
	}

	 /**
	 * 목적지CIDR블록
	 * @return destinationCidrBlock
	**/
	public String getDestinationCidrBlock() {
		return destinationCidrBlock;
	}

	public void setDestinationCidrBlock(String destinationCidrBlock) {
		this.destinationCidrBlock = destinationCidrBlock;
	}

	public RouteParameter targetTypeCode(String targetTypeCode) {
		this.targetTypeCode = targetTypeCode;
		return this;
	}

	 /**
	 * 목적지유형코드
	 * @return targetTypeCode
	**/
	public String getTargetTypeCode() {
		return targetTypeCode;
	}

	public void setTargetTypeCode(String targetTypeCode) {
		this.targetTypeCode = targetTypeCode;
	}

	public RouteParameter targetNo(String targetNo) {
		this.targetNo = targetNo;
		return this;
	}

	 /**
	 * 목적지번호
	 * @return targetNo
	**/
	public String getTargetNo() {
		return targetNo;
	}

	public void setTargetNo(String targetNo) {
		this.targetNo = targetNo;
	}

	public RouteParameter targetName(String targetName) {
		this.targetName = targetName;
		return this;
	}

	 /**
	 * 목적지이름
	 * @return targetName
	**/
	public String getTargetName() {
		return targetName;
	}

	public void setTargetName(String targetName) {
		this.targetName = targetName;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		RouteParameter routeParameter = (RouteParameter) o;
		return Objects.equals(this.destinationCidrBlock, routeParameter.destinationCidrBlock) &&
				Objects.equals(this.targetTypeCode, routeParameter.targetTypeCode) &&
				Objects.equals(this.targetNo, routeParameter.targetNo) &&
				Objects.equals(this.targetName, routeParameter.targetName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(destinationCidrBlock, targetTypeCode, targetNo, targetName);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class RouteParameter {\n");
		
		sb.append("		destinationCidrBlock: ").append(toIndentedString(destinationCidrBlock)).append("\n");
		sb.append("		targetTypeCode: ").append(toIndentedString(targetTypeCode)).append("\n");
		sb.append("		targetNo: ").append(toIndentedString(targetNo)).append("\n");
		sb.append("		targetName: ").append(toIndentedString(targetName)).append("\n");
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

