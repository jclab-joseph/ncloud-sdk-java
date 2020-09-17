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
import com.ncloud.vpc.model.CommonCode;

/**
 * Vpc
 */
public class Vpc {
	private String vpcNo = null;

	private String vpcName = null;

	private String ipv4CidrBlock = null;

	private CommonCode vpcStatus = null;

	private String regionCode = null;

	private String createDate = null;

	public Vpc vpcNo(String vpcNo) {
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

	public Vpc vpcName(String vpcName) {
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

	public Vpc ipv4CidrBlock(String ipv4CidrBlock) {
		this.ipv4CidrBlock = ipv4CidrBlock;
		return this;
	}

	 /**
	 * IPv4 CIDR블록
	 * @return ipv4CidrBlock
	**/
	public String getIpv4CidrBlock() {
		return ipv4CidrBlock;
	}

	public void setIpv4CidrBlock(String ipv4CidrBlock) {
		this.ipv4CidrBlock = ipv4CidrBlock;
	}

	public Vpc vpcStatus(CommonCode vpcStatus) {
		this.vpcStatus = vpcStatus;
		return this;
	}

	 /**
	 * VPC상태
	 * @return vpcStatus
	**/
	public CommonCode getVpcStatus() {
		return vpcStatus;
	}

	public void setVpcStatus(CommonCode vpcStatus) {
		this.vpcStatus = vpcStatus;
	}

	public Vpc regionCode(String regionCode) {
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

	public Vpc createDate(String createDate) {
		this.createDate = createDate;
		return this;
	}

	 /**
	 * 생성일시
	 * @return createDate
	**/
	public String getCreateDate() {
		return createDate;
	}

	public void setCreateDate(String createDate) {
		this.createDate = createDate;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		Vpc vpc = (Vpc) o;
		return Objects.equals(this.vpcNo, vpc.vpcNo) &&
				Objects.equals(this.vpcName, vpc.vpcName) &&
				Objects.equals(this.ipv4CidrBlock, vpc.ipv4CidrBlock) &&
				Objects.equals(this.vpcStatus, vpc.vpcStatus) &&
				Objects.equals(this.regionCode, vpc.regionCode) &&
				Objects.equals(this.createDate, vpc.createDate);
	}

	@Override
	public int hashCode() {
		return Objects.hash(vpcNo, vpcName, ipv4CidrBlock, vpcStatus, regionCode, createDate);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class Vpc {\n");
		
		sb.append("		vpcNo: ").append(toIndentedString(vpcNo)).append("\n");
		sb.append("		vpcName: ").append(toIndentedString(vpcName)).append("\n");
		sb.append("		ipv4CidrBlock: ").append(toIndentedString(ipv4CidrBlock)).append("\n");
		sb.append("		vpcStatus: ").append(toIndentedString(vpcStatus)).append("\n");
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		createDate: ").append(toIndentedString(createDate)).append("\n");
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

