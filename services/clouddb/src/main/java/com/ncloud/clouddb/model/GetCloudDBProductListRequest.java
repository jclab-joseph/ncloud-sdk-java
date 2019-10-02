/*
 * clouddb
 * Cloud DB<br/>https://ncloud.apigw.ntruss.com/clouddb/v2
 *
 * OpenAPI spec version: 2018-11-13T06:30:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.clouddb.model;

import java.util.Objects;

/**
 * GetCloudDBProductListRequest
 */
public class GetCloudDBProductListRequest {
	private String exclusionProductCode = null;

	private String cloudDBImageProductCode = null;

	private String productCode = null;

	private String regionNo = null;

	private String zoneNo = null;

	private String responseFormatType = null;

	public GetCloudDBProductListRequest exclusionProductCode(String exclusionProductCode) {
		this.exclusionProductCode = exclusionProductCode;
		return this;
	}

	 /**
	 * 제외할상품코드
	 * @return exclusionProductCode
	**/
	public String getExclusionProductCode() {
		return exclusionProductCode;
	}

	public void setExclusionProductCode(String exclusionProductCode) {
		this.exclusionProductCode = exclusionProductCode;
	}

	public GetCloudDBProductListRequest cloudDBImageProductCode(String cloudDBImageProductCode) {
		this.cloudDBImageProductCode = cloudDBImageProductCode;
		return this;
	}

	 /**
	 * CloudDB이미지상품코드
	 * @return cloudDBImageProductCode
	**/
	public String getCloudDBImageProductCode() {
		return cloudDBImageProductCode;
	}

	public void setCloudDBImageProductCode(String cloudDBImageProductCode) {
		this.cloudDBImageProductCode = cloudDBImageProductCode;
	}

	public GetCloudDBProductListRequest productCode(String productCode) {
		this.productCode = productCode;
		return this;
	}

	 /**
	 * 조회할상품코드
	 * @return productCode
	**/
	public String getProductCode() {
		return productCode;
	}

	public void setProductCode(String productCode) {
		this.productCode = productCode;
	}

	public GetCloudDBProductListRequest regionNo(String regionNo) {
		this.regionNo = regionNo;
		return this;
	}

	 /**
	 * 리전번호
	 * @return regionNo
	**/
	public String getRegionNo() {
		return regionNo;
	}

	public void setRegionNo(String regionNo) {
		this.regionNo = regionNo;
	}

	public GetCloudDBProductListRequest zoneNo(String zoneNo) {
		this.zoneNo = zoneNo;
		return this;
	}

	 /**
	 * zone번호
	 * @return zoneNo
	**/
	public String getZoneNo() {
		return zoneNo;
	}

	public void setZoneNo(String zoneNo) {
		this.zoneNo = zoneNo;
	}

	public GetCloudDBProductListRequest responseFormatType(String responseFormatType) {
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
		GetCloudDBProductListRequest getCloudDBProductListRequest = (GetCloudDBProductListRequest) o;
		return Objects.equals(this.exclusionProductCode, getCloudDBProductListRequest.exclusionProductCode) &&
				Objects.equals(this.cloudDBImageProductCode, getCloudDBProductListRequest.cloudDBImageProductCode) &&
				Objects.equals(this.productCode, getCloudDBProductListRequest.productCode) &&
				Objects.equals(this.regionNo, getCloudDBProductListRequest.regionNo) &&
				Objects.equals(this.zoneNo, getCloudDBProductListRequest.zoneNo) &&
				Objects.equals(this.responseFormatType, getCloudDBProductListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(exclusionProductCode, cloudDBImageProductCode, productCode, regionNo, zoneNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetCloudDBProductListRequest {\n");
		
		sb.append("		exclusionProductCode: ").append(toIndentedString(exclusionProductCode)).append("\n");
		sb.append("		cloudDBImageProductCode: ").append(toIndentedString(cloudDBImageProductCode)).append("\n");
		sb.append("		productCode: ").append(toIndentedString(productCode)).append("\n");
		sb.append("		regionNo: ").append(toIndentedString(regionNo)).append("\n");
		sb.append("		zoneNo: ").append(toIndentedString(zoneNo)).append("\n");
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

