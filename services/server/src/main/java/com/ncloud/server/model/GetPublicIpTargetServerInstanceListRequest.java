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
 * GetPublicIpTargetServerInstanceListRequest
 */
public class GetPublicIpTargetServerInstanceListRequest {
	private String internetLineTypeCode = null;

	private String regionNo = null;

	private String zoneNo = null;

	private String responseFormatType = null;

	public GetPublicIpTargetServerInstanceListRequest internetLineTypeCode(String internetLineTypeCode) {
		this.internetLineTypeCode = internetLineTypeCode;
		return this;
	}

	 /**
	 * 인터넷라인구분코드
	 * @return internetLineTypeCode
	**/
	public String getInternetLineTypeCode() {
		return internetLineTypeCode;
	}

	public void setInternetLineTypeCode(String internetLineTypeCode) {
		this.internetLineTypeCode = internetLineTypeCode;
	}

	public GetPublicIpTargetServerInstanceListRequest regionNo(String regionNo) {
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

	public GetPublicIpTargetServerInstanceListRequest zoneNo(String zoneNo) {
		this.zoneNo = zoneNo;
		return this;
	}

	 /**
	 * ZONE번호
	 * @return zoneNo
	**/
	public String getZoneNo() {
		return zoneNo;
	}

	public void setZoneNo(String zoneNo) {
		this.zoneNo = zoneNo;
	}

	public GetPublicIpTargetServerInstanceListRequest responseFormatType(String responseFormatType) {
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
		GetPublicIpTargetServerInstanceListRequest getPublicIpTargetServerInstanceListRequest = (GetPublicIpTargetServerInstanceListRequest) o;
		return Objects.equals(this.internetLineTypeCode, getPublicIpTargetServerInstanceListRequest.internetLineTypeCode) &&
				Objects.equals(this.regionNo, getPublicIpTargetServerInstanceListRequest.regionNo) &&
				Objects.equals(this.zoneNo, getPublicIpTargetServerInstanceListRequest.zoneNo) &&
				Objects.equals(this.responseFormatType, getPublicIpTargetServerInstanceListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(internetLineTypeCode, regionNo, zoneNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetPublicIpTargetServerInstanceListRequest {\n");
		
		sb.append("		internetLineTypeCode: ").append(toIndentedString(internetLineTypeCode)).append("\n");
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

