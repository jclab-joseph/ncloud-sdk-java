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
 * DeletePlacementGroupRequest
 */
public class DeletePlacementGroupRequest {
	private String regionCode = null;

	private String placementGroupNo = null;

	private String responseFormatType = null;

	public DeletePlacementGroupRequest regionCode(String regionCode) {
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

	public DeletePlacementGroupRequest placementGroupNo(String placementGroupNo) {
		this.placementGroupNo = placementGroupNo;
		return this;
	}

	 /**
	 * 물리배치그룹번호
	 * @return placementGroupNo
	**/
	public String getPlacementGroupNo() {
		return placementGroupNo;
	}

	public void setPlacementGroupNo(String placementGroupNo) {
		this.placementGroupNo = placementGroupNo;
	}

	public DeletePlacementGroupRequest responseFormatType(String responseFormatType) {
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
		DeletePlacementGroupRequest deletePlacementGroupRequest = (DeletePlacementGroupRequest) o;
		return Objects.equals(this.regionCode, deletePlacementGroupRequest.regionCode) &&
				Objects.equals(this.placementGroupNo, deletePlacementGroupRequest.placementGroupNo) &&
				Objects.equals(this.responseFormatType, deletePlacementGroupRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, placementGroupNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeletePlacementGroupRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		placementGroupNo: ").append(toIndentedString(placementGroupNo)).append("\n");
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

