/*
 * autoscaling
 * <br/>https://ncloud.apigw.ntruss.com/autoscaling/v2
 *
 * OpenAPI spec version: 2018-11-13T06:27:22Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.autoscaling.model;

import java.util.Objects;
import java.util.ArrayList;
import java.util.List;

/**
 * GetAutoScalingGroupListRequest
 */
public class GetAutoScalingGroupListRequest {
	private List<String> autoScalingGroupNameList = null;

	private Integer pageNo = null;

	private Integer pageSize = null;

	private String sortedBy = null;

	private String sortingOrder = null;

	private String regionNo = null;

	private String responseFormatType = null;

	public GetAutoScalingGroupListRequest autoScalingGroupNameList(List<String> autoScalingGroupNameList) {
		this.autoScalingGroupNameList = autoScalingGroupNameList;
		return this;
	}

	public GetAutoScalingGroupListRequest addAutoScalingGroupNameListItem(String autoScalingGroupNameListItem) {
		if (this.autoScalingGroupNameList == null) {
			this.autoScalingGroupNameList = new ArrayList<String>();
		}
		this.autoScalingGroupNameList.add(autoScalingGroupNameListItem);
		return this;
	}

	 /**
	 * 오토스케일링그룹명리스트
	 * @return autoScalingGroupNameList
	**/
	public List<String> getAutoScalingGroupNameList() {
		return autoScalingGroupNameList;
	}

	public void setAutoScalingGroupNameList(List<String> autoScalingGroupNameList) {
		this.autoScalingGroupNameList = autoScalingGroupNameList;
	}

	public GetAutoScalingGroupListRequest pageNo(Integer pageNo) {
		this.pageNo = pageNo;
		return this;
	}

	 /**
	 * 페이지번호
	 * @return pageNo
	**/
	public Integer getPageNo() {
		return pageNo;
	}

	public void setPageNo(Integer pageNo) {
		this.pageNo = pageNo;
	}

	public GetAutoScalingGroupListRequest pageSize(Integer pageSize) {
		this.pageSize = pageSize;
		return this;
	}

	 /**
	 * 페이지사이즈
	 * @return pageSize
	**/
	public Integer getPageSize() {
		return pageSize;
	}

	public void setPageSize(Integer pageSize) {
		this.pageSize = pageSize;
	}

	public GetAutoScalingGroupListRequest sortedBy(String sortedBy) {
		this.sortedBy = sortedBy;
		return this;
	}

	 /**
	 * 소팅대상
	 * @return sortedBy
	**/
	public String getSortedBy() {
		return sortedBy;
	}

	public void setSortedBy(String sortedBy) {
		this.sortedBy = sortedBy;
	}

	public GetAutoScalingGroupListRequest sortingOrder(String sortingOrder) {
		this.sortingOrder = sortingOrder;
		return this;
	}

	 /**
	 * 소팅순서
	 * @return sortingOrder
	**/
	public String getSortingOrder() {
		return sortingOrder;
	}

	public void setSortingOrder(String sortingOrder) {
		this.sortingOrder = sortingOrder;
	}

	public GetAutoScalingGroupListRequest regionNo(String regionNo) {
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

	public GetAutoScalingGroupListRequest responseFormatType(String responseFormatType) {
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
		GetAutoScalingGroupListRequest getAutoScalingGroupListRequest = (GetAutoScalingGroupListRequest) o;
		return Objects.equals(this.autoScalingGroupNameList, getAutoScalingGroupListRequest.autoScalingGroupNameList) &&
				Objects.equals(this.pageNo, getAutoScalingGroupListRequest.pageNo) &&
				Objects.equals(this.pageSize, getAutoScalingGroupListRequest.pageSize) &&
				Objects.equals(this.sortedBy, getAutoScalingGroupListRequest.sortedBy) &&
				Objects.equals(this.sortingOrder, getAutoScalingGroupListRequest.sortingOrder) &&
				Objects.equals(this.regionNo, getAutoScalingGroupListRequest.regionNo) &&
				Objects.equals(this.responseFormatType, getAutoScalingGroupListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(autoScalingGroupNameList, pageNo, pageSize, sortedBy, sortingOrder, regionNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetAutoScalingGroupListRequest {\n");
		
		sb.append("		autoScalingGroupNameList: ").append(toIndentedString(autoScalingGroupNameList)).append("\n");
		sb.append("		pageNo: ").append(toIndentedString(pageNo)).append("\n");
		sb.append("		pageSize: ").append(toIndentedString(pageSize)).append("\n");
		sb.append("		sortedBy: ").append(toIndentedString(sortedBy)).append("\n");
		sb.append("		sortingOrder: ").append(toIndentedString(sortingOrder)).append("\n");
		sb.append("		regionNo: ").append(toIndentedString(regionNo)).append("\n");
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

