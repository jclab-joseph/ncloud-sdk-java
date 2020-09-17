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
 * GetRouteTableListRequest
 */
public class GetRouteTableListRequest {
	private String regionCode = null;

	private List<String> routeTableNoList = null;

	private String routeTableName = null;

	private String supportedSubnetTypeCode = null;

	private Integer pageNo = null;

	private Integer pageSize = null;

	private String sortedBy = null;

	private String sortingOrder = null;

	private String vpcNo = null;

	private String responseFormatType = null;

	public GetRouteTableListRequest regionCode(String regionCode) {
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

	public GetRouteTableListRequest routeTableNoList(List<String> routeTableNoList) {
		this.routeTableNoList = routeTableNoList;
		return this;
	}

	public GetRouteTableListRequest addRouteTableNoListItem(String routeTableNoListItem) {
		if (this.routeTableNoList == null) {
			this.routeTableNoList = new ArrayList<String>();
		}
		this.routeTableNoList.add(routeTableNoListItem);
		return this;
	}

	 /**
	 * 라우트테이블번호리스트
	 * @return routeTableNoList
	**/
	public List<String> getRouteTableNoList() {
		return routeTableNoList;
	}

	public void setRouteTableNoList(List<String> routeTableNoList) {
		this.routeTableNoList = routeTableNoList;
	}

	public GetRouteTableListRequest routeTableName(String routeTableName) {
		this.routeTableName = routeTableName;
		return this;
	}

	 /**
	 * 라우트테이블이름
	 * @return routeTableName
	**/
	public String getRouteTableName() {
		return routeTableName;
	}

	public void setRouteTableName(String routeTableName) {
		this.routeTableName = routeTableName;
	}

	public GetRouteTableListRequest supportedSubnetTypeCode(String supportedSubnetTypeCode) {
		this.supportedSubnetTypeCode = supportedSubnetTypeCode;
		return this;
	}

	 /**
	 * 지원하는서브넷유형코드
	 * @return supportedSubnetTypeCode
	**/
	public String getSupportedSubnetTypeCode() {
		return supportedSubnetTypeCode;
	}

	public void setSupportedSubnetTypeCode(String supportedSubnetTypeCode) {
		this.supportedSubnetTypeCode = supportedSubnetTypeCode;
	}

	public GetRouteTableListRequest pageNo(Integer pageNo) {
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

	public GetRouteTableListRequest pageSize(Integer pageSize) {
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

	public GetRouteTableListRequest sortedBy(String sortedBy) {
		this.sortedBy = sortedBy;
		return this;
	}

	 /**
	 * 정렬대상
	 * @return sortedBy
	**/
	public String getSortedBy() {
		return sortedBy;
	}

	public void setSortedBy(String sortedBy) {
		this.sortedBy = sortedBy;
	}

	public GetRouteTableListRequest sortingOrder(String sortingOrder) {
		this.sortingOrder = sortingOrder;
		return this;
	}

	 /**
	 * 정렬순서
	 * @return sortingOrder
	**/
	public String getSortingOrder() {
		return sortingOrder;
	}

	public void setSortingOrder(String sortingOrder) {
		this.sortingOrder = sortingOrder;
	}

	public GetRouteTableListRequest vpcNo(String vpcNo) {
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

	public GetRouteTableListRequest responseFormatType(String responseFormatType) {
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
		GetRouteTableListRequest getRouteTableListRequest = (GetRouteTableListRequest) o;
		return Objects.equals(this.regionCode, getRouteTableListRequest.regionCode) &&
				Objects.equals(this.routeTableNoList, getRouteTableListRequest.routeTableNoList) &&
				Objects.equals(this.routeTableName, getRouteTableListRequest.routeTableName) &&
				Objects.equals(this.supportedSubnetTypeCode, getRouteTableListRequest.supportedSubnetTypeCode) &&
				Objects.equals(this.pageNo, getRouteTableListRequest.pageNo) &&
				Objects.equals(this.pageSize, getRouteTableListRequest.pageSize) &&
				Objects.equals(this.sortedBy, getRouteTableListRequest.sortedBy) &&
				Objects.equals(this.sortingOrder, getRouteTableListRequest.sortingOrder) &&
				Objects.equals(this.vpcNo, getRouteTableListRequest.vpcNo) &&
				Objects.equals(this.responseFormatType, getRouteTableListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, routeTableNoList, routeTableName, supportedSubnetTypeCode, pageNo, pageSize, sortedBy, sortingOrder, vpcNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetRouteTableListRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		routeTableNoList: ").append(toIndentedString(routeTableNoList)).append("\n");
		sb.append("		routeTableName: ").append(toIndentedString(routeTableName)).append("\n");
		sb.append("		supportedSubnetTypeCode: ").append(toIndentedString(supportedSubnetTypeCode)).append("\n");
		sb.append("		pageNo: ").append(toIndentedString(pageNo)).append("\n");
		sb.append("		pageSize: ").append(toIndentedString(pageSize)).append("\n");
		sb.append("		sortedBy: ").append(toIndentedString(sortedBy)).append("\n");
		sb.append("		sortingOrder: ").append(toIndentedString(sortingOrder)).append("\n");
		sb.append("		vpcNo: ").append(toIndentedString(vpcNo)).append("\n");
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

