/*
 * loadbalancer
 * <br/>https://ncloud.apigw.ntruss.com/loadbalancer/v2
 *
 * OpenAPI spec version: 2018-11-13T06:25:36Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.loadbalancer.model;

import java.util.Objects;
import java.util.ArrayList;
import java.util.List;

/**
 * GetLoadBalancerInstanceListRequest
 */
public class GetLoadBalancerInstanceListRequest {
	private List<String> loadBalancerInstanceNoList = null;

	private String internetLineTypeCode = null;

	private String networkUsageTypeCode = null;

	private String regionNo = null;

	private Integer pageNo = null;

	private Integer pageSize = null;

	private String sortedBy = null;

	private String sortingOrder = null;

	private String responseFormatType = null;

	public GetLoadBalancerInstanceListRequest loadBalancerInstanceNoList(List<String> loadBalancerInstanceNoList) {
		this.loadBalancerInstanceNoList = loadBalancerInstanceNoList;
		return this;
	}

	public GetLoadBalancerInstanceListRequest addLoadBalancerInstanceNoListItem(String loadBalancerInstanceNoListItem) {
		if (this.loadBalancerInstanceNoList == null) {
			this.loadBalancerInstanceNoList = new ArrayList<String>();
		}
		this.loadBalancerInstanceNoList.add(loadBalancerInstanceNoListItem);
		return this;
	}

	 /**
	 * 로드밸런서인스턴스번호리스트
	 * @return loadBalancerInstanceNoList
	**/
	public List<String> getLoadBalancerInstanceNoList() {
		return loadBalancerInstanceNoList;
	}

	public void setLoadBalancerInstanceNoList(List<String> loadBalancerInstanceNoList) {
		this.loadBalancerInstanceNoList = loadBalancerInstanceNoList;
	}

	public GetLoadBalancerInstanceListRequest internetLineTypeCode(String internetLineTypeCode) {
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

	public GetLoadBalancerInstanceListRequest networkUsageTypeCode(String networkUsageTypeCode) {
		this.networkUsageTypeCode = networkUsageTypeCode;
		return this;
	}

	 /**
	 * 네트워크 구분코드
	 * @return networkUsageTypeCode
	**/
	public String getNetworkUsageTypeCode() {
		return networkUsageTypeCode;
	}

	public void setNetworkUsageTypeCode(String networkUsageTypeCode) {
		this.networkUsageTypeCode = networkUsageTypeCode;
	}

	public GetLoadBalancerInstanceListRequest regionNo(String regionNo) {
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

	public GetLoadBalancerInstanceListRequest pageNo(Integer pageNo) {
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

	public GetLoadBalancerInstanceListRequest pageSize(Integer pageSize) {
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

	public GetLoadBalancerInstanceListRequest sortedBy(String sortedBy) {
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

	public GetLoadBalancerInstanceListRequest sortingOrder(String sortingOrder) {
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

	public GetLoadBalancerInstanceListRequest responseFormatType(String responseFormatType) {
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
		GetLoadBalancerInstanceListRequest getLoadBalancerInstanceListRequest = (GetLoadBalancerInstanceListRequest) o;
		return Objects.equals(this.loadBalancerInstanceNoList, getLoadBalancerInstanceListRequest.loadBalancerInstanceNoList) &&
				Objects.equals(this.internetLineTypeCode, getLoadBalancerInstanceListRequest.internetLineTypeCode) &&
				Objects.equals(this.networkUsageTypeCode, getLoadBalancerInstanceListRequest.networkUsageTypeCode) &&
				Objects.equals(this.regionNo, getLoadBalancerInstanceListRequest.regionNo) &&
				Objects.equals(this.pageNo, getLoadBalancerInstanceListRequest.pageNo) &&
				Objects.equals(this.pageSize, getLoadBalancerInstanceListRequest.pageSize) &&
				Objects.equals(this.sortedBy, getLoadBalancerInstanceListRequest.sortedBy) &&
				Objects.equals(this.sortingOrder, getLoadBalancerInstanceListRequest.sortingOrder) &&
				Objects.equals(this.responseFormatType, getLoadBalancerInstanceListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(loadBalancerInstanceNoList, internetLineTypeCode, networkUsageTypeCode, regionNo, pageNo, pageSize, sortedBy, sortingOrder, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetLoadBalancerInstanceListRequest {\n");
		
		sb.append("		loadBalancerInstanceNoList: ").append(toIndentedString(loadBalancerInstanceNoList)).append("\n");
		sb.append("		internetLineTypeCode: ").append(toIndentedString(internetLineTypeCode)).append("\n");
		sb.append("		networkUsageTypeCode: ").append(toIndentedString(networkUsageTypeCode)).append("\n");
		sb.append("		regionNo: ").append(toIndentedString(regionNo)).append("\n");
		sb.append("		pageNo: ").append(toIndentedString(pageNo)).append("\n");
		sb.append("		pageSize: ").append(toIndentedString(pageSize)).append("\n");
		sb.append("		sortedBy: ").append(toIndentedString(sortedBy)).append("\n");
		sb.append("		sortingOrder: ").append(toIndentedString(sortingOrder)).append("\n");
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

