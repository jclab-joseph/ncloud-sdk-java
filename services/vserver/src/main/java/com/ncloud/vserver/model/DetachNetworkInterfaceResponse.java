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
import com.ncloud.vserver.model.NetworkInterface;
import java.util.ArrayList;
import java.util.List;

/**
 * DetachNetworkInterfaceResponse
 */
public class DetachNetworkInterfaceResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<NetworkInterface> networkInterfaceList = null;

	public DetachNetworkInterfaceResponse requestId(String requestId) {
		this.requestId = requestId;
		return this;
	}

	 /**
	 * Get requestId
	 * @return requestId
	**/
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public DetachNetworkInterfaceResponse returnCode(String returnCode) {
		this.returnCode = returnCode;
		return this;
	}

	 /**
	 * Get returnCode
	 * @return returnCode
	**/
	public String getReturnCode() {
		return returnCode;
	}

	public void setReturnCode(String returnCode) {
		this.returnCode = returnCode;
	}

	public DetachNetworkInterfaceResponse returnMessage(String returnMessage) {
		this.returnMessage = returnMessage;
		return this;
	}

	 /**
	 * Get returnMessage
	 * @return returnMessage
	**/
	public String getReturnMessage() {
		return returnMessage;
	}

	public void setReturnMessage(String returnMessage) {
		this.returnMessage = returnMessage;
	}

	public DetachNetworkInterfaceResponse totalRows(Integer totalRows) {
		this.totalRows = totalRows;
		return this;
	}

	 /**
	 * Get totalRows
	 * @return totalRows
	**/
	public Integer getTotalRows() {
		return totalRows;
	}

	public void setTotalRows(Integer totalRows) {
		this.totalRows = totalRows;
	}

	public DetachNetworkInterfaceResponse networkInterfaceList(List<NetworkInterface> networkInterfaceList) {
		this.networkInterfaceList = networkInterfaceList;
		return this;
	}

	public DetachNetworkInterfaceResponse addNetworkInterfaceListItem(NetworkInterface networkInterfaceListItem) {
		if (this.networkInterfaceList == null) {
			this.networkInterfaceList = new ArrayList<NetworkInterface>();
		}
		this.networkInterfaceList.add(networkInterfaceListItem);
		return this;
	}

	 /**
	 * Get networkInterfaceList
	 * @return networkInterfaceList
	**/
	public List<NetworkInterface> getNetworkInterfaceList() {
		return networkInterfaceList;
	}

	public void setNetworkInterfaceList(List<NetworkInterface> networkInterfaceList) {
		this.networkInterfaceList = networkInterfaceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DetachNetworkInterfaceResponse detachNetworkInterfaceResponse = (DetachNetworkInterfaceResponse) o;
		return Objects.equals(this.requestId, detachNetworkInterfaceResponse.requestId) &&
				Objects.equals(this.returnCode, detachNetworkInterfaceResponse.returnCode) &&
				Objects.equals(this.returnMessage, detachNetworkInterfaceResponse.returnMessage) &&
				Objects.equals(this.totalRows, detachNetworkInterfaceResponse.totalRows) &&
				Objects.equals(this.networkInterfaceList, detachNetworkInterfaceResponse.networkInterfaceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, networkInterfaceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DetachNetworkInterfaceResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		networkInterfaceList: ").append(toIndentedString(networkInterfaceList)).append("\n");
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

