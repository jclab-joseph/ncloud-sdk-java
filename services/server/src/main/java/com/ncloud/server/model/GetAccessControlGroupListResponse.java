/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2020-09-09T12:03:56Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;
import com.ncloud.server.model.AccessControlGroup;
import java.util.ArrayList;
import java.util.List;

/**
 * GetAccessControlGroupListResponse
 */
public class GetAccessControlGroupListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<AccessControlGroup> accessControlGroupList = null;

	public GetAccessControlGroupListResponse requestId(String requestId) {
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

	public GetAccessControlGroupListResponse returnCode(String returnCode) {
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

	public GetAccessControlGroupListResponse returnMessage(String returnMessage) {
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

	public GetAccessControlGroupListResponse totalRows(Integer totalRows) {
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

	public GetAccessControlGroupListResponse accessControlGroupList(List<AccessControlGroup> accessControlGroupList) {
		this.accessControlGroupList = accessControlGroupList;
		return this;
	}

	public GetAccessControlGroupListResponse addAccessControlGroupListItem(AccessControlGroup accessControlGroupListItem) {
		if (this.accessControlGroupList == null) {
			this.accessControlGroupList = new ArrayList<AccessControlGroup>();
		}
		this.accessControlGroupList.add(accessControlGroupListItem);
		return this;
	}

	 /**
	 * Get accessControlGroupList
	 * @return accessControlGroupList
	**/
	public List<AccessControlGroup> getAccessControlGroupList() {
		return accessControlGroupList;
	}

	public void setAccessControlGroupList(List<AccessControlGroup> accessControlGroupList) {
		this.accessControlGroupList = accessControlGroupList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetAccessControlGroupListResponse getAccessControlGroupListResponse = (GetAccessControlGroupListResponse) o;
		return Objects.equals(this.requestId, getAccessControlGroupListResponse.requestId) &&
				Objects.equals(this.returnCode, getAccessControlGroupListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getAccessControlGroupListResponse.returnMessage) &&
				Objects.equals(this.totalRows, getAccessControlGroupListResponse.totalRows) &&
				Objects.equals(this.accessControlGroupList, getAccessControlGroupListResponse.accessControlGroupList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, accessControlGroupList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetAccessControlGroupListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		accessControlGroupList: ").append(toIndentedString(accessControlGroupList)).append("\n");
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

