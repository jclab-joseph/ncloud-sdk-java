/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2019-01-25T05:09:58Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;
import com.ncloud.server.model.AccessControlRule;
import java.util.ArrayList;
import java.util.List;

/**
 * GetAccessControlRuleListResponse
 */
public class GetAccessControlRuleListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<AccessControlRule> accessControlRuleList = null;

	public GetAccessControlRuleListResponse requestId(String requestId) {
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

	public GetAccessControlRuleListResponse returnCode(String returnCode) {
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

	public GetAccessControlRuleListResponse returnMessage(String returnMessage) {
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

	public GetAccessControlRuleListResponse totalRows(Integer totalRows) {
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

	public GetAccessControlRuleListResponse accessControlRuleList(List<AccessControlRule> accessControlRuleList) {
		this.accessControlRuleList = accessControlRuleList;
		return this;
	}

	public GetAccessControlRuleListResponse addAccessControlRuleListItem(AccessControlRule accessControlRuleListItem) {
		if (this.accessControlRuleList == null) {
			this.accessControlRuleList = new ArrayList<AccessControlRule>();
		}
		this.accessControlRuleList.add(accessControlRuleListItem);
		return this;
	}

	 /**
	 * Get accessControlRuleList
	 * @return accessControlRuleList
	**/
	public List<AccessControlRule> getAccessControlRuleList() {
		return accessControlRuleList;
	}

	public void setAccessControlRuleList(List<AccessControlRule> accessControlRuleList) {
		this.accessControlRuleList = accessControlRuleList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetAccessControlRuleListResponse getAccessControlRuleListResponse = (GetAccessControlRuleListResponse) o;
		return Objects.equals(this.requestId, getAccessControlRuleListResponse.requestId) &&
				Objects.equals(this.returnCode, getAccessControlRuleListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getAccessControlRuleListResponse.returnMessage) &&
				Objects.equals(this.totalRows, getAccessControlRuleListResponse.totalRows) &&
				Objects.equals(this.accessControlRuleList, getAccessControlRuleListResponse.accessControlRuleList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, accessControlRuleList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetAccessControlRuleListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		accessControlRuleList: ").append(toIndentedString(accessControlRuleList)).append("\n");
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

