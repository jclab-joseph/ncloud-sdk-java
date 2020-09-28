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
import com.ncloud.server.model.InstanceTag;
import java.util.ArrayList;
import java.util.List;

/**
 * GetInstanceTagListResponse
 */
public class GetInstanceTagListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<InstanceTag> instanceTagList = null;

	public GetInstanceTagListResponse requestId(String requestId) {
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

	public GetInstanceTagListResponse returnCode(String returnCode) {
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

	public GetInstanceTagListResponse returnMessage(String returnMessage) {
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

	public GetInstanceTagListResponse totalRows(Integer totalRows) {
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

	public GetInstanceTagListResponse instanceTagList(List<InstanceTag> instanceTagList) {
		this.instanceTagList = instanceTagList;
		return this;
	}

	public GetInstanceTagListResponse addInstanceTagListItem(InstanceTag instanceTagListItem) {
		if (this.instanceTagList == null) {
			this.instanceTagList = new ArrayList<InstanceTag>();
		}
		this.instanceTagList.add(instanceTagListItem);
		return this;
	}

	 /**
	 * Get instanceTagList
	 * @return instanceTagList
	**/
	public List<InstanceTag> getInstanceTagList() {
		return instanceTagList;
	}

	public void setInstanceTagList(List<InstanceTag> instanceTagList) {
		this.instanceTagList = instanceTagList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetInstanceTagListResponse getInstanceTagListResponse = (GetInstanceTagListResponse) o;
		return Objects.equals(this.requestId, getInstanceTagListResponse.requestId) &&
				Objects.equals(this.returnCode, getInstanceTagListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getInstanceTagListResponse.returnMessage) &&
				Objects.equals(this.totalRows, getInstanceTagListResponse.totalRows) &&
				Objects.equals(this.instanceTagList, getInstanceTagListResponse.instanceTagList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, instanceTagList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetInstanceTagListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		instanceTagList: ").append(toIndentedString(instanceTagList)).append("\n");
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

