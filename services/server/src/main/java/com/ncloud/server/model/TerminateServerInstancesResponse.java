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
import com.ncloud.server.model.ServerInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * TerminateServerInstancesResponse
 */
public class TerminateServerInstancesResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<ServerInstance> serverInstanceList = null;

	public TerminateServerInstancesResponse requestId(String requestId) {
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

	public TerminateServerInstancesResponse returnCode(String returnCode) {
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

	public TerminateServerInstancesResponse returnMessage(String returnMessage) {
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

	public TerminateServerInstancesResponse totalRows(Integer totalRows) {
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

	public TerminateServerInstancesResponse serverInstanceList(List<ServerInstance> serverInstanceList) {
		this.serverInstanceList = serverInstanceList;
		return this;
	}

	public TerminateServerInstancesResponse addServerInstanceListItem(ServerInstance serverInstanceListItem) {
		if (this.serverInstanceList == null) {
			this.serverInstanceList = new ArrayList<ServerInstance>();
		}
		this.serverInstanceList.add(serverInstanceListItem);
		return this;
	}

	 /**
	 * Get serverInstanceList
	 * @return serverInstanceList
	**/
	public List<ServerInstance> getServerInstanceList() {
		return serverInstanceList;
	}

	public void setServerInstanceList(List<ServerInstance> serverInstanceList) {
		this.serverInstanceList = serverInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		TerminateServerInstancesResponse terminateServerInstancesResponse = (TerminateServerInstancesResponse) o;
		return Objects.equals(this.requestId, terminateServerInstancesResponse.requestId) &&
				Objects.equals(this.returnCode, terminateServerInstancesResponse.returnCode) &&
				Objects.equals(this.returnMessage, terminateServerInstancesResponse.returnMessage) &&
				Objects.equals(this.totalRows, terminateServerInstancesResponse.totalRows) &&
				Objects.equals(this.serverInstanceList, terminateServerInstancesResponse.serverInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, serverInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class TerminateServerInstancesResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		serverInstanceList: ").append(toIndentedString(serverInstanceList)).append("\n");
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

