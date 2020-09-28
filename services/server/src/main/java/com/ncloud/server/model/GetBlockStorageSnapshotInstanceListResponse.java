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
import com.ncloud.server.model.BlockStorageSnapshotInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * GetBlockStorageSnapshotInstanceListResponse
 */
public class GetBlockStorageSnapshotInstanceListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<BlockStorageSnapshotInstance> blockStorageSnapshotInstanceList = null;

	public GetBlockStorageSnapshotInstanceListResponse requestId(String requestId) {
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

	public GetBlockStorageSnapshotInstanceListResponse returnCode(String returnCode) {
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

	public GetBlockStorageSnapshotInstanceListResponse returnMessage(String returnMessage) {
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

	public GetBlockStorageSnapshotInstanceListResponse totalRows(Integer totalRows) {
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

	public GetBlockStorageSnapshotInstanceListResponse blockStorageSnapshotInstanceList(List<BlockStorageSnapshotInstance> blockStorageSnapshotInstanceList) {
		this.blockStorageSnapshotInstanceList = blockStorageSnapshotInstanceList;
		return this;
	}

	public GetBlockStorageSnapshotInstanceListResponse addBlockStorageSnapshotInstanceListItem(BlockStorageSnapshotInstance blockStorageSnapshotInstanceListItem) {
		if (this.blockStorageSnapshotInstanceList == null) {
			this.blockStorageSnapshotInstanceList = new ArrayList<BlockStorageSnapshotInstance>();
		}
		this.blockStorageSnapshotInstanceList.add(blockStorageSnapshotInstanceListItem);
		return this;
	}

	 /**
	 * Get blockStorageSnapshotInstanceList
	 * @return blockStorageSnapshotInstanceList
	**/
	public List<BlockStorageSnapshotInstance> getBlockStorageSnapshotInstanceList() {
		return blockStorageSnapshotInstanceList;
	}

	public void setBlockStorageSnapshotInstanceList(List<BlockStorageSnapshotInstance> blockStorageSnapshotInstanceList) {
		this.blockStorageSnapshotInstanceList = blockStorageSnapshotInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetBlockStorageSnapshotInstanceListResponse getBlockStorageSnapshotInstanceListResponse = (GetBlockStorageSnapshotInstanceListResponse) o;
		return Objects.equals(this.requestId, getBlockStorageSnapshotInstanceListResponse.requestId) &&
				Objects.equals(this.returnCode, getBlockStorageSnapshotInstanceListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getBlockStorageSnapshotInstanceListResponse.returnMessage) &&
				Objects.equals(this.totalRows, getBlockStorageSnapshotInstanceListResponse.totalRows) &&
				Objects.equals(this.blockStorageSnapshotInstanceList, getBlockStorageSnapshotInstanceListResponse.blockStorageSnapshotInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, blockStorageSnapshotInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetBlockStorageSnapshotInstanceListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		blockStorageSnapshotInstanceList: ").append(toIndentedString(blockStorageSnapshotInstanceList)).append("\n");
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

