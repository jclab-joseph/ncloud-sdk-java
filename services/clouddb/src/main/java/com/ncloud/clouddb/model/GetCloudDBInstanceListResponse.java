/*
 * clouddb
 * Cloud DB<br/>https://ncloud.apigw.ntruss.com/clouddb/v2
 *
 * OpenAPI spec version: 2018-11-13T06:30:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.clouddb.model;

import java.util.Objects;
import com.ncloud.clouddb.model.CloudDBInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * GetCloudDBInstanceListResponse
 */
public class GetCloudDBInstanceListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<CloudDBInstance> cloudDBInstanceList = null;

	public GetCloudDBInstanceListResponse requestId(String requestId) {
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

	public GetCloudDBInstanceListResponse returnCode(String returnCode) {
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

	public GetCloudDBInstanceListResponse returnMessage(String returnMessage) {
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

	public GetCloudDBInstanceListResponse totalRows(Integer totalRows) {
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

	public GetCloudDBInstanceListResponse cloudDBInstanceList(List<CloudDBInstance> cloudDBInstanceList) {
		this.cloudDBInstanceList = cloudDBInstanceList;
		return this;
	}

	public GetCloudDBInstanceListResponse addCloudDBInstanceListItem(CloudDBInstance cloudDBInstanceListItem) {
		if (this.cloudDBInstanceList == null) {
			this.cloudDBInstanceList = new ArrayList<CloudDBInstance>();
		}
		this.cloudDBInstanceList.add(cloudDBInstanceListItem);
		return this;
	}

	 /**
	 * Get cloudDBInstanceList
	 * @return cloudDBInstanceList
	**/
	public List<CloudDBInstance> getCloudDBInstanceList() {
		return cloudDBInstanceList;
	}

	public void setCloudDBInstanceList(List<CloudDBInstance> cloudDBInstanceList) {
		this.cloudDBInstanceList = cloudDBInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetCloudDBInstanceListResponse getCloudDBInstanceListResponse = (GetCloudDBInstanceListResponse) o;
		return Objects.equals(this.requestId, getCloudDBInstanceListResponse.requestId) &&
				Objects.equals(this.returnCode, getCloudDBInstanceListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getCloudDBInstanceListResponse.returnMessage) &&
				Objects.equals(this.totalRows, getCloudDBInstanceListResponse.totalRows) &&
				Objects.equals(this.cloudDBInstanceList, getCloudDBInstanceListResponse.cloudDBInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, cloudDBInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetCloudDBInstanceListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		cloudDBInstanceList: ").append(toIndentedString(cloudDBInstanceList)).append("\n");
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

