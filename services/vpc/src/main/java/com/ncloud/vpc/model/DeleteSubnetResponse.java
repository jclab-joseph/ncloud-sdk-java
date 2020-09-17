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
import com.ncloud.vpc.model.Subnet;
import java.util.ArrayList;
import java.util.List;

/**
 * DeleteSubnetResponse
 */
public class DeleteSubnetResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<Subnet> subnetList = null;

	public DeleteSubnetResponse requestId(String requestId) {
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

	public DeleteSubnetResponse returnCode(String returnCode) {
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

	public DeleteSubnetResponse returnMessage(String returnMessage) {
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

	public DeleteSubnetResponse totalRows(Integer totalRows) {
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

	public DeleteSubnetResponse subnetList(List<Subnet> subnetList) {
		this.subnetList = subnetList;
		return this;
	}

	public DeleteSubnetResponse addSubnetListItem(Subnet subnetListItem) {
		if (this.subnetList == null) {
			this.subnetList = new ArrayList<Subnet>();
		}
		this.subnetList.add(subnetListItem);
		return this;
	}

	 /**
	 * Get subnetList
	 * @return subnetList
	**/
	public List<Subnet> getSubnetList() {
		return subnetList;
	}

	public void setSubnetList(List<Subnet> subnetList) {
		this.subnetList = subnetList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DeleteSubnetResponse deleteSubnetResponse = (DeleteSubnetResponse) o;
		return Objects.equals(this.requestId, deleteSubnetResponse.requestId) &&
				Objects.equals(this.returnCode, deleteSubnetResponse.returnCode) &&
				Objects.equals(this.returnMessage, deleteSubnetResponse.returnMessage) &&
				Objects.equals(this.totalRows, deleteSubnetResponse.totalRows) &&
				Objects.equals(this.subnetList, deleteSubnetResponse.subnetList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, subnetList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeleteSubnetResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		subnetList: ").append(toIndentedString(subnetList)).append("\n");
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

