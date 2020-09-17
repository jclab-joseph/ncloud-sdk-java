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
import com.ncloud.vserver.model.MemberServerImageInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * DeleteMemberServerImageInstancesResponse
 */
public class DeleteMemberServerImageInstancesResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<MemberServerImageInstance> memberServerImageInstanceList = null;

	public DeleteMemberServerImageInstancesResponse requestId(String requestId) {
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

	public DeleteMemberServerImageInstancesResponse returnCode(String returnCode) {
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

	public DeleteMemberServerImageInstancesResponse returnMessage(String returnMessage) {
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

	public DeleteMemberServerImageInstancesResponse totalRows(Integer totalRows) {
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

	public DeleteMemberServerImageInstancesResponse memberServerImageInstanceList(List<MemberServerImageInstance> memberServerImageInstanceList) {
		this.memberServerImageInstanceList = memberServerImageInstanceList;
		return this;
	}

	public DeleteMemberServerImageInstancesResponse addMemberServerImageInstanceListItem(MemberServerImageInstance memberServerImageInstanceListItem) {
		if (this.memberServerImageInstanceList == null) {
			this.memberServerImageInstanceList = new ArrayList<MemberServerImageInstance>();
		}
		this.memberServerImageInstanceList.add(memberServerImageInstanceListItem);
		return this;
	}

	 /**
	 * Get memberServerImageInstanceList
	 * @return memberServerImageInstanceList
	**/
	public List<MemberServerImageInstance> getMemberServerImageInstanceList() {
		return memberServerImageInstanceList;
	}

	public void setMemberServerImageInstanceList(List<MemberServerImageInstance> memberServerImageInstanceList) {
		this.memberServerImageInstanceList = memberServerImageInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DeleteMemberServerImageInstancesResponse deleteMemberServerImageInstancesResponse = (DeleteMemberServerImageInstancesResponse) o;
		return Objects.equals(this.requestId, deleteMemberServerImageInstancesResponse.requestId) &&
				Objects.equals(this.returnCode, deleteMemberServerImageInstancesResponse.returnCode) &&
				Objects.equals(this.returnMessage, deleteMemberServerImageInstancesResponse.returnMessage) &&
				Objects.equals(this.totalRows, deleteMemberServerImageInstancesResponse.totalRows) &&
				Objects.equals(this.memberServerImageInstanceList, deleteMemberServerImageInstancesResponse.memberServerImageInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, memberServerImageInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeleteMemberServerImageInstancesResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		memberServerImageInstanceList: ").append(toIndentedString(memberServerImageInstanceList)).append("\n");
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

