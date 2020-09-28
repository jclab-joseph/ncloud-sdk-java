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
import com.ncloud.server.model.MemberServerImage;
import java.util.ArrayList;
import java.util.List;

/**
 * CreateMemberServerImageResponse
 */
public class CreateMemberServerImageResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<MemberServerImage> memberServerImageList = null;

	public CreateMemberServerImageResponse requestId(String requestId) {
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

	public CreateMemberServerImageResponse returnCode(String returnCode) {
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

	public CreateMemberServerImageResponse returnMessage(String returnMessage) {
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

	public CreateMemberServerImageResponse totalRows(Integer totalRows) {
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

	public CreateMemberServerImageResponse memberServerImageList(List<MemberServerImage> memberServerImageList) {
		this.memberServerImageList = memberServerImageList;
		return this;
	}

	public CreateMemberServerImageResponse addMemberServerImageListItem(MemberServerImage memberServerImageListItem) {
		if (this.memberServerImageList == null) {
			this.memberServerImageList = new ArrayList<MemberServerImage>();
		}
		this.memberServerImageList.add(memberServerImageListItem);
		return this;
	}

	 /**
	 * Get memberServerImageList
	 * @return memberServerImageList
	**/
	public List<MemberServerImage> getMemberServerImageList() {
		return memberServerImageList;
	}

	public void setMemberServerImageList(List<MemberServerImage> memberServerImageList) {
		this.memberServerImageList = memberServerImageList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		CreateMemberServerImageResponse createMemberServerImageResponse = (CreateMemberServerImageResponse) o;
		return Objects.equals(this.requestId, createMemberServerImageResponse.requestId) &&
				Objects.equals(this.returnCode, createMemberServerImageResponse.returnCode) &&
				Objects.equals(this.returnMessage, createMemberServerImageResponse.returnMessage) &&
				Objects.equals(this.totalRows, createMemberServerImageResponse.totalRows) &&
				Objects.equals(this.memberServerImageList, createMemberServerImageResponse.memberServerImageList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, memberServerImageList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class CreateMemberServerImageResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		memberServerImageList: ").append(toIndentedString(memberServerImageList)).append("\n");
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

