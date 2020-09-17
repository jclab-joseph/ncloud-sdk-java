/*
 * vnas
 * VPC NAS 관련 API<br/>https://ncloud.apigw.ntruss.com/vnas/v2
 *
 * OpenAPI spec version: 2020-09-17T02:28:41Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vnas.model;

import java.util.Objects;
import com.ncloud.vnas.model.NasVolumeInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * RemoveNasVolumeAccessControlResponse
 */
public class RemoveNasVolumeAccessControlResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<NasVolumeInstance> nasVolumeInstanceList = null;

	public RemoveNasVolumeAccessControlResponse requestId(String requestId) {
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

	public RemoveNasVolumeAccessControlResponse returnCode(String returnCode) {
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

	public RemoveNasVolumeAccessControlResponse returnMessage(String returnMessage) {
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

	public RemoveNasVolumeAccessControlResponse totalRows(Integer totalRows) {
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

	public RemoveNasVolumeAccessControlResponse nasVolumeInstanceList(List<NasVolumeInstance> nasVolumeInstanceList) {
		this.nasVolumeInstanceList = nasVolumeInstanceList;
		return this;
	}

	public RemoveNasVolumeAccessControlResponse addNasVolumeInstanceListItem(NasVolumeInstance nasVolumeInstanceListItem) {
		if (this.nasVolumeInstanceList == null) {
			this.nasVolumeInstanceList = new ArrayList<NasVolumeInstance>();
		}
		this.nasVolumeInstanceList.add(nasVolumeInstanceListItem);
		return this;
	}

	 /**
	 * Get nasVolumeInstanceList
	 * @return nasVolumeInstanceList
	**/
	public List<NasVolumeInstance> getNasVolumeInstanceList() {
		return nasVolumeInstanceList;
	}

	public void setNasVolumeInstanceList(List<NasVolumeInstance> nasVolumeInstanceList) {
		this.nasVolumeInstanceList = nasVolumeInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		RemoveNasVolumeAccessControlResponse removeNasVolumeAccessControlResponse = (RemoveNasVolumeAccessControlResponse) o;
		return Objects.equals(this.requestId, removeNasVolumeAccessControlResponse.requestId) &&
				Objects.equals(this.returnCode, removeNasVolumeAccessControlResponse.returnCode) &&
				Objects.equals(this.returnMessage, removeNasVolumeAccessControlResponse.returnMessage) &&
				Objects.equals(this.totalRows, removeNasVolumeAccessControlResponse.totalRows) &&
				Objects.equals(this.nasVolumeInstanceList, removeNasVolumeAccessControlResponse.nasVolumeInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, nasVolumeInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class RemoveNasVolumeAccessControlResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		nasVolumeInstanceList: ").append(toIndentedString(nasVolumeInstanceList)).append("\n");
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

