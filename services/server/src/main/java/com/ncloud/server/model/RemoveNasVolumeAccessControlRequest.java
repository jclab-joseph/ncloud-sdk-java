/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2019-10-17T10:28:43Z
 *
 * NBP corp.
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;
import java.util.ArrayList;
import java.util.List;

/**
 * RemoveNasVolumeAccessControlRequest
 */
public class RemoveNasVolumeAccessControlRequest {
	private String nasVolumeInstanceNo = null;

	private List<String> serverInstanceNoList = null;

	private List<String> customIpList = null;

	private String responseFormatType = null;

	public RemoveNasVolumeAccessControlRequest nasVolumeInstanceNo(String nasVolumeInstanceNo) {
		this.nasVolumeInstanceNo = nasVolumeInstanceNo;
		return this;
	}

	 /**
	 * NAS볼륨인스턴스번호
	 * @return nasVolumeInstanceNo
	**/
	public String getNasVolumeInstanceNo() {
		return nasVolumeInstanceNo;
	}

	public void setNasVolumeInstanceNo(String nasVolumeInstanceNo) {
		this.nasVolumeInstanceNo = nasVolumeInstanceNo;
	}

	public RemoveNasVolumeAccessControlRequest serverInstanceNoList(List<String> serverInstanceNoList) {
		this.serverInstanceNoList = serverInstanceNoList;
		return this;
	}

	public RemoveNasVolumeAccessControlRequest addServerInstanceNoListItem(String serverInstanceNoListItem) {
		if (this.serverInstanceNoList == null) {
			this.serverInstanceNoList = new ArrayList<String>();
		}
		this.serverInstanceNoList.add(serverInstanceNoListItem);
		return this;
	}

	 /**
	 * 서버인스턴스번호리스트
	 * @return serverInstanceNoList
	**/
	public List<String> getServerInstanceNoList() {
		return serverInstanceNoList;
	}

	public void setServerInstanceNoList(List<String> serverInstanceNoList) {
		this.serverInstanceNoList = serverInstanceNoList;
	}

	public RemoveNasVolumeAccessControlRequest customIpList(List<String> customIpList) {
		this.customIpList = customIpList;
		return this;
	}

	public RemoveNasVolumeAccessControlRequest addCustomIpListItem(String customIpListItem) {
		if (this.customIpList == null) {
			this.customIpList = new ArrayList<String>();
		}
		this.customIpList.add(customIpListItem);
		return this;
	}

	 /**
	 * 커스텀IP리스트
	 * @return customIpList
	**/
	public List<String> getCustomIpList() {
		return customIpList;
	}

	public void setCustomIpList(List<String> customIpList) {
		this.customIpList = customIpList;
	}

	public RemoveNasVolumeAccessControlRequest responseFormatType(String responseFormatType) {
		this.responseFormatType = responseFormatType;
		return this;
	}

	 /**
	 * responseFormatType {json, xml}
	 * @return responseFormatType
	**/
	public String getResponseFormatType() {
		return responseFormatType;
	}

	public void setResponseFormatType(String responseFormatType) {
		this.responseFormatType = responseFormatType;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		RemoveNasVolumeAccessControlRequest removeNasVolumeAccessControlRequest = (RemoveNasVolumeAccessControlRequest) o;
		return Objects.equals(this.nasVolumeInstanceNo, removeNasVolumeAccessControlRequest.nasVolumeInstanceNo) &&
				Objects.equals(this.serverInstanceNoList, removeNasVolumeAccessControlRequest.serverInstanceNoList) &&
				Objects.equals(this.customIpList, removeNasVolumeAccessControlRequest.customIpList) &&
				Objects.equals(this.responseFormatType, removeNasVolumeAccessControlRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nasVolumeInstanceNo, serverInstanceNoList, customIpList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class RemoveNasVolumeAccessControlRequest {\n");
		
		sb.append("		nasVolumeInstanceNo: ").append(toIndentedString(nasVolumeInstanceNo)).append("\n");
		sb.append("		serverInstanceNoList: ").append(toIndentedString(serverInstanceNoList)).append("\n");
		sb.append("		customIpList: ").append(toIndentedString(customIpList)).append("\n");
		sb.append("		responseFormatType: ").append(toIndentedString(responseFormatType)).append("\n");
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

