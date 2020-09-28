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
import java.util.ArrayList;
import java.util.List;

/**
 * SetNasVolumeAccessControlRequest
 */
public class SetNasVolumeAccessControlRequest {
	private String nasVolumeInstanceNo = null;

	private List<String> serverInstanceNoList = null;

	private List<String> customIpList = null;

	private String responseFormatType = null;

	public SetNasVolumeAccessControlRequest nasVolumeInstanceNo(String nasVolumeInstanceNo) {
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

	public SetNasVolumeAccessControlRequest serverInstanceNoList(List<String> serverInstanceNoList) {
		this.serverInstanceNoList = serverInstanceNoList;
		return this;
	}

	public SetNasVolumeAccessControlRequest addServerInstanceNoListItem(String serverInstanceNoListItem) {
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

	public SetNasVolumeAccessControlRequest customIpList(List<String> customIpList) {
		this.customIpList = customIpList;
		return this;
	}

	public SetNasVolumeAccessControlRequest addCustomIpListItem(String customIpListItem) {
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

	public SetNasVolumeAccessControlRequest responseFormatType(String responseFormatType) {
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
		SetNasVolumeAccessControlRequest setNasVolumeAccessControlRequest = (SetNasVolumeAccessControlRequest) o;
		return Objects.equals(this.nasVolumeInstanceNo, setNasVolumeAccessControlRequest.nasVolumeInstanceNo) &&
				Objects.equals(this.serverInstanceNoList, setNasVolumeAccessControlRequest.serverInstanceNoList) &&
				Objects.equals(this.customIpList, setNasVolumeAccessControlRequest.customIpList) &&
				Objects.equals(this.responseFormatType, setNasVolumeAccessControlRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(nasVolumeInstanceNo, serverInstanceNoList, customIpList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class SetNasVolumeAccessControlRequest {\n");
		
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

