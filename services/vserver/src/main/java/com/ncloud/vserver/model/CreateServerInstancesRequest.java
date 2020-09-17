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
import com.ncloud.vserver.model.NetworkInterfaceParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * CreateServerInstancesRequest
 */
public class CreateServerInstancesRequest {
	private String regionCode = null;

	private String serverProductCode = null;

	private String serverImageProductCode = null;

	private String memberServerImageInstanceNo = null;

	private String serverName = null;

	private String serverDescription = null;

	private String loginKeyName = null;

	private Boolean isProtectServerTermination = null;

	private Integer serverCreateCount = null;

	private Integer serverCreateStartNo = null;

	private String feeSystemTypeCode = null;

	private String initScriptNo = null;

	private String vpcNo = null;

	private String subnetNo = null;

	private List<NetworkInterfaceParameter> networkInterfaceList = new ArrayList<NetworkInterfaceParameter>();

	private String placementGroupNo = null;

	private Boolean isEncryptedBaseBlockStorageVolume = null;

	private String responseFormatType = null;

	public CreateServerInstancesRequest regionCode(String regionCode) {
		this.regionCode = regionCode;
		return this;
	}

	 /**
	 * REGION코드
	 * @return regionCode
	**/
	public String getRegionCode() {
		return regionCode;
	}

	public void setRegionCode(String regionCode) {
		this.regionCode = regionCode;
	}

	public CreateServerInstancesRequest serverProductCode(String serverProductCode) {
		this.serverProductCode = serverProductCode;
		return this;
	}

	 /**
	 * 서버상품코드
	 * @return serverProductCode
	**/
	public String getServerProductCode() {
		return serverProductCode;
	}

	public void setServerProductCode(String serverProductCode) {
		this.serverProductCode = serverProductCode;
	}

	public CreateServerInstancesRequest serverImageProductCode(String serverImageProductCode) {
		this.serverImageProductCode = serverImageProductCode;
		return this;
	}

	 /**
	 * 서버이미지상품코드
	 * @return serverImageProductCode
	**/
	public String getServerImageProductCode() {
		return serverImageProductCode;
	}

	public void setServerImageProductCode(String serverImageProductCode) {
		this.serverImageProductCode = serverImageProductCode;
	}

	public CreateServerInstancesRequest memberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스번호
	 * @return memberServerImageInstanceNo
	**/
	public String getMemberServerImageInstanceNo() {
		return memberServerImageInstanceNo;
	}

	public void setMemberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
	}

	public CreateServerInstancesRequest serverName(String serverName) {
		this.serverName = serverName;
		return this;
	}

	 /**
	 * 서버이름
	 * @return serverName
	**/
	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	public CreateServerInstancesRequest serverDescription(String serverDescription) {
		this.serverDescription = serverDescription;
		return this;
	}

	 /**
	 * 서버설명
	 * @return serverDescription
	**/
	public String getServerDescription() {
		return serverDescription;
	}

	public void setServerDescription(String serverDescription) {
		this.serverDescription = serverDescription;
	}

	public CreateServerInstancesRequest loginKeyName(String loginKeyName) {
		this.loginKeyName = loginKeyName;
		return this;
	}

	 /**
	 * 로그인키이름
	 * @return loginKeyName
	**/
	public String getLoginKeyName() {
		return loginKeyName;
	}

	public void setLoginKeyName(String loginKeyName) {
		this.loginKeyName = loginKeyName;
	}

	public CreateServerInstancesRequest isProtectServerTermination(Boolean isProtectServerTermination) {
		this.isProtectServerTermination = isProtectServerTermination;
		return this;
	}

	 /**
	 * 반납보호여부
	 * @return isProtectServerTermination
	**/
	public Boolean isIsProtectServerTermination() {
		return isProtectServerTermination;
	}

	public void setIsProtectServerTermination(Boolean isProtectServerTermination) {
		this.isProtectServerTermination = isProtectServerTermination;
	}

	public CreateServerInstancesRequest serverCreateCount(Integer serverCreateCount) {
		this.serverCreateCount = serverCreateCount;
		return this;
	}

	 /**
	 * 서버생성개수
	 * @return serverCreateCount
	**/
	public Integer getServerCreateCount() {
		return serverCreateCount;
	}

	public void setServerCreateCount(Integer serverCreateCount) {
		this.serverCreateCount = serverCreateCount;
	}

	public CreateServerInstancesRequest serverCreateStartNo(Integer serverCreateStartNo) {
		this.serverCreateStartNo = serverCreateStartNo;
		return this;
	}

	 /**
	 * 서버생성시작번호
	 * @return serverCreateStartNo
	**/
	public Integer getServerCreateStartNo() {
		return serverCreateStartNo;
	}

	public void setServerCreateStartNo(Integer serverCreateStartNo) {
		this.serverCreateStartNo = serverCreateStartNo;
	}

	public CreateServerInstancesRequest feeSystemTypeCode(String feeSystemTypeCode) {
		this.feeSystemTypeCode = feeSystemTypeCode;
		return this;
	}

	 /**
	 * 요금제유형코드
	 * @return feeSystemTypeCode
	**/
	public String getFeeSystemTypeCode() {
		return feeSystemTypeCode;
	}

	public void setFeeSystemTypeCode(String feeSystemTypeCode) {
		this.feeSystemTypeCode = feeSystemTypeCode;
	}

	public CreateServerInstancesRequest initScriptNo(String initScriptNo) {
		this.initScriptNo = initScriptNo;
		return this;
	}

	 /**
	 * 초기화스크립트번호
	 * @return initScriptNo
	**/
	public String getInitScriptNo() {
		return initScriptNo;
	}

	public void setInitScriptNo(String initScriptNo) {
		this.initScriptNo = initScriptNo;
	}

	public CreateServerInstancesRequest vpcNo(String vpcNo) {
		this.vpcNo = vpcNo;
		return this;
	}

	 /**
	 * VPC번호
	 * @return vpcNo
	**/
	public String getVpcNo() {
		return vpcNo;
	}

	public void setVpcNo(String vpcNo) {
		this.vpcNo = vpcNo;
	}

	public CreateServerInstancesRequest subnetNo(String subnetNo) {
		this.subnetNo = subnetNo;
		return this;
	}

	 /**
	 * 서브넷번호
	 * @return subnetNo
	**/
	public String getSubnetNo() {
		return subnetNo;
	}

	public void setSubnetNo(String subnetNo) {
		this.subnetNo = subnetNo;
	}

	public CreateServerInstancesRequest networkInterfaceList(List<NetworkInterfaceParameter> networkInterfaceList) {
		this.networkInterfaceList = networkInterfaceList;
		return this;
	}

	public CreateServerInstancesRequest addNetworkInterfaceListItem(NetworkInterfaceParameter networkInterfaceListItem) {
		this.networkInterfaceList.add(networkInterfaceListItem);
		return this;
	}

	 /**
	 * 네트워크인터페이스리스트
	 * @return networkInterfaceList
	**/
	public List<NetworkInterfaceParameter> getNetworkInterfaceList() {
		return networkInterfaceList;
	}

	public void setNetworkInterfaceList(List<NetworkInterfaceParameter> networkInterfaceList) {
		this.networkInterfaceList = networkInterfaceList;
	}

	public CreateServerInstancesRequest placementGroupNo(String placementGroupNo) {
		this.placementGroupNo = placementGroupNo;
		return this;
	}

	 /**
	 * 물리배치그룹번호
	 * @return placementGroupNo
	**/
	public String getPlacementGroupNo() {
		return placementGroupNo;
	}

	public void setPlacementGroupNo(String placementGroupNo) {
		this.placementGroupNo = placementGroupNo;
	}

	public CreateServerInstancesRequest isEncryptedBaseBlockStorageVolume(Boolean isEncryptedBaseBlockStorageVolume) {
		this.isEncryptedBaseBlockStorageVolume = isEncryptedBaseBlockStorageVolume;
		return this;
	}

	 /**
	 * 기본블록스토리지볼륨암호화여부
	 * @return isEncryptedBaseBlockStorageVolume
	**/
	public Boolean isIsEncryptedBaseBlockStorageVolume() {
		return isEncryptedBaseBlockStorageVolume;
	}

	public void setIsEncryptedBaseBlockStorageVolume(Boolean isEncryptedBaseBlockStorageVolume) {
		this.isEncryptedBaseBlockStorageVolume = isEncryptedBaseBlockStorageVolume;
	}

	public CreateServerInstancesRequest responseFormatType(String responseFormatType) {
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
		CreateServerInstancesRequest createServerInstancesRequest = (CreateServerInstancesRequest) o;
		return Objects.equals(this.regionCode, createServerInstancesRequest.regionCode) &&
				Objects.equals(this.serverProductCode, createServerInstancesRequest.serverProductCode) &&
				Objects.equals(this.serverImageProductCode, createServerInstancesRequest.serverImageProductCode) &&
				Objects.equals(this.memberServerImageInstanceNo, createServerInstancesRequest.memberServerImageInstanceNo) &&
				Objects.equals(this.serverName, createServerInstancesRequest.serverName) &&
				Objects.equals(this.serverDescription, createServerInstancesRequest.serverDescription) &&
				Objects.equals(this.loginKeyName, createServerInstancesRequest.loginKeyName) &&
				Objects.equals(this.isProtectServerTermination, createServerInstancesRequest.isProtectServerTermination) &&
				Objects.equals(this.serverCreateCount, createServerInstancesRequest.serverCreateCount) &&
				Objects.equals(this.serverCreateStartNo, createServerInstancesRequest.serverCreateStartNo) &&
				Objects.equals(this.feeSystemTypeCode, createServerInstancesRequest.feeSystemTypeCode) &&
				Objects.equals(this.initScriptNo, createServerInstancesRequest.initScriptNo) &&
				Objects.equals(this.vpcNo, createServerInstancesRequest.vpcNo) &&
				Objects.equals(this.subnetNo, createServerInstancesRequest.subnetNo) &&
				Objects.equals(this.networkInterfaceList, createServerInstancesRequest.networkInterfaceList) &&
				Objects.equals(this.placementGroupNo, createServerInstancesRequest.placementGroupNo) &&
				Objects.equals(this.isEncryptedBaseBlockStorageVolume, createServerInstancesRequest.isEncryptedBaseBlockStorageVolume) &&
				Objects.equals(this.responseFormatType, createServerInstancesRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(regionCode, serverProductCode, serverImageProductCode, memberServerImageInstanceNo, serverName, serverDescription, loginKeyName, isProtectServerTermination, serverCreateCount, serverCreateStartNo, feeSystemTypeCode, initScriptNo, vpcNo, subnetNo, networkInterfaceList, placementGroupNo, isEncryptedBaseBlockStorageVolume, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class CreateServerInstancesRequest {\n");
		
		sb.append("		regionCode: ").append(toIndentedString(regionCode)).append("\n");
		sb.append("		serverProductCode: ").append(toIndentedString(serverProductCode)).append("\n");
		sb.append("		serverImageProductCode: ").append(toIndentedString(serverImageProductCode)).append("\n");
		sb.append("		memberServerImageInstanceNo: ").append(toIndentedString(memberServerImageInstanceNo)).append("\n");
		sb.append("		serverName: ").append(toIndentedString(serverName)).append("\n");
		sb.append("		serverDescription: ").append(toIndentedString(serverDescription)).append("\n");
		sb.append("		loginKeyName: ").append(toIndentedString(loginKeyName)).append("\n");
		sb.append("		isProtectServerTermination: ").append(toIndentedString(isProtectServerTermination)).append("\n");
		sb.append("		serverCreateCount: ").append(toIndentedString(serverCreateCount)).append("\n");
		sb.append("		serverCreateStartNo: ").append(toIndentedString(serverCreateStartNo)).append("\n");
		sb.append("		feeSystemTypeCode: ").append(toIndentedString(feeSystemTypeCode)).append("\n");
		sb.append("		initScriptNo: ").append(toIndentedString(initScriptNo)).append("\n");
		sb.append("		vpcNo: ").append(toIndentedString(vpcNo)).append("\n");
		sb.append("		subnetNo: ").append(toIndentedString(subnetNo)).append("\n");
		sb.append("		networkInterfaceList: ").append(toIndentedString(networkInterfaceList)).append("\n");
		sb.append("		placementGroupNo: ").append(toIndentedString(placementGroupNo)).append("\n");
		sb.append("		isEncryptedBaseBlockStorageVolume: ").append(toIndentedString(isEncryptedBaseBlockStorageVolume)).append("\n");
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

