/*
 * autoscaling
 * <br/>https://ncloud.apigw.ntruss.com/autoscaling/v2
 *
 * OpenAPI spec version: 2018-11-13T06:27:22Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.autoscaling.model;

import java.util.Objects;
import java.util.ArrayList;
import java.util.List;

/**
 * CreateLaunchConfigurationRequest
 */
public class CreateLaunchConfigurationRequest {
	private String launchConfigurationName = null;

	private String serverImageProductCode = null;

	private String serverProductCode = null;

	private String memberServerImageNo = null;

	private List<String> accessControlGroupConfigurationNoList = null;

	private String loginKeyName = null;

	private String userData = null;

	private String regionNo = null;

	private String responseFormatType = null;

	public CreateLaunchConfigurationRequest launchConfigurationName(String launchConfigurationName) {
		this.launchConfigurationName = launchConfigurationName;
		return this;
	}

	 /**
	 * 론치설정명
	 * @return launchConfigurationName
	**/
	public String getLaunchConfigurationName() {
		return launchConfigurationName;
	}

	public void setLaunchConfigurationName(String launchConfigurationName) {
		this.launchConfigurationName = launchConfigurationName;
	}

	public CreateLaunchConfigurationRequest serverImageProductCode(String serverImageProductCode) {
		this.serverImageProductCode = serverImageProductCode;
		return this;
	}

	 /**
	 * 소프트웨어상품코드
	 * @return serverImageProductCode
	**/
	public String getServerImageProductCode() {
		return serverImageProductCode;
	}

	public void setServerImageProductCode(String serverImageProductCode) {
		this.serverImageProductCode = serverImageProductCode;
	}

	public CreateLaunchConfigurationRequest serverProductCode(String serverProductCode) {
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

	public CreateLaunchConfigurationRequest memberServerImageNo(String memberServerImageNo) {
		this.memberServerImageNo = memberServerImageNo;
		return this;
	}

	 /**
	 * 회원서버이미지번호
	 * @return memberServerImageNo
	**/
	public String getMemberServerImageNo() {
		return memberServerImageNo;
	}

	public void setMemberServerImageNo(String memberServerImageNo) {
		this.memberServerImageNo = memberServerImageNo;
	}

	public CreateLaunchConfigurationRequest accessControlGroupConfigurationNoList(List<String> accessControlGroupConfigurationNoList) {
		this.accessControlGroupConfigurationNoList = accessControlGroupConfigurationNoList;
		return this;
	}

	public CreateLaunchConfigurationRequest addAccessControlGroupConfigurationNoListItem(String accessControlGroupConfigurationNoListItem) {
		if (this.accessControlGroupConfigurationNoList == null) {
			this.accessControlGroupConfigurationNoList = new ArrayList<String>();
		}
		this.accessControlGroupConfigurationNoList.add(accessControlGroupConfigurationNoListItem);
		return this;
	}

	 /**
	 * ACG설정번호리스트
	 * @return accessControlGroupConfigurationNoList
	**/
	public List<String> getAccessControlGroupConfigurationNoList() {
		return accessControlGroupConfigurationNoList;
	}

	public void setAccessControlGroupConfigurationNoList(List<String> accessControlGroupConfigurationNoList) {
		this.accessControlGroupConfigurationNoList = accessControlGroupConfigurationNoList;
	}

	public CreateLaunchConfigurationRequest loginKeyName(String loginKeyName) {
		this.loginKeyName = loginKeyName;
		return this;
	}

	 /**
	 * 로그인키명
	 * @return loginKeyName
	**/
	public String getLoginKeyName() {
		return loginKeyName;
	}

	public void setLoginKeyName(String loginKeyName) {
		this.loginKeyName = loginKeyName;
	}

	public CreateLaunchConfigurationRequest userData(String userData) {
		this.userData = userData;
		return this;
	}

	 /**
	 * 사용자데이터
	 * @return userData
	**/
	public String getUserData() {
		return userData;
	}

	public void setUserData(String userData) {
		this.userData = userData;
	}

	public CreateLaunchConfigurationRequest regionNo(String regionNo) {
		this.regionNo = regionNo;
		return this;
	}

	 /**
	 * 리전번호
	 * @return regionNo
	**/
	public String getRegionNo() {
		return regionNo;
	}

	public void setRegionNo(String regionNo) {
		this.regionNo = regionNo;
	}

	public CreateLaunchConfigurationRequest responseFormatType(String responseFormatType) {
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
		CreateLaunchConfigurationRequest createLaunchConfigurationRequest = (CreateLaunchConfigurationRequest) o;
		return Objects.equals(this.launchConfigurationName, createLaunchConfigurationRequest.launchConfigurationName) &&
				Objects.equals(this.serverImageProductCode, createLaunchConfigurationRequest.serverImageProductCode) &&
				Objects.equals(this.serverProductCode, createLaunchConfigurationRequest.serverProductCode) &&
				Objects.equals(this.memberServerImageNo, createLaunchConfigurationRequest.memberServerImageNo) &&
				Objects.equals(this.accessControlGroupConfigurationNoList, createLaunchConfigurationRequest.accessControlGroupConfigurationNoList) &&
				Objects.equals(this.loginKeyName, createLaunchConfigurationRequest.loginKeyName) &&
				Objects.equals(this.userData, createLaunchConfigurationRequest.userData) &&
				Objects.equals(this.regionNo, createLaunchConfigurationRequest.regionNo) &&
				Objects.equals(this.responseFormatType, createLaunchConfigurationRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(launchConfigurationName, serverImageProductCode, serverProductCode, memberServerImageNo, accessControlGroupConfigurationNoList, loginKeyName, userData, regionNo, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class CreateLaunchConfigurationRequest {\n");
		
		sb.append("		launchConfigurationName: ").append(toIndentedString(launchConfigurationName)).append("\n");
		sb.append("		serverImageProductCode: ").append(toIndentedString(serverImageProductCode)).append("\n");
		sb.append("		serverProductCode: ").append(toIndentedString(serverProductCode)).append("\n");
		sb.append("		memberServerImageNo: ").append(toIndentedString(memberServerImageNo)).append("\n");
		sb.append("		accessControlGroupConfigurationNoList: ").append(toIndentedString(accessControlGroupConfigurationNoList)).append("\n");
		sb.append("		loginKeyName: ").append(toIndentedString(loginKeyName)).append("\n");
		sb.append("		userData: ").append(toIndentedString(userData)).append("\n");
		sb.append("		regionNo: ").append(toIndentedString(regionNo)).append("\n");
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

