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
 * UpdateAutoScalingGroupRequest
 */
public class UpdateAutoScalingGroupRequest {
	private String autoScalingGroupName = null;

	private String launchConfigurationName = null;

	private Integer desiredCapacity = null;

	private Integer minSize = null;

	private Integer maxSize = null;

	private Integer defaultCooldown = null;

	private Integer healthCheckGracePeriod = null;

	private String healthCheckTypeCode = null;

	private List<String> zoneNoList = null;

	private String responseFormatType = null;

	public UpdateAutoScalingGroupRequest autoScalingGroupName(String autoScalingGroupName) {
		this.autoScalingGroupName = autoScalingGroupName;
		return this;
	}

	 /**
	 * 오토스케일링그룹명
	 * @return autoScalingGroupName
	**/
	public String getAutoScalingGroupName() {
		return autoScalingGroupName;
	}

	public void setAutoScalingGroupName(String autoScalingGroupName) {
		this.autoScalingGroupName = autoScalingGroupName;
	}

	public UpdateAutoScalingGroupRequest launchConfigurationName(String launchConfigurationName) {
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

	public UpdateAutoScalingGroupRequest desiredCapacity(Integer desiredCapacity) {
		this.desiredCapacity = desiredCapacity;
		return this;
	}

	 /**
	 * 기대용량치
	 * @return desiredCapacity
	**/
	public Integer getDesiredCapacity() {
		return desiredCapacity;
	}

	public void setDesiredCapacity(Integer desiredCapacity) {
		this.desiredCapacity = desiredCapacity;
	}

	public UpdateAutoScalingGroupRequest minSize(Integer minSize) {
		this.minSize = minSize;
		return this;
	}

	 /**
	 * 최소사이즈
	 * @return minSize
	**/
	public Integer getMinSize() {
		return minSize;
	}

	public void setMinSize(Integer minSize) {
		this.minSize = minSize;
	}

	public UpdateAutoScalingGroupRequest maxSize(Integer maxSize) {
		this.maxSize = maxSize;
		return this;
	}

	 /**
	 * 최대사이즈
	 * @return maxSize
	**/
	public Integer getMaxSize() {
		return maxSize;
	}

	public void setMaxSize(Integer maxSize) {
		this.maxSize = maxSize;
	}

	public UpdateAutoScalingGroupRequest defaultCooldown(Integer defaultCooldown) {
		this.defaultCooldown = defaultCooldown;
		return this;
	}

	 /**
	 * 디폴트쿨다운타임
	 * @return defaultCooldown
	**/
	public Integer getDefaultCooldown() {
		return defaultCooldown;
	}

	public void setDefaultCooldown(Integer defaultCooldown) {
		this.defaultCooldown = defaultCooldown;
	}

	public UpdateAutoScalingGroupRequest healthCheckGracePeriod(Integer healthCheckGracePeriod) {
		this.healthCheckGracePeriod = healthCheckGracePeriod;
		return this;
	}

	 /**
	 * 헬스체크보류기간
	 * @return healthCheckGracePeriod
	**/
	public Integer getHealthCheckGracePeriod() {
		return healthCheckGracePeriod;
	}

	public void setHealthCheckGracePeriod(Integer healthCheckGracePeriod) {
		this.healthCheckGracePeriod = healthCheckGracePeriod;
	}

	public UpdateAutoScalingGroupRequest healthCheckTypeCode(String healthCheckTypeCode) {
		this.healthCheckTypeCode = healthCheckTypeCode;
		return this;
	}

	 /**
	 * 헬스체크유형코드
	 * @return healthCheckTypeCode
	**/
	public String getHealthCheckTypeCode() {
		return healthCheckTypeCode;
	}

	public void setHealthCheckTypeCode(String healthCheckTypeCode) {
		this.healthCheckTypeCode = healthCheckTypeCode;
	}

	public UpdateAutoScalingGroupRequest zoneNoList(List<String> zoneNoList) {
		this.zoneNoList = zoneNoList;
		return this;
	}

	public UpdateAutoScalingGroupRequest addZoneNoListItem(String zoneNoListItem) {
		if (this.zoneNoList == null) {
			this.zoneNoList = new ArrayList<String>();
		}
		this.zoneNoList.add(zoneNoListItem);
		return this;
	}

	 /**
	 * ZONE번호리스트
	 * @return zoneNoList
	**/
	public List<String> getZoneNoList() {
		return zoneNoList;
	}

	public void setZoneNoList(List<String> zoneNoList) {
		this.zoneNoList = zoneNoList;
	}

	public UpdateAutoScalingGroupRequest responseFormatType(String responseFormatType) {
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
		UpdateAutoScalingGroupRequest updateAutoScalingGroupRequest = (UpdateAutoScalingGroupRequest) o;
		return Objects.equals(this.autoScalingGroupName, updateAutoScalingGroupRequest.autoScalingGroupName) &&
				Objects.equals(this.launchConfigurationName, updateAutoScalingGroupRequest.launchConfigurationName) &&
				Objects.equals(this.desiredCapacity, updateAutoScalingGroupRequest.desiredCapacity) &&
				Objects.equals(this.minSize, updateAutoScalingGroupRequest.minSize) &&
				Objects.equals(this.maxSize, updateAutoScalingGroupRequest.maxSize) &&
				Objects.equals(this.defaultCooldown, updateAutoScalingGroupRequest.defaultCooldown) &&
				Objects.equals(this.healthCheckGracePeriod, updateAutoScalingGroupRequest.healthCheckGracePeriod) &&
				Objects.equals(this.healthCheckTypeCode, updateAutoScalingGroupRequest.healthCheckTypeCode) &&
				Objects.equals(this.zoneNoList, updateAutoScalingGroupRequest.zoneNoList) &&
				Objects.equals(this.responseFormatType, updateAutoScalingGroupRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(autoScalingGroupName, launchConfigurationName, desiredCapacity, minSize, maxSize, defaultCooldown, healthCheckGracePeriod, healthCheckTypeCode, zoneNoList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class UpdateAutoScalingGroupRequest {\n");
		
		sb.append("		autoScalingGroupName: ").append(toIndentedString(autoScalingGroupName)).append("\n");
		sb.append("		launchConfigurationName: ").append(toIndentedString(launchConfigurationName)).append("\n");
		sb.append("		desiredCapacity: ").append(toIndentedString(desiredCapacity)).append("\n");
		sb.append("		minSize: ").append(toIndentedString(minSize)).append("\n");
		sb.append("		maxSize: ").append(toIndentedString(maxSize)).append("\n");
		sb.append("		defaultCooldown: ").append(toIndentedString(defaultCooldown)).append("\n");
		sb.append("		healthCheckGracePeriod: ").append(toIndentedString(healthCheckGracePeriod)).append("\n");
		sb.append("		healthCheckTypeCode: ").append(toIndentedString(healthCheckTypeCode)).append("\n");
		sb.append("		zoneNoList: ").append(toIndentedString(zoneNoList)).append("\n");
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

