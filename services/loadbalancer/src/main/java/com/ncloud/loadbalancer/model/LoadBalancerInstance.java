/*
 * loadbalancer
 * <br/>https://ncloud.apigw.ntruss.com/loadbalancer/v2
 *
 * OpenAPI spec version: 2018-11-13T06:25:36Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.loadbalancer.model;

import java.util.Objects;
import com.ncloud.loadbalancer.model.CommonCode;
import com.ncloud.loadbalancer.model.LoadBalancedServerInstance;
import com.ncloud.loadbalancer.model.LoadBalancerRule;
import java.util.ArrayList;
import java.util.List;

/**
 * LoadBalancerInstance
 */
public class LoadBalancerInstance {
	private String loadBalancerInstanceNo = null;

	private String virtualIp = null;

	private String loadBalancerName = null;

	private CommonCode loadBalancerAlgorithmType = null;

	private String loadBalancerDescription = null;

	private String createDate = null;

	private String domainName = null;

	private CommonCode internetLineType = null;

	private String loadBalancerInstanceStatusName = null;

	private CommonCode loadBalancerInstanceStatus = null;

	private CommonCode loadBalancerInstanceOperation = null;

	private CommonCode networkUsageType = null;

	private Boolean isHttpKeepAlive = null;

	private Integer connectionTimeout = null;

	private String certificateName = null;

	private List<LoadBalancerRule> loadBalancerRuleList = null;

	private List<LoadBalancedServerInstance> loadBalancedServerInstanceList = null;

	public LoadBalancerInstance loadBalancerInstanceNo(String loadBalancerInstanceNo) {
		this.loadBalancerInstanceNo = loadBalancerInstanceNo;
		return this;
	}

	 /**
	 * 로드밸런서인스턴스번호
	 * @return loadBalancerInstanceNo
	**/
	public String getLoadBalancerInstanceNo() {
		return loadBalancerInstanceNo;
	}

	public void setLoadBalancerInstanceNo(String loadBalancerInstanceNo) {
		this.loadBalancerInstanceNo = loadBalancerInstanceNo;
	}

	public LoadBalancerInstance virtualIp(String virtualIp) {
		this.virtualIp = virtualIp;
		return this;
	}

	 /**
	 * virtualIp
	 * @return virtualIp
	**/
	public String getVirtualIp() {
		return virtualIp;
	}

	public void setVirtualIp(String virtualIp) {
		this.virtualIp = virtualIp;
	}

	public LoadBalancerInstance loadBalancerName(String loadBalancerName) {
		this.loadBalancerName = loadBalancerName;
		return this;
	}

	 /**
	 * 로드밸런서명
	 * @return loadBalancerName
	**/
	public String getLoadBalancerName() {
		return loadBalancerName;
	}

	public void setLoadBalancerName(String loadBalancerName) {
		this.loadBalancerName = loadBalancerName;
	}

	public LoadBalancerInstance loadBalancerAlgorithmType(CommonCode loadBalancerAlgorithmType) {
		this.loadBalancerAlgorithmType = loadBalancerAlgorithmType;
		return this;
	}

	 /**
	 * 로드밸런서알고리즘구분코
	 * @return loadBalancerAlgorithmType
	**/
	public CommonCode getLoadBalancerAlgorithmType() {
		return loadBalancerAlgorithmType;
	}

	public void setLoadBalancerAlgorithmType(CommonCode loadBalancerAlgorithmType) {
		this.loadBalancerAlgorithmType = loadBalancerAlgorithmType;
	}

	public LoadBalancerInstance loadBalancerDescription(String loadBalancerDescription) {
		this.loadBalancerDescription = loadBalancerDescription;
		return this;
	}

	 /**
	 * 로드밸런서설명
	 * @return loadBalancerDescription
	**/
	public String getLoadBalancerDescription() {
		return loadBalancerDescription;
	}

	public void setLoadBalancerDescription(String loadBalancerDescription) {
		this.loadBalancerDescription = loadBalancerDescription;
	}

	public LoadBalancerInstance createDate(String createDate) {
		this.createDate = createDate;
		return this;
	}

	 /**
	 * 생성일자
	 * @return createDate
	**/
	public String getCreateDate() {
		return createDate;
	}

	public void setCreateDate(String createDate) {
		this.createDate = createDate;
	}

	public LoadBalancerInstance domainName(String domainName) {
		this.domainName = domainName;
		return this;
	}

	 /**
	 * 도메인명
	 * @return domainName
	**/
	public String getDomainName() {
		return domainName;
	}

	public void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	public LoadBalancerInstance internetLineType(CommonCode internetLineType) {
		this.internetLineType = internetLineType;
		return this;
	}

	 /**
	 * 인터넷회선구분
	 * @return internetLineType
	**/
	public CommonCode getInternetLineType() {
		return internetLineType;
	}

	public void setInternetLineType(CommonCode internetLineType) {
		this.internetLineType = internetLineType;
	}

	public LoadBalancerInstance loadBalancerInstanceStatusName(String loadBalancerInstanceStatusName) {
		this.loadBalancerInstanceStatusName = loadBalancerInstanceStatusName;
		return this;
	}

	 /**
	 * 로드밸런서인스턴스상태명
	 * @return loadBalancerInstanceStatusName
	**/
	public String getLoadBalancerInstanceStatusName() {
		return loadBalancerInstanceStatusName;
	}

	public void setLoadBalancerInstanceStatusName(String loadBalancerInstanceStatusName) {
		this.loadBalancerInstanceStatusName = loadBalancerInstanceStatusName;
	}

	public LoadBalancerInstance loadBalancerInstanceStatus(CommonCode loadBalancerInstanceStatus) {
		this.loadBalancerInstanceStatus = loadBalancerInstanceStatus;
		return this;
	}

	 /**
	 * 로드밸런서인스턴스상태
	 * @return loadBalancerInstanceStatus
	**/
	public CommonCode getLoadBalancerInstanceStatus() {
		return loadBalancerInstanceStatus;
	}

	public void setLoadBalancerInstanceStatus(CommonCode loadBalancerInstanceStatus) {
		this.loadBalancerInstanceStatus = loadBalancerInstanceStatus;
	}

	public LoadBalancerInstance loadBalancerInstanceOperation(CommonCode loadBalancerInstanceOperation) {
		this.loadBalancerInstanceOperation = loadBalancerInstanceOperation;
		return this;
	}

	 /**
	 * 로드밸런서인스턴스OP
	 * @return loadBalancerInstanceOperation
	**/
	public CommonCode getLoadBalancerInstanceOperation() {
		return loadBalancerInstanceOperation;
	}

	public void setLoadBalancerInstanceOperation(CommonCode loadBalancerInstanceOperation) {
		this.loadBalancerInstanceOperation = loadBalancerInstanceOperation;
	}

	public LoadBalancerInstance networkUsageType(CommonCode networkUsageType) {
		this.networkUsageType = networkUsageType;
		return this;
	}

	 /**
	 * 네트워크사용구분
	 * @return networkUsageType
	**/
	public CommonCode getNetworkUsageType() {
		return networkUsageType;
	}

	public void setNetworkUsageType(CommonCode networkUsageType) {
		this.networkUsageType = networkUsageType;
	}

	public LoadBalancerInstance isHttpKeepAlive(Boolean isHttpKeepAlive) {
		this.isHttpKeepAlive = isHttpKeepAlive;
		return this;
	}

	 /**
	 * httpKeepAlive사용여부
	 * @return isHttpKeepAlive
	**/
	public Boolean isIsHttpKeepAlive() {
		return isHttpKeepAlive;
	}

	public void setIsHttpKeepAlive(Boolean isHttpKeepAlive) {
		this.isHttpKeepAlive = isHttpKeepAlive;
	}

	public LoadBalancerInstance connectionTimeout(Integer connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
		return this;
	}

	 /**
	 * 커넥션타임아웃
	 * @return connectionTimeout
	**/
	public Integer getConnectionTimeout() {
		return connectionTimeout;
	}

	public void setConnectionTimeout(Integer connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}

	public LoadBalancerInstance certificateName(String certificateName) {
		this.certificateName = certificateName;
		return this;
	}

	 /**
	 * SSL인증명
	 * @return certificateName
	**/
	public String getCertificateName() {
		return certificateName;
	}

	public void setCertificateName(String certificateName) {
		this.certificateName = certificateName;
	}

	public LoadBalancerInstance loadBalancerRuleList(List<LoadBalancerRule> loadBalancerRuleList) {
		this.loadBalancerRuleList = loadBalancerRuleList;
		return this;
	}

	public LoadBalancerInstance addLoadBalancerRuleListItem(LoadBalancerRule loadBalancerRuleListItem) {
		if (this.loadBalancerRuleList == null) {
			this.loadBalancerRuleList = new ArrayList<LoadBalancerRule>();
		}
		this.loadBalancerRuleList.add(loadBalancerRuleListItem);
		return this;
	}

	 /**
	 * Get loadBalancerRuleList
	 * @return loadBalancerRuleList
	**/
	public List<LoadBalancerRule> getLoadBalancerRuleList() {
		return loadBalancerRuleList;
	}

	public void setLoadBalancerRuleList(List<LoadBalancerRule> loadBalancerRuleList) {
		this.loadBalancerRuleList = loadBalancerRuleList;
	}

	public LoadBalancerInstance loadBalancedServerInstanceList(List<LoadBalancedServerInstance> loadBalancedServerInstanceList) {
		this.loadBalancedServerInstanceList = loadBalancedServerInstanceList;
		return this;
	}

	public LoadBalancerInstance addLoadBalancedServerInstanceListItem(LoadBalancedServerInstance loadBalancedServerInstanceListItem) {
		if (this.loadBalancedServerInstanceList == null) {
			this.loadBalancedServerInstanceList = new ArrayList<LoadBalancedServerInstance>();
		}
		this.loadBalancedServerInstanceList.add(loadBalancedServerInstanceListItem);
		return this;
	}

	 /**
	 * Get loadBalancedServerInstanceList
	 * @return loadBalancedServerInstanceList
	**/
	public List<LoadBalancedServerInstance> getLoadBalancedServerInstanceList() {
		return loadBalancedServerInstanceList;
	}

	public void setLoadBalancedServerInstanceList(List<LoadBalancedServerInstance> loadBalancedServerInstanceList) {
		this.loadBalancedServerInstanceList = loadBalancedServerInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		LoadBalancerInstance loadBalancerInstance = (LoadBalancerInstance) o;
		return Objects.equals(this.loadBalancerInstanceNo, loadBalancerInstance.loadBalancerInstanceNo) &&
				Objects.equals(this.virtualIp, loadBalancerInstance.virtualIp) &&
				Objects.equals(this.loadBalancerName, loadBalancerInstance.loadBalancerName) &&
				Objects.equals(this.loadBalancerAlgorithmType, loadBalancerInstance.loadBalancerAlgorithmType) &&
				Objects.equals(this.loadBalancerDescription, loadBalancerInstance.loadBalancerDescription) &&
				Objects.equals(this.createDate, loadBalancerInstance.createDate) &&
				Objects.equals(this.domainName, loadBalancerInstance.domainName) &&
				Objects.equals(this.internetLineType, loadBalancerInstance.internetLineType) &&
				Objects.equals(this.loadBalancerInstanceStatusName, loadBalancerInstance.loadBalancerInstanceStatusName) &&
				Objects.equals(this.loadBalancerInstanceStatus, loadBalancerInstance.loadBalancerInstanceStatus) &&
				Objects.equals(this.loadBalancerInstanceOperation, loadBalancerInstance.loadBalancerInstanceOperation) &&
				Objects.equals(this.networkUsageType, loadBalancerInstance.networkUsageType) &&
				Objects.equals(this.isHttpKeepAlive, loadBalancerInstance.isHttpKeepAlive) &&
				Objects.equals(this.connectionTimeout, loadBalancerInstance.connectionTimeout) &&
				Objects.equals(this.certificateName, loadBalancerInstance.certificateName) &&
				Objects.equals(this.loadBalancerRuleList, loadBalancerInstance.loadBalancerRuleList) &&
				Objects.equals(this.loadBalancedServerInstanceList, loadBalancerInstance.loadBalancedServerInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(loadBalancerInstanceNo, virtualIp, loadBalancerName, loadBalancerAlgorithmType, loadBalancerDescription, createDate, domainName, internetLineType, loadBalancerInstanceStatusName, loadBalancerInstanceStatus, loadBalancerInstanceOperation, networkUsageType, isHttpKeepAlive, connectionTimeout, certificateName, loadBalancerRuleList, loadBalancedServerInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class LoadBalancerInstance {\n");
		
		sb.append("		loadBalancerInstanceNo: ").append(toIndentedString(loadBalancerInstanceNo)).append("\n");
		sb.append("		virtualIp: ").append(toIndentedString(virtualIp)).append("\n");
		sb.append("		loadBalancerName: ").append(toIndentedString(loadBalancerName)).append("\n");
		sb.append("		loadBalancerAlgorithmType: ").append(toIndentedString(loadBalancerAlgorithmType)).append("\n");
		sb.append("		loadBalancerDescription: ").append(toIndentedString(loadBalancerDescription)).append("\n");
		sb.append("		createDate: ").append(toIndentedString(createDate)).append("\n");
		sb.append("		domainName: ").append(toIndentedString(domainName)).append("\n");
		sb.append("		internetLineType: ").append(toIndentedString(internetLineType)).append("\n");
		sb.append("		loadBalancerInstanceStatusName: ").append(toIndentedString(loadBalancerInstanceStatusName)).append("\n");
		sb.append("		loadBalancerInstanceStatus: ").append(toIndentedString(loadBalancerInstanceStatus)).append("\n");
		sb.append("		loadBalancerInstanceOperation: ").append(toIndentedString(loadBalancerInstanceOperation)).append("\n");
		sb.append("		networkUsageType: ").append(toIndentedString(networkUsageType)).append("\n");
		sb.append("		isHttpKeepAlive: ").append(toIndentedString(isHttpKeepAlive)).append("\n");
		sb.append("		connectionTimeout: ").append(toIndentedString(connectionTimeout)).append("\n");
		sb.append("		certificateName: ").append(toIndentedString(certificateName)).append("\n");
		sb.append("		loadBalancerRuleList: ").append(toIndentedString(loadBalancerRuleList)).append("\n");
		sb.append("		loadBalancedServerInstanceList: ").append(toIndentedString(loadBalancedServerInstanceList)).append("\n");
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

