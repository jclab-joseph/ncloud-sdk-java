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
import com.ncloud.loadbalancer.model.ServerHealthCheckStatus;
import com.ncloud.loadbalancer.model.ServerInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * LoadBalancedServerInstance
 */
public class LoadBalancedServerInstance {
	private ServerInstance serverInstance = null;

	private List<ServerHealthCheckStatus> serverHealthCheckStatusList = null;

	public LoadBalancedServerInstance serverInstance(ServerInstance serverInstance) {
		this.serverInstance = serverInstance;
		return this;
	}

	 /**
	 * 서버인스턴스
	 * @return serverInstance
	**/
	public ServerInstance getServerInstance() {
		return serverInstance;
	}

	public void setServerInstance(ServerInstance serverInstance) {
		this.serverInstance = serverInstance;
	}

	public LoadBalancedServerInstance serverHealthCheckStatusList(List<ServerHealthCheckStatus> serverHealthCheckStatusList) {
		this.serverHealthCheckStatusList = serverHealthCheckStatusList;
		return this;
	}

	public LoadBalancedServerInstance addServerHealthCheckStatusListItem(ServerHealthCheckStatus serverHealthCheckStatusListItem) {
		if (this.serverHealthCheckStatusList == null) {
			this.serverHealthCheckStatusList = new ArrayList<ServerHealthCheckStatus>();
		}
		this.serverHealthCheckStatusList.add(serverHealthCheckStatusListItem);
		return this;
	}

	 /**
	 * 서버헬스체크상태리스트
	 * @return serverHealthCheckStatusList
	**/
	public List<ServerHealthCheckStatus> getServerHealthCheckStatusList() {
		return serverHealthCheckStatusList;
	}

	public void setServerHealthCheckStatusList(List<ServerHealthCheckStatus> serverHealthCheckStatusList) {
		this.serverHealthCheckStatusList = serverHealthCheckStatusList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		LoadBalancedServerInstance loadBalancedServerInstance = (LoadBalancedServerInstance) o;
		return Objects.equals(this.serverInstance, loadBalancedServerInstance.serverInstance) &&
				Objects.equals(this.serverHealthCheckStatusList, loadBalancedServerInstance.serverHealthCheckStatusList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(serverInstance, serverHealthCheckStatusList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class LoadBalancedServerInstance {\n");
		
		sb.append("		serverInstance: ").append(toIndentedString(serverInstance)).append("\n");
		sb.append("		serverHealthCheckStatusList: ").append(toIndentedString(serverHealthCheckStatusList)).append("\n");
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

