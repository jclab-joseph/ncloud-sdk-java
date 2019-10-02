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
import com.ncloud.loadbalancer.model.SslCertificate;
import java.util.ArrayList;
import java.util.List;

/**
 * DeleteLoadBalancerSslCertificateResponse
 */
public class DeleteLoadBalancerSslCertificateResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<SslCertificate> sslCertificateList = null;

	public DeleteLoadBalancerSslCertificateResponse requestId(String requestId) {
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

	public DeleteLoadBalancerSslCertificateResponse returnCode(String returnCode) {
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

	public DeleteLoadBalancerSslCertificateResponse returnMessage(String returnMessage) {
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

	public DeleteLoadBalancerSslCertificateResponse totalRows(Integer totalRows) {
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

	public DeleteLoadBalancerSslCertificateResponse sslCertificateList(List<SslCertificate> sslCertificateList) {
		this.sslCertificateList = sslCertificateList;
		return this;
	}

	public DeleteLoadBalancerSslCertificateResponse addSslCertificateListItem(SslCertificate sslCertificateListItem) {
		if (this.sslCertificateList == null) {
			this.sslCertificateList = new ArrayList<SslCertificate>();
		}
		this.sslCertificateList.add(sslCertificateListItem);
		return this;
	}

	 /**
	 * Get sslCertificateList
	 * @return sslCertificateList
	**/
	public List<SslCertificate> getSslCertificateList() {
		return sslCertificateList;
	}

	public void setSslCertificateList(List<SslCertificate> sslCertificateList) {
		this.sslCertificateList = sslCertificateList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DeleteLoadBalancerSslCertificateResponse deleteLoadBalancerSslCertificateResponse = (DeleteLoadBalancerSslCertificateResponse) o;
		return Objects.equals(this.requestId, deleteLoadBalancerSslCertificateResponse.requestId) &&
				Objects.equals(this.returnCode, deleteLoadBalancerSslCertificateResponse.returnCode) &&
				Objects.equals(this.returnMessage, deleteLoadBalancerSslCertificateResponse.returnMessage) &&
				Objects.equals(this.totalRows, deleteLoadBalancerSslCertificateResponse.totalRows) &&
				Objects.equals(this.sslCertificateList, deleteLoadBalancerSslCertificateResponse.sslCertificateList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, sslCertificateList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeleteLoadBalancerSslCertificateResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		sslCertificateList: ").append(toIndentedString(sslCertificateList)).append("\n");
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

