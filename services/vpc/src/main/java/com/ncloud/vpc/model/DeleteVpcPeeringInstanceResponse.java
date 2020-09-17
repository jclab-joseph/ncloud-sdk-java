/*
 * vpc
 * VPC Network 관련 API<br/>https://ncloud.apigw.ntruss.com/vpc/v2
 *
 * OpenAPI spec version: 2020-09-17T02:27:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vpc.model;

import java.util.Objects;
import com.ncloud.vpc.model.VpcPeeringInstance;
import java.util.ArrayList;
import java.util.List;

/**
 * DeleteVpcPeeringInstanceResponse
 */
public class DeleteVpcPeeringInstanceResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private Integer totalRows = null;

	private List<VpcPeeringInstance> vpcPeeringInstanceList = null;

	public DeleteVpcPeeringInstanceResponse requestId(String requestId) {
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

	public DeleteVpcPeeringInstanceResponse returnCode(String returnCode) {
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

	public DeleteVpcPeeringInstanceResponse returnMessage(String returnMessage) {
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

	public DeleteVpcPeeringInstanceResponse totalRows(Integer totalRows) {
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

	public DeleteVpcPeeringInstanceResponse vpcPeeringInstanceList(List<VpcPeeringInstance> vpcPeeringInstanceList) {
		this.vpcPeeringInstanceList = vpcPeeringInstanceList;
		return this;
	}

	public DeleteVpcPeeringInstanceResponse addVpcPeeringInstanceListItem(VpcPeeringInstance vpcPeeringInstanceListItem) {
		if (this.vpcPeeringInstanceList == null) {
			this.vpcPeeringInstanceList = new ArrayList<VpcPeeringInstance>();
		}
		this.vpcPeeringInstanceList.add(vpcPeeringInstanceListItem);
		return this;
	}

	 /**
	 * Get vpcPeeringInstanceList
	 * @return vpcPeeringInstanceList
	**/
	public List<VpcPeeringInstance> getVpcPeeringInstanceList() {
		return vpcPeeringInstanceList;
	}

	public void setVpcPeeringInstanceList(List<VpcPeeringInstance> vpcPeeringInstanceList) {
		this.vpcPeeringInstanceList = vpcPeeringInstanceList;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DeleteVpcPeeringInstanceResponse deleteVpcPeeringInstanceResponse = (DeleteVpcPeeringInstanceResponse) o;
		return Objects.equals(this.requestId, deleteVpcPeeringInstanceResponse.requestId) &&
				Objects.equals(this.returnCode, deleteVpcPeeringInstanceResponse.returnCode) &&
				Objects.equals(this.returnMessage, deleteVpcPeeringInstanceResponse.returnMessage) &&
				Objects.equals(this.totalRows, deleteVpcPeeringInstanceResponse.totalRows) &&
				Objects.equals(this.vpcPeeringInstanceList, deleteVpcPeeringInstanceResponse.vpcPeeringInstanceList);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, totalRows, vpcPeeringInstanceList);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class DeleteVpcPeeringInstanceResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
		sb.append("		vpcPeeringInstanceList: ").append(toIndentedString(vpcPeeringInstanceList)).append("\n");
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

