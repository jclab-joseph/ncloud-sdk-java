/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2019-01-25T05:09:58Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;
import com.ncloud.server.model.Product;
import java.util.ArrayList;
import java.util.List;

/**
 * GetServerProductListResponse
 */
public class GetServerProductListResponse {
	private String requestId = null;

	private String returnCode = null;

	private String returnMessage = null;

	private List<Product> productList = null;

	private Integer totalRows = null;

	public GetServerProductListResponse requestId(String requestId) {
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

	public GetServerProductListResponse returnCode(String returnCode) {
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

	public GetServerProductListResponse returnMessage(String returnMessage) {
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

	public GetServerProductListResponse productList(List<Product> productList) {
		this.productList = productList;
		return this;
	}

	public GetServerProductListResponse addProductListItem(Product productListItem) {
		if (this.productList == null) {
			this.productList = new ArrayList<Product>();
		}
		this.productList.add(productListItem);
		return this;
	}

	 /**
	 * Get productList
	 * @return productList
	**/
	public List<Product> getProductList() {
		return productList;
	}

	public void setProductList(List<Product> productList) {
		this.productList = productList;
	}

	public GetServerProductListResponse totalRows(Integer totalRows) {
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


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		GetServerProductListResponse getServerProductListResponse = (GetServerProductListResponse) o;
		return Objects.equals(this.requestId, getServerProductListResponse.requestId) &&
				Objects.equals(this.returnCode, getServerProductListResponse.returnCode) &&
				Objects.equals(this.returnMessage, getServerProductListResponse.returnMessage) &&
				Objects.equals(this.productList, getServerProductListResponse.productList) &&
				Objects.equals(this.totalRows, getServerProductListResponse.totalRows);
	}

	@Override
	public int hashCode() {
		return Objects.hash(requestId, returnCode, returnMessage, productList, totalRows);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetServerProductListResponse {\n");
		
		sb.append("		requestId: ").append(toIndentedString(requestId)).append("\n");
		sb.append("		returnCode: ").append(toIndentedString(returnCode)).append("\n");
		sb.append("		returnMessage: ").append(toIndentedString(returnMessage)).append("\n");
		sb.append("		productList: ").append(toIndentedString(productList)).append("\n");
		sb.append("		totalRows: ").append(toIndentedString(totalRows)).append("\n");
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

