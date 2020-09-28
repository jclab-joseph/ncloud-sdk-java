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
import com.ncloud.server.model.RootPasswordServerInstanceParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * GetRootPasswordServerInstanceListRequest
 */
public class GetRootPasswordServerInstanceListRequest {
	private List<RootPasswordServerInstanceParameter> rootPasswordServerInstanceList = new ArrayList<RootPasswordServerInstanceParameter>();

	private String responseFormatType = null;

	public GetRootPasswordServerInstanceListRequest rootPasswordServerInstanceList(List<RootPasswordServerInstanceParameter> rootPasswordServerInstanceList) {
		this.rootPasswordServerInstanceList = rootPasswordServerInstanceList;
		return this;
	}

	public GetRootPasswordServerInstanceListRequest addRootPasswordServerInstanceListItem(RootPasswordServerInstanceParameter rootPasswordServerInstanceListItem) {
		this.rootPasswordServerInstanceList.add(rootPasswordServerInstanceListItem);
		return this;
	}

	 /**
	 * 인스턴스태그리스트
	 * @return rootPasswordServerInstanceList
	**/
	public List<RootPasswordServerInstanceParameter> getRootPasswordServerInstanceList() {
		return rootPasswordServerInstanceList;
	}

	public void setRootPasswordServerInstanceList(List<RootPasswordServerInstanceParameter> rootPasswordServerInstanceList) {
		this.rootPasswordServerInstanceList = rootPasswordServerInstanceList;
	}

	public GetRootPasswordServerInstanceListRequest responseFormatType(String responseFormatType) {
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
		GetRootPasswordServerInstanceListRequest getRootPasswordServerInstanceListRequest = (GetRootPasswordServerInstanceListRequest) o;
		return Objects.equals(this.rootPasswordServerInstanceList, getRootPasswordServerInstanceListRequest.rootPasswordServerInstanceList) &&
				Objects.equals(this.responseFormatType, getRootPasswordServerInstanceListRequest.responseFormatType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rootPasswordServerInstanceList, responseFormatType);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class GetRootPasswordServerInstanceListRequest {\n");
		
		sb.append("		rootPasswordServerInstanceList: ").append(toIndentedString(rootPasswordServerInstanceList)).append("\n");
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

