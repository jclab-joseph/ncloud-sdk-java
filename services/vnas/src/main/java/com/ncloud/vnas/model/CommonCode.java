/*
 * vnas
 * VPC NAS 관련 API<br/>https://ncloud.apigw.ntruss.com/vnas/v2
 *
 * OpenAPI spec version: 2020-09-17T02:28:41Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vnas.model;

import java.util.Objects;

/**
 * CommonCode
 */
public class CommonCode {
	private String code = null;

	private String codeName = null;

	public CommonCode code(String code) {
		this.code = code;
		return this;
	}

	 /**
	 * 코드
	 * @return code
	**/
	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public CommonCode codeName(String codeName) {
		this.codeName = codeName;
		return this;
	}

	 /**
	 * 코드명
	 * @return codeName
	**/
	public String getCodeName() {
		return codeName;
	}

	public void setCodeName(String codeName) {
		this.codeName = codeName;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		CommonCode commonCode = (CommonCode) o;
		return Objects.equals(this.code, commonCode.code) &&
				Objects.equals(this.codeName, commonCode.codeName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(code, codeName);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class CommonCode {\n");
		
		sb.append("		code: ").append(toIndentedString(code)).append("\n");
		sb.append("		codeName: ").append(toIndentedString(codeName)).append("\n");
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

