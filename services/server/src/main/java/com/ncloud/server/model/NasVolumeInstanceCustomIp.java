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

/**
 * NasVolumeInstanceCustomIp
 */
public class NasVolumeInstanceCustomIp {
	private String customIp = null;

	public NasVolumeInstanceCustomIp customIp(String customIp) {
		this.customIp = customIp;
		return this;
	}

	 /**
	 * 커스텀IP
	 * @return customIp
	**/
	public String getCustomIp() {
		return customIp;
	}

	public void setCustomIp(String customIp) {
		this.customIp = customIp;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		NasVolumeInstanceCustomIp nasVolumeInstanceCustomIp = (NasVolumeInstanceCustomIp) o;
		return Objects.equals(this.customIp, nasVolumeInstanceCustomIp.customIp);
	}

	@Override
	public int hashCode() {
		return Objects.hash(customIp);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class NasVolumeInstanceCustomIp {\n");
		
		sb.append("		customIp: ").append(toIndentedString(customIp)).append("\n");
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

