/*
 * server
 * <br/>https://ncloud.apigw.ntruss.com/server/v2
 *
 * OpenAPI spec version: 2019-10-17T10:28:43Z
 *
 * NBP corp.
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.server.model;

import java.util.Objects;
import com.ncloud.server.model.CommonCode;
import com.ncloud.server.model.Region;
import com.ncloud.server.model.ServerInstance;
import com.ncloud.server.model.Zone;

/**
 * PublicIpInstance
 */
public class PublicIpInstance {
	private String publicIpInstanceNo = null;

	private String publicIp = null;

	private String publicIpDescription = null;

	private String createDate = null;

	private CommonCode internetLineType = null;

	private String publicIpInstanceStatusName = null;

	private CommonCode publicIpInstanceStatus = null;

	private CommonCode publicIpInstanceOperation = null;

	private CommonCode publicIpKindType = null;

	private ServerInstance serverInstanceAssociatedWithPublicIp = null;

	private Region region = null;

	private Zone zone = null;

	public PublicIpInstance publicIpInstanceNo(String publicIpInstanceNo) {
		this.publicIpInstanceNo = publicIpInstanceNo;
		return this;
	}

	 /**
	 * 공인IP인스턴스번호
	 * @return publicIpInstanceNo
	**/
	public String getPublicIpInstanceNo() {
		return publicIpInstanceNo;
	}

	public void setPublicIpInstanceNo(String publicIpInstanceNo) {
		this.publicIpInstanceNo = publicIpInstanceNo;
	}

	public PublicIpInstance publicIp(String publicIp) {
		this.publicIp = publicIp;
		return this;
	}

	 /**
	 * 공인IP
	 * @return publicIp
	**/
	public String getPublicIp() {
		return publicIp;
	}

	public void setPublicIp(String publicIp) {
		this.publicIp = publicIp;
	}

	public PublicIpInstance publicIpDescription(String publicIpDescription) {
		this.publicIpDescription = publicIpDescription;
		return this;
	}

	 /**
	 * 공인IP설명
	 * @return publicIpDescription
	**/
	public String getPublicIpDescription() {
		return publicIpDescription;
	}

	public void setPublicIpDescription(String publicIpDescription) {
		this.publicIpDescription = publicIpDescription;
	}

	public PublicIpInstance createDate(String createDate) {
		this.createDate = createDate;
		return this;
	}

	 /**
	 * 생성일시
	 * @return createDate
	**/
	public String getCreateDate() {
		return createDate;
	}

	public void setCreateDate(String createDate) {
		this.createDate = createDate;
	}

	public PublicIpInstance internetLineType(CommonCode internetLineType) {
		this.internetLineType = internetLineType;
		return this;
	}

	 /**
	 * 인터넷라인구분
	 * @return internetLineType
	**/
	public CommonCode getInternetLineType() {
		return internetLineType;
	}

	public void setInternetLineType(CommonCode internetLineType) {
		this.internetLineType = internetLineType;
	}

	public PublicIpInstance publicIpInstanceStatusName(String publicIpInstanceStatusName) {
		this.publicIpInstanceStatusName = publicIpInstanceStatusName;
		return this;
	}

	 /**
	 * 공인IP인스턴스상태명
	 * @return publicIpInstanceStatusName
	**/
	public String getPublicIpInstanceStatusName() {
		return publicIpInstanceStatusName;
	}

	public void setPublicIpInstanceStatusName(String publicIpInstanceStatusName) {
		this.publicIpInstanceStatusName = publicIpInstanceStatusName;
	}

	public PublicIpInstance publicIpInstanceStatus(CommonCode publicIpInstanceStatus) {
		this.publicIpInstanceStatus = publicIpInstanceStatus;
		return this;
	}

	 /**
	 * 공인IP인스턴스상태
	 * @return publicIpInstanceStatus
	**/
	public CommonCode getPublicIpInstanceStatus() {
		return publicIpInstanceStatus;
	}

	public void setPublicIpInstanceStatus(CommonCode publicIpInstanceStatus) {
		this.publicIpInstanceStatus = publicIpInstanceStatus;
	}

	public PublicIpInstance publicIpInstanceOperation(CommonCode publicIpInstanceOperation) {
		this.publicIpInstanceOperation = publicIpInstanceOperation;
		return this;
	}

	 /**
	 * 공인IP인스턴스OP
	 * @return publicIpInstanceOperation
	**/
	public CommonCode getPublicIpInstanceOperation() {
		return publicIpInstanceOperation;
	}

	public void setPublicIpInstanceOperation(CommonCode publicIpInstanceOperation) {
		this.publicIpInstanceOperation = publicIpInstanceOperation;
	}

	public PublicIpInstance publicIpKindType(CommonCode publicIpKindType) {
		this.publicIpKindType = publicIpKindType;
		return this;
	}

	 /**
	 * 공인IP종류구분
	 * @return publicIpKindType
	**/
	public CommonCode getPublicIpKindType() {
		return publicIpKindType;
	}

	public void setPublicIpKindType(CommonCode publicIpKindType) {
		this.publicIpKindType = publicIpKindType;
	}

	public PublicIpInstance serverInstanceAssociatedWithPublicIp(ServerInstance serverInstanceAssociatedWithPublicIp) {
		this.serverInstanceAssociatedWithPublicIp = serverInstanceAssociatedWithPublicIp;
		return this;
	}

	 /**
	 * 공인IP할당된서버인스턴스
	 * @return serverInstanceAssociatedWithPublicIp
	**/
	public ServerInstance getServerInstanceAssociatedWithPublicIp() {
		return serverInstanceAssociatedWithPublicIp;
	}

	public void setServerInstanceAssociatedWithPublicIp(ServerInstance serverInstanceAssociatedWithPublicIp) {
		this.serverInstanceAssociatedWithPublicIp = serverInstanceAssociatedWithPublicIp;
	}

	public PublicIpInstance region(Region region) {
		this.region = region;
		return this;
	}

	 /**
	 * 리전
	 * @return region
	**/
	public Region getRegion() {
		return region;
	}

	public void setRegion(Region region) {
		this.region = region;
	}

	public PublicIpInstance zone(Zone zone) {
		this.zone = zone;
		return this;
	}

	 /**
	 * ZONE
	 * @return zone
	**/
	public Zone getZone() {
		return zone;
	}

	public void setZone(Zone zone) {
		this.zone = zone;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		PublicIpInstance publicIpInstance = (PublicIpInstance) o;
		return Objects.equals(this.publicIpInstanceNo, publicIpInstance.publicIpInstanceNo) &&
				Objects.equals(this.publicIp, publicIpInstance.publicIp) &&
				Objects.equals(this.publicIpDescription, publicIpInstance.publicIpDescription) &&
				Objects.equals(this.createDate, publicIpInstance.createDate) &&
				Objects.equals(this.internetLineType, publicIpInstance.internetLineType) &&
				Objects.equals(this.publicIpInstanceStatusName, publicIpInstance.publicIpInstanceStatusName) &&
				Objects.equals(this.publicIpInstanceStatus, publicIpInstance.publicIpInstanceStatus) &&
				Objects.equals(this.publicIpInstanceOperation, publicIpInstance.publicIpInstanceOperation) &&
				Objects.equals(this.publicIpKindType, publicIpInstance.publicIpKindType) &&
				Objects.equals(this.serverInstanceAssociatedWithPublicIp, publicIpInstance.serverInstanceAssociatedWithPublicIp) &&
				Objects.equals(this.region, publicIpInstance.region) &&
				Objects.equals(this.zone, publicIpInstance.zone);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicIpInstanceNo, publicIp, publicIpDescription, createDate, internetLineType, publicIpInstanceStatusName, publicIpInstanceStatus, publicIpInstanceOperation, publicIpKindType, serverInstanceAssociatedWithPublicIp, region, zone);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class PublicIpInstance {\n");
		
		sb.append("		publicIpInstanceNo: ").append(toIndentedString(publicIpInstanceNo)).append("\n");
		sb.append("		publicIp: ").append(toIndentedString(publicIp)).append("\n");
		sb.append("		publicIpDescription: ").append(toIndentedString(publicIpDescription)).append("\n");
		sb.append("		createDate: ").append(toIndentedString(createDate)).append("\n");
		sb.append("		internetLineType: ").append(toIndentedString(internetLineType)).append("\n");
		sb.append("		publicIpInstanceStatusName: ").append(toIndentedString(publicIpInstanceStatusName)).append("\n");
		sb.append("		publicIpInstanceStatus: ").append(toIndentedString(publicIpInstanceStatus)).append("\n");
		sb.append("		publicIpInstanceOperation: ").append(toIndentedString(publicIpInstanceOperation)).append("\n");
		sb.append("		publicIpKindType: ").append(toIndentedString(publicIpKindType)).append("\n");
		sb.append("		serverInstanceAssociatedWithPublicIp: ").append(toIndentedString(serverInstanceAssociatedWithPublicIp)).append("\n");
		sb.append("		region: ").append(toIndentedString(region)).append("\n");
		sb.append("		zone: ").append(toIndentedString(zone)).append("\n");
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

