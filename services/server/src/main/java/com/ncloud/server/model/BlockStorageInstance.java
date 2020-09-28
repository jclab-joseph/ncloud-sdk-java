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
import com.ncloud.server.model.CommonCode;
import com.ncloud.server.model.Region;
import com.ncloud.server.model.Zone;

/**
 * BlockStorageInstance
 */
public class BlockStorageInstance {
	private String blockStorageInstanceNo = null;

	private String serverInstanceNo = null;

	private String serverName = null;

	private CommonCode blockStorageType = null;

	private String blockStorageName = null;

	private Long blockStorageSize = null;

	private String deviceName = null;

	private String memberServerImageNo = null;

	private String blockStorageProductCode = null;

	private CommonCode blockStorageInstanceStatus = null;

	private CommonCode blockStorageInstanceOperation = null;

	private String blockStorageInstanceStatusName = null;

	private String createDate = null;

	private String blockStorageInstanceDescription = null;

	private CommonCode diskType = null;

	private CommonCode diskDetailType = null;

	private Integer maxIopsThroughput = null;

	private Region region = null;

	private Zone zone = null;

	public BlockStorageInstance blockStorageInstanceNo(String blockStorageInstanceNo) {
		this.blockStorageInstanceNo = blockStorageInstanceNo;
		return this;
	}

	 /**
	 * 블록스토리지인스턴스번호
	 * @return blockStorageInstanceNo
	**/
	public String getBlockStorageInstanceNo() {
		return blockStorageInstanceNo;
	}

	public void setBlockStorageInstanceNo(String blockStorageInstanceNo) {
		this.blockStorageInstanceNo = blockStorageInstanceNo;
	}

	public BlockStorageInstance serverInstanceNo(String serverInstanceNo) {
		this.serverInstanceNo = serverInstanceNo;
		return this;
	}

	 /**
	 * 서버인스턴스번호
	 * @return serverInstanceNo
	**/
	public String getServerInstanceNo() {
		return serverInstanceNo;
	}

	public void setServerInstanceNo(String serverInstanceNo) {
		this.serverInstanceNo = serverInstanceNo;
	}

	public BlockStorageInstance serverName(String serverName) {
		this.serverName = serverName;
		return this;
	}

	 /**
	 * 서버명
	 * @return serverName
	**/
	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	public BlockStorageInstance blockStorageType(CommonCode blockStorageType) {
		this.blockStorageType = blockStorageType;
		return this;
	}

	 /**
	 * 블록스토리지구분
	 * @return blockStorageType
	**/
	public CommonCode getBlockStorageType() {
		return blockStorageType;
	}

	public void setBlockStorageType(CommonCode blockStorageType) {
		this.blockStorageType = blockStorageType;
	}

	public BlockStorageInstance blockStorageName(String blockStorageName) {
		this.blockStorageName = blockStorageName;
		return this;
	}

	 /**
	 * 블록스토리지명
	 * @return blockStorageName
	**/
	public String getBlockStorageName() {
		return blockStorageName;
	}

	public void setBlockStorageName(String blockStorageName) {
		this.blockStorageName = blockStorageName;
	}

	public BlockStorageInstance blockStorageSize(Long blockStorageSize) {
		this.blockStorageSize = blockStorageSize;
		return this;
	}

	 /**
	 * 블록스토리지사이즈
	 * @return blockStorageSize
	**/
	public Long getBlockStorageSize() {
		return blockStorageSize;
	}

	public void setBlockStorageSize(Long blockStorageSize) {
		this.blockStorageSize = blockStorageSize;
	}

	public BlockStorageInstance deviceName(String deviceName) {
		this.deviceName = deviceName;
		return this;
	}

	 /**
	 * 디바이스명
	 * @return deviceName
	**/
	public String getDeviceName() {
		return deviceName;
	}

	public void setDeviceName(String deviceName) {
		this.deviceName = deviceName;
	}

	public BlockStorageInstance memberServerImageNo(String memberServerImageNo) {
		this.memberServerImageNo = memberServerImageNo;
		return this;
	}

	 /**
	 * 회원서버이미지번호
	 * @return memberServerImageNo
	**/
	public String getMemberServerImageNo() {
		return memberServerImageNo;
	}

	public void setMemberServerImageNo(String memberServerImageNo) {
		this.memberServerImageNo = memberServerImageNo;
	}

	public BlockStorageInstance blockStorageProductCode(String blockStorageProductCode) {
		this.blockStorageProductCode = blockStorageProductCode;
		return this;
	}

	 /**
	 * 블록스토리지상품코드
	 * @return blockStorageProductCode
	**/
	public String getBlockStorageProductCode() {
		return blockStorageProductCode;
	}

	public void setBlockStorageProductCode(String blockStorageProductCode) {
		this.blockStorageProductCode = blockStorageProductCode;
	}

	public BlockStorageInstance blockStorageInstanceStatus(CommonCode blockStorageInstanceStatus) {
		this.blockStorageInstanceStatus = blockStorageInstanceStatus;
		return this;
	}

	 /**
	 * 블록스토리지인스턴스상태
	 * @return blockStorageInstanceStatus
	**/
	public CommonCode getBlockStorageInstanceStatus() {
		return blockStorageInstanceStatus;
	}

	public void setBlockStorageInstanceStatus(CommonCode blockStorageInstanceStatus) {
		this.blockStorageInstanceStatus = blockStorageInstanceStatus;
	}

	public BlockStorageInstance blockStorageInstanceOperation(CommonCode blockStorageInstanceOperation) {
		this.blockStorageInstanceOperation = blockStorageInstanceOperation;
		return this;
	}

	 /**
	 * 블록스토리지인스턴스OP
	 * @return blockStorageInstanceOperation
	**/
	public CommonCode getBlockStorageInstanceOperation() {
		return blockStorageInstanceOperation;
	}

	public void setBlockStorageInstanceOperation(CommonCode blockStorageInstanceOperation) {
		this.blockStorageInstanceOperation = blockStorageInstanceOperation;
	}

	public BlockStorageInstance blockStorageInstanceStatusName(String blockStorageInstanceStatusName) {
		this.blockStorageInstanceStatusName = blockStorageInstanceStatusName;
		return this;
	}

	 /**
	 * 블록스토리지인스턴스상태명
	 * @return blockStorageInstanceStatusName
	**/
	public String getBlockStorageInstanceStatusName() {
		return blockStorageInstanceStatusName;
	}

	public void setBlockStorageInstanceStatusName(String blockStorageInstanceStatusName) {
		this.blockStorageInstanceStatusName = blockStorageInstanceStatusName;
	}

	public BlockStorageInstance createDate(String createDate) {
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

	public BlockStorageInstance blockStorageInstanceDescription(String blockStorageInstanceDescription) {
		this.blockStorageInstanceDescription = blockStorageInstanceDescription;
		return this;
	}

	 /**
	 * 블록스토리지인스턴스설명
	 * @return blockStorageInstanceDescription
	**/
	public String getBlockStorageInstanceDescription() {
		return blockStorageInstanceDescription;
	}

	public void setBlockStorageInstanceDescription(String blockStorageInstanceDescription) {
		this.blockStorageInstanceDescription = blockStorageInstanceDescription;
	}

	public BlockStorageInstance diskType(CommonCode diskType) {
		this.diskType = diskType;
		return this;
	}

	 /**
	 * 디스크유형
	 * @return diskType
	**/
	public CommonCode getDiskType() {
		return diskType;
	}

	public void setDiskType(CommonCode diskType) {
		this.diskType = diskType;
	}

	public BlockStorageInstance diskDetailType(CommonCode diskDetailType) {
		this.diskDetailType = diskDetailType;
		return this;
	}

	 /**
	 * 디스크상세유형
	 * @return diskDetailType
	**/
	public CommonCode getDiskDetailType() {
		return diskDetailType;
	}

	public void setDiskDetailType(CommonCode diskDetailType) {
		this.diskDetailType = diskDetailType;
	}

	public BlockStorageInstance maxIopsThroughput(Integer maxIopsThroughput) {
		this.maxIopsThroughput = maxIopsThroughput;
		return this;
	}

	 /**
	 * 최대 IOPS
	 * @return maxIopsThroughput
	**/
	public Integer getMaxIopsThroughput() {
		return maxIopsThroughput;
	}

	public void setMaxIopsThroughput(Integer maxIopsThroughput) {
		this.maxIopsThroughput = maxIopsThroughput;
	}

	public BlockStorageInstance region(Region region) {
		this.region = region;
		return this;
	}

	 /**
	 * Get region
	 * @return region
	**/
	public Region getRegion() {
		return region;
	}

	public void setRegion(Region region) {
		this.region = region;
	}

	public BlockStorageInstance zone(Zone zone) {
		this.zone = zone;
		return this;
	}

	 /**
	 * Get zone
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
		BlockStorageInstance blockStorageInstance = (BlockStorageInstance) o;
		return Objects.equals(this.blockStorageInstanceNo, blockStorageInstance.blockStorageInstanceNo) &&
				Objects.equals(this.serverInstanceNo, blockStorageInstance.serverInstanceNo) &&
				Objects.equals(this.serverName, blockStorageInstance.serverName) &&
				Objects.equals(this.blockStorageType, blockStorageInstance.blockStorageType) &&
				Objects.equals(this.blockStorageName, blockStorageInstance.blockStorageName) &&
				Objects.equals(this.blockStorageSize, blockStorageInstance.blockStorageSize) &&
				Objects.equals(this.deviceName, blockStorageInstance.deviceName) &&
				Objects.equals(this.memberServerImageNo, blockStorageInstance.memberServerImageNo) &&
				Objects.equals(this.blockStorageProductCode, blockStorageInstance.blockStorageProductCode) &&
				Objects.equals(this.blockStorageInstanceStatus, blockStorageInstance.blockStorageInstanceStatus) &&
				Objects.equals(this.blockStorageInstanceOperation, blockStorageInstance.blockStorageInstanceOperation) &&
				Objects.equals(this.blockStorageInstanceStatusName, blockStorageInstance.blockStorageInstanceStatusName) &&
				Objects.equals(this.createDate, blockStorageInstance.createDate) &&
				Objects.equals(this.blockStorageInstanceDescription, blockStorageInstance.blockStorageInstanceDescription) &&
				Objects.equals(this.diskType, blockStorageInstance.diskType) &&
				Objects.equals(this.diskDetailType, blockStorageInstance.diskDetailType) &&
				Objects.equals(this.maxIopsThroughput, blockStorageInstance.maxIopsThroughput) &&
				Objects.equals(this.region, blockStorageInstance.region) &&
				Objects.equals(this.zone, blockStorageInstance.zone);
	}

	@Override
	public int hashCode() {
		return Objects.hash(blockStorageInstanceNo, serverInstanceNo, serverName, blockStorageType, blockStorageName, blockStorageSize, deviceName, memberServerImageNo, blockStorageProductCode, blockStorageInstanceStatus, blockStorageInstanceOperation, blockStorageInstanceStatusName, createDate, blockStorageInstanceDescription, diskType, diskDetailType, maxIopsThroughput, region, zone);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class BlockStorageInstance {\n");
		
		sb.append("		blockStorageInstanceNo: ").append(toIndentedString(blockStorageInstanceNo)).append("\n");
		sb.append("		serverInstanceNo: ").append(toIndentedString(serverInstanceNo)).append("\n");
		sb.append("		serverName: ").append(toIndentedString(serverName)).append("\n");
		sb.append("		blockStorageType: ").append(toIndentedString(blockStorageType)).append("\n");
		sb.append("		blockStorageName: ").append(toIndentedString(blockStorageName)).append("\n");
		sb.append("		blockStorageSize: ").append(toIndentedString(blockStorageSize)).append("\n");
		sb.append("		deviceName: ").append(toIndentedString(deviceName)).append("\n");
		sb.append("		memberServerImageNo: ").append(toIndentedString(memberServerImageNo)).append("\n");
		sb.append("		blockStorageProductCode: ").append(toIndentedString(blockStorageProductCode)).append("\n");
		sb.append("		blockStorageInstanceStatus: ").append(toIndentedString(blockStorageInstanceStatus)).append("\n");
		sb.append("		blockStorageInstanceOperation: ").append(toIndentedString(blockStorageInstanceOperation)).append("\n");
		sb.append("		blockStorageInstanceStatusName: ").append(toIndentedString(blockStorageInstanceStatusName)).append("\n");
		sb.append("		createDate: ").append(toIndentedString(createDate)).append("\n");
		sb.append("		blockStorageInstanceDescription: ").append(toIndentedString(blockStorageInstanceDescription)).append("\n");
		sb.append("		diskType: ").append(toIndentedString(diskType)).append("\n");
		sb.append("		diskDetailType: ").append(toIndentedString(diskDetailType)).append("\n");
		sb.append("		maxIopsThroughput: ").append(toIndentedString(maxIopsThroughput)).append("\n");
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

