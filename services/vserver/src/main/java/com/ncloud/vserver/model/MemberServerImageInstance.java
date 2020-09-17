/*
 * vserver
 * VPC Compute 관련 API<br/>https://ncloud.apigw.ntruss.com/vserver/v2
 *
 * OpenAPI spec version: 2020-09-17T02:28:03Z
 *
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.ncloud.vserver.model;

import java.util.Objects;
import com.ncloud.vserver.model.CommonCode;

/**
 * MemberServerImageInstance
 */
public class MemberServerImageInstance {
	private String memberServerImageInstanceNo = null;

	private String memberServerImageName = null;

	private String memberServerImageDescription = null;

	private String originalServerInstanceNo = null;

	private String originalServerImageProductCode = null;

	private CommonCode memberServerImageInstanceStatus = null;

	private CommonCode memberServerImageInstanceOperation = null;

	private String memberServerImageInstanceStatusName = null;

	private String createDate = null;

	private Integer memberServerImageBlockStorageTotalRows = null;

	private Long memberServerImageBlockStorageTotalSize = null;

	public MemberServerImageInstance memberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스번호
	 * @return memberServerImageInstanceNo
	**/
	public String getMemberServerImageInstanceNo() {
		return memberServerImageInstanceNo;
	}

	public void setMemberServerImageInstanceNo(String memberServerImageInstanceNo) {
		this.memberServerImageInstanceNo = memberServerImageInstanceNo;
	}

	public MemberServerImageInstance memberServerImageName(String memberServerImageName) {
		this.memberServerImageName = memberServerImageName;
		return this;
	}

	 /**
	 * 회원서버이미지이름
	 * @return memberServerImageName
	**/
	public String getMemberServerImageName() {
		return memberServerImageName;
	}

	public void setMemberServerImageName(String memberServerImageName) {
		this.memberServerImageName = memberServerImageName;
	}

	public MemberServerImageInstance memberServerImageDescription(String memberServerImageDescription) {
		this.memberServerImageDescription = memberServerImageDescription;
		return this;
	}

	 /**
	 * 회원서버이미지설명
	 * @return memberServerImageDescription
	**/
	public String getMemberServerImageDescription() {
		return memberServerImageDescription;
	}

	public void setMemberServerImageDescription(String memberServerImageDescription) {
		this.memberServerImageDescription = memberServerImageDescription;
	}

	public MemberServerImageInstance originalServerInstanceNo(String originalServerInstanceNo) {
		this.originalServerInstanceNo = originalServerInstanceNo;
		return this;
	}

	 /**
	 * 원본서버인스턴스번호
	 * @return originalServerInstanceNo
	**/
	public String getOriginalServerInstanceNo() {
		return originalServerInstanceNo;
	}

	public void setOriginalServerInstanceNo(String originalServerInstanceNo) {
		this.originalServerInstanceNo = originalServerInstanceNo;
	}

	public MemberServerImageInstance originalServerImageProductCode(String originalServerImageProductCode) {
		this.originalServerImageProductCode = originalServerImageProductCode;
		return this;
	}

	 /**
	 * 원본서버이미지상품코드
	 * @return originalServerImageProductCode
	**/
	public String getOriginalServerImageProductCode() {
		return originalServerImageProductCode;
	}

	public void setOriginalServerImageProductCode(String originalServerImageProductCode) {
		this.originalServerImageProductCode = originalServerImageProductCode;
	}

	public MemberServerImageInstance memberServerImageInstanceStatus(CommonCode memberServerImageInstanceStatus) {
		this.memberServerImageInstanceStatus = memberServerImageInstanceStatus;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스상태
	 * @return memberServerImageInstanceStatus
	**/
	public CommonCode getMemberServerImageInstanceStatus() {
		return memberServerImageInstanceStatus;
	}

	public void setMemberServerImageInstanceStatus(CommonCode memberServerImageInstanceStatus) {
		this.memberServerImageInstanceStatus = memberServerImageInstanceStatus;
	}

	public MemberServerImageInstance memberServerImageInstanceOperation(CommonCode memberServerImageInstanceOperation) {
		this.memberServerImageInstanceOperation = memberServerImageInstanceOperation;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스OP
	 * @return memberServerImageInstanceOperation
	**/
	public CommonCode getMemberServerImageInstanceOperation() {
		return memberServerImageInstanceOperation;
	}

	public void setMemberServerImageInstanceOperation(CommonCode memberServerImageInstanceOperation) {
		this.memberServerImageInstanceOperation = memberServerImageInstanceOperation;
	}

	public MemberServerImageInstance memberServerImageInstanceStatusName(String memberServerImageInstanceStatusName) {
		this.memberServerImageInstanceStatusName = memberServerImageInstanceStatusName;
		return this;
	}

	 /**
	 * 회원서버이미지인스턴스상태이름
	 * @return memberServerImageInstanceStatusName
	**/
	public String getMemberServerImageInstanceStatusName() {
		return memberServerImageInstanceStatusName;
	}

	public void setMemberServerImageInstanceStatusName(String memberServerImageInstanceStatusName) {
		this.memberServerImageInstanceStatusName = memberServerImageInstanceStatusName;
	}

	public MemberServerImageInstance createDate(String createDate) {
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

	public MemberServerImageInstance memberServerImageBlockStorageTotalRows(Integer memberServerImageBlockStorageTotalRows) {
		this.memberServerImageBlockStorageTotalRows = memberServerImageBlockStorageTotalRows;
		return this;
	}

	 /**
	 * 회원서버이미지블록스토리지총개수
	 * @return memberServerImageBlockStorageTotalRows
	**/
	public Integer getMemberServerImageBlockStorageTotalRows() {
		return memberServerImageBlockStorageTotalRows;
	}

	public void setMemberServerImageBlockStorageTotalRows(Integer memberServerImageBlockStorageTotalRows) {
		this.memberServerImageBlockStorageTotalRows = memberServerImageBlockStorageTotalRows;
	}

	public MemberServerImageInstance memberServerImageBlockStorageTotalSize(Long memberServerImageBlockStorageTotalSize) {
		this.memberServerImageBlockStorageTotalSize = memberServerImageBlockStorageTotalSize;
		return this;
	}

	 /**
	 * 회원서버이미지블록스토리지총사이즈
	 * @return memberServerImageBlockStorageTotalSize
	**/
	public Long getMemberServerImageBlockStorageTotalSize() {
		return memberServerImageBlockStorageTotalSize;
	}

	public void setMemberServerImageBlockStorageTotalSize(Long memberServerImageBlockStorageTotalSize) {
		this.memberServerImageBlockStorageTotalSize = memberServerImageBlockStorageTotalSize;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		MemberServerImageInstance memberServerImageInstance = (MemberServerImageInstance) o;
		return Objects.equals(this.memberServerImageInstanceNo, memberServerImageInstance.memberServerImageInstanceNo) &&
				Objects.equals(this.memberServerImageName, memberServerImageInstance.memberServerImageName) &&
				Objects.equals(this.memberServerImageDescription, memberServerImageInstance.memberServerImageDescription) &&
				Objects.equals(this.originalServerInstanceNo, memberServerImageInstance.originalServerInstanceNo) &&
				Objects.equals(this.originalServerImageProductCode, memberServerImageInstance.originalServerImageProductCode) &&
				Objects.equals(this.memberServerImageInstanceStatus, memberServerImageInstance.memberServerImageInstanceStatus) &&
				Objects.equals(this.memberServerImageInstanceOperation, memberServerImageInstance.memberServerImageInstanceOperation) &&
				Objects.equals(this.memberServerImageInstanceStatusName, memberServerImageInstance.memberServerImageInstanceStatusName) &&
				Objects.equals(this.createDate, memberServerImageInstance.createDate) &&
				Objects.equals(this.memberServerImageBlockStorageTotalRows, memberServerImageInstance.memberServerImageBlockStorageTotalRows) &&
				Objects.equals(this.memberServerImageBlockStorageTotalSize, memberServerImageInstance.memberServerImageBlockStorageTotalSize);
	}

	@Override
	public int hashCode() {
		return Objects.hash(memberServerImageInstanceNo, memberServerImageName, memberServerImageDescription, originalServerInstanceNo, originalServerImageProductCode, memberServerImageInstanceStatus, memberServerImageInstanceOperation, memberServerImageInstanceStatusName, createDate, memberServerImageBlockStorageTotalRows, memberServerImageBlockStorageTotalSize);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class MemberServerImageInstance {\n");
		
		sb.append("		memberServerImageInstanceNo: ").append(toIndentedString(memberServerImageInstanceNo)).append("\n");
		sb.append("		memberServerImageName: ").append(toIndentedString(memberServerImageName)).append("\n");
		sb.append("		memberServerImageDescription: ").append(toIndentedString(memberServerImageDescription)).append("\n");
		sb.append("		originalServerInstanceNo: ").append(toIndentedString(originalServerInstanceNo)).append("\n");
		sb.append("		originalServerImageProductCode: ").append(toIndentedString(originalServerImageProductCode)).append("\n");
		sb.append("		memberServerImageInstanceStatus: ").append(toIndentedString(memberServerImageInstanceStatus)).append("\n");
		sb.append("		memberServerImageInstanceOperation: ").append(toIndentedString(memberServerImageInstanceOperation)).append("\n");
		sb.append("		memberServerImageInstanceStatusName: ").append(toIndentedString(memberServerImageInstanceStatusName)).append("\n");
		sb.append("		createDate: ").append(toIndentedString(createDate)).append("\n");
		sb.append("		memberServerImageBlockStorageTotalRows: ").append(toIndentedString(memberServerImageBlockStorageTotalRows)).append("\n");
		sb.append("		memberServerImageBlockStorageTotalSize: ").append(toIndentedString(memberServerImageBlockStorageTotalSize)).append("\n");
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

