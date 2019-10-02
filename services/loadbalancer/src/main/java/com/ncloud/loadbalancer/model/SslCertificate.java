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

/**
 * SslCertificate
 */
public class SslCertificate {
	private String certificateName = null;

	private String privateKey = null;

	private String publicKeyCertificate = null;

	private String certificateChain = null;

	public SslCertificate certificateName(String certificateName) {
		this.certificateName = certificateName;
		return this;
	}

	 /**
	 * 인증서명
	 * @return certificateName
	**/
	public String getCertificateName() {
		return certificateName;
	}

	public void setCertificateName(String certificateName) {
		this.certificateName = certificateName;
	}

	public SslCertificate privateKey(String privateKey) {
		this.privateKey = privateKey;
		return this;
	}

	 /**
	 * 비밀키
	 * @return privateKey
	**/
	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public SslCertificate publicKeyCertificate(String publicKeyCertificate) {
		this.publicKeyCertificate = publicKeyCertificate;
		return this;
	}

	 /**
	 * 공개키인증서
	 * @return publicKeyCertificate
	**/
	public String getPublicKeyCertificate() {
		return publicKeyCertificate;
	}

	public void setPublicKeyCertificate(String publicKeyCertificate) {
		this.publicKeyCertificate = publicKeyCertificate;
	}

	public SslCertificate certificateChain(String certificateChain) {
		this.certificateChain = certificateChain;
		return this;
	}

	 /**
	 * chainca
	 * @return certificateChain
	**/
	public String getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(String certificateChain) {
		this.certificateChain = certificateChain;
	}


	@Override
	public boolean equals(java.lang.Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SslCertificate sslCertificate = (SslCertificate) o;
		return Objects.equals(this.certificateName, sslCertificate.certificateName) &&
				Objects.equals(this.privateKey, sslCertificate.privateKey) &&
				Objects.equals(this.publicKeyCertificate, sslCertificate.publicKeyCertificate) &&
				Objects.equals(this.certificateChain, sslCertificate.certificateChain);
	}

	@Override
	public int hashCode() {
		return Objects.hash(certificateName, privateKey, publicKeyCertificate, certificateChain);
	}


	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("class SslCertificate {\n");
		
		sb.append("		certificateName: ").append(toIndentedString(certificateName)).append("\n");
		sb.append("		privateKey: ").append(toIndentedString(privateKey)).append("\n");
		sb.append("		publicKeyCertificate: ").append(toIndentedString(publicKeyCertificate)).append("\n");
		sb.append("		certificateChain: ").append(toIndentedString(certificateChain)).append("\n");
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

