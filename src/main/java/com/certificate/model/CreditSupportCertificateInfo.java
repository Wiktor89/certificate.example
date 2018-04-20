package com.certificate.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Информация о сертификате для кредитно-обеспечительной документации
 */
public class CreditSupportCertificateInfo {

    /**
     * Данные сертификата серийный номер
     */
    private String serialNumber;

    /**
     * Данные сертификата срок действия с
     */
    private Date validNotBefore;

    /**
     * Данные сертификата срок действия по
     */
    private Date validNotAfter;

    /**
     * Данные сертификата владелец
     */
    private String owner;

    /**
     * Данные владельца СНИЛС
     */
    private String ownerSnils;

    /**
     * Данные владельца ОГРН
     */
    private String ownerOGRN;

    /**
     * Данные владельца ИНН
     */
    private String ownerINN;

    /**
     * Данные владельца C
     */
    private String ownerCountry;

    /**
     * Данные владельца ST
     */
    private String ownerStateOrProvince;

    /**
     * Данные владельца L
     */
    private String ownerLocality;

    /**
     * Данные владельца O
     */
    private String ownerOrganization;

    /**
     * Данные владельца CN
     */
    private String ownerCommonName;

    /**
     * Данные владельца STREET
     */
    private String ownerStreet;

    /**
     * Данные владельца TITLE
     */
    private String ownerTitle;

    /**
     * Данные владельца G
     */
    private String ownerGivenName;

    /**
     * Данные владельца SN
     */
    private String ownerSureName;

    /**
     * Данные издателя EMAIL
     */
    private String issuerEmail;

    /**
     * Данные издателя ОГРН
     */
    private String issuerOGRN;

    /**
     * Данные издателя ИНН
     */
    private String issuerINN;

    /**
     * Данные издателя C
     */
    private String issuerCountry;

    /**
     * Данные издателя ST
     */
    private String issuerStateOrProvince;

    /**
     * Данные издателя L
     */
    private String issuerLocality;

    /**
     * Данные издателя STREET
     */
    private String issuerStreet;

    /**
     * Данные издателя OU
     */
    private String organizationalUnit;

    /**
     * Данные издателя O
     */
    private String organization;

    /**
     * Данные издателя CN
     */
    private String issuerCommonName;

    /**
     * Данные списка отзыва
     */
    private List<String> crlRevocationList = new ArrayList<>();

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public Date getValidNotBefore() {
        return validNotBefore;
    }

    public void setValidNotBefore(Date validNotBefore) {
        this.validNotBefore = validNotBefore;
    }

    public Date getValidNotAfter() {
        return validNotAfter;
    }

    public void setValidNotAfter(Date validNotAfter) {
        this.validNotAfter = validNotAfter;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getOwnerSnils() {
        return ownerSnils;
    }

    public void setOwnerSnils(String ownerSnils) {
        this.ownerSnils = ownerSnils;
    }

    public String getOwnerOGRN() {
        return ownerOGRN;
    }

    public void setOwnerOGRN(String ownerOGRN) {
        this.ownerOGRN = ownerOGRN;
    }

    public String getOwnerINN() {
        return ownerINN;
    }

    public void setOwnerINN(String ownerINN) {
        this.ownerINN = ownerINN;
    }

    public String getOwnerCountry() {
        return ownerCountry;
    }

    public void setOwnerCountry(String ownerCountry) {
        this.ownerCountry = ownerCountry;
    }

    public String getOwnerStateOrProvince() {
        return ownerStateOrProvince;
    }

    public void setOwnerStateOrProvince(String ownerStateOrProvince) {
        this.ownerStateOrProvince = ownerStateOrProvince;
    }

    public String getOwnerLocality() {
        return ownerLocality;
    }

    public void setOwnerLocality(String ownerLocality) {
        this.ownerLocality = ownerLocality;
    }

    public String getOwnerOrganization() {
        return ownerOrganization;
    }

    public void setOwnerOrganization(String ownerOrganization) {
        this.ownerOrganization = ownerOrganization;
    }

    public String getOwnerCommonName() {
        return ownerCommonName;
    }

    public void setOwnerCommonName(String ownerCommonName) {
        this.ownerCommonName = ownerCommonName;
    }

    public String getOwnerStreet() {
        return ownerStreet;
    }

    public void setOwnerStreet(String ownerStreet) {
        this.ownerStreet = ownerStreet;
    }

    public String getOwnerTitle() {
        return ownerTitle;
    }

    public void setOwnerTitle(String ownerTitle) {
        this.ownerTitle = ownerTitle;
    }

    public String getOwnerGivenName() {
        return ownerGivenName;
    }

    public void setOwnerGivenName(String ownerGivenName) {
        this.ownerGivenName = ownerGivenName;
    }

    public String getOwnerSureName() {
        return ownerSureName;
    }

    public void setOwnerSureName(String ownerSureName) {
        this.ownerSureName = ownerSureName;
    }

    public String getIssuerEmail() {
        return issuerEmail;
    }

    public void setIssuerEmail(String issuerEmail) {
        this.issuerEmail = issuerEmail;
    }

    public String getIssuerOGRN() {
        return issuerOGRN;
    }

    public void setIssuerOGRN(String issuerOGRN) {
        this.issuerOGRN = issuerOGRN;
    }

    public String getIssuerINN() {
        return issuerINN;
    }

    public void setIssuerINN(String issuerINN) {
        this.issuerINN = issuerINN;
    }

    public String getIssuerCountry() {
        return issuerCountry;
    }

    public void setIssuerCountry(String issuerCountry) {
        this.issuerCountry = issuerCountry;
    }

    public String getIssuerStateOrProvince() {
        return issuerStateOrProvince;
    }

    public void setIssuerStateOrProvince(String issuerStateOrProvince) {
        this.issuerStateOrProvince = issuerStateOrProvince;
    }

    public String getIssuerLocality() {
        return issuerLocality;
    }

    public void setIssuerLocality(String issuerLocality) {
        this.issuerLocality = issuerLocality;
    }

    public String getIssuerStreet() {
        return issuerStreet;
    }

    public void setIssuerStreet(String issuerStreet) {
        this.issuerStreet = issuerStreet;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(String organizationalUnit) {
        this.organizationalUnit = organizationalUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getIssuerCommonName() {
        return issuerCommonName;
    }

    public void setIssuerCommonName(String issuerCommonName) {
        this.issuerCommonName = issuerCommonName;
    }

    public List<String> getCrlRevocationList() {
        return crlRevocationList;
    }

    public void setCrlRevocationList(List<String> crlRevocationList) {
        this.crlRevocationList = crlRevocationList;
    }
}
    