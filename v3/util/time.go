/*
 * ZLint Copyright 2025 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package util

import (
	"math"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

const (
	DurationDay = 24 * time.Hour
)

var (
	ZeroDate                   = time.Date(0000, time.January, 1, 0, 0, 0, 0, time.UTC)
	RFC1035Date                = time.Date(1987, time.January, 1, 0, 0, 0, 0, time.UTC)
	RFC2459Date                = time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC)
	RFC3279Date                = time.Date(2002, time.April, 1, 0, 0, 0, 0, time.UTC)
	RFC3280Date                = time.Date(2002, time.April, 1, 0, 0, 0, 0, time.UTC)
	RFC3490Date                = time.Date(2003, time.March, 1, 0, 0, 0, 0, time.UTC)
	RFC8399Date                = time.Date(2018, time.May, 1, 0, 0, 0, 0, time.UTC)
	RFC4325Date                = time.Date(2005, time.December, 1, 0, 0, 0, 0, time.UTC)
	RFC4630Date                = time.Date(2006, time.August, 1, 0, 0, 0, 0, time.UTC)
	RFC5280Date                = time.Date(2008, time.May, 1, 0, 0, 0, 0, time.UTC)
	RFC6818Date                = time.Date(2013, time.January, 1, 0, 0, 0, 0, time.UTC)
	RFC6960Date                = time.Date(2013, time.June, 1, 0, 0, 0, 0, time.UTC)
	RFC6962Date                = time.Date(2013, time.June, 1, 0, 0, 0, 0, time.UTC)
	RFC8813Date                = time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
	CABEffectiveDate           = time.Date(2012, time.July, 1, 0, 0, 0, 0, time.UTC)
	CABReservedIPDate          = time.Date(2016, time.October, 1, 0, 0, 0, 0, time.UTC)
	CABGivenNameDate           = time.Date(2016, time.September, 7, 0, 0, 0, 0, time.UTC)
	CABSerialNumberEntropyDate = time.Date(2016, time.September, 30, 0, 0, 0, 0, time.UTC)
	CABV102Date                = time.Date(2012, time.June, 8, 0, 0, 0, 0, time.UTC)
	CABV113Date                = time.Date(2013, time.February, 21, 0, 0, 0, 0, time.UTC)
	CABV114Date                = time.Date(2013, time.May, 3, 0, 0, 0, 0, time.UTC)
	CABV116Date                = time.Date(2013, time.July, 29, 0, 0, 0, 0, time.UTC)
	CABV130Date                = time.Date(2015, time.April, 16, 0, 0, 0, 0, time.UTC)
	CABV131Date                = time.Date(2015, time.September, 28, 0, 0, 0, 0, time.UTC)
	// https://cabforum.org/wp-content/uploads/CA-Browser-Forum-EV-Guidelines-v1.7.0.pdf
	CABV170Date                                      = time.Date(2020, time.January, 31, 0, 0, 0, 0, time.UTC)
	NO_SHA1                                          = time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC)
	NoRSA1024RootDate                                = time.Date(2011, time.January, 1, 0, 0, 0, 0, time.UTC)
	NoRSA1024Date                                    = time.Date(2014, time.January, 1, 0, 0, 0, 0, time.UTC)
	GeneralizedDate                                  = time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)
	NoReservedIP                                     = time.Date(2015, time.November, 1, 0, 0, 0, 0, time.UTC)
	SubCert39Month                                   = time.Date(2016, time.July, 2, 0, 0, 0, 0, time.UTC)
	SubCert825Days                                   = time.Date(2018, time.March, 2, 0, 0, 0, 0, time.UTC)
	CABV148Date                                      = time.Date(2017, time.June, 8, 0, 0, 0, 0, time.UTC)
	EtsiEn319_412_5_V2_2_1_Date                      = time.Date(2017, time.November, 1, 0, 0, 0, 0, time.UTC)
	EtsiEn319_412_5_V2_4_1_Date                      = time.Date(2023, time.September, 1, 0, 0, 0, 0, time.UTC)
	OnionOnlyEVDate                                  = time.Date(2015, time.May, 1, 0, 0, 0, 0, time.UTC)
	CABV201Date                                      = time.Date(2017, time.July, 28, 0, 0, 0, 0, time.UTC)
	AppleCTPolicyDate                                = time.Date(2018, time.October, 15, 0, 0, 0, 0, time.UTC)
	MozillaPolicy22Date                              = time.Date(2013, time.July, 26, 0, 0, 0, 0, time.UTC)
	MozillaPolicy24Date                              = time.Date(2017, time.February, 28, 0, 0, 0, 0, time.UTC)
	MozillaPolicy241Date                             = time.Date(2017, time.March, 31, 0, 0, 0, 0, time.UTC)
	MozillaPolicy27Date                              = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	MozillaPolicy30Date                              = time.Date(2025, time.March, 15, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_6_2_UnderscorePermissibilitySunsetDate = time.Date(2019, time.April, 1, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_6_2_Date                               = time.Date(2018, time.December, 10, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_2_1_Date                               = time.Date(2015, time.January, 16, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_6_9_Date                               = time.Date(2020, time.March, 27, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_7_1_Date                               = time.Date(2020, time.August, 20, 0, 0, 0, 0, time.UTC)
	AppleReducedLifetimeDate                         = time.Date(2020, time.September, 1, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_7_9_Date                               = time.Date(2021, time.August, 16, 0, 0, 0, 0, time.UTC)
	CABFBRs_1_8_0_Date                               = time.Date(2021, time.August, 25, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_0_Date                               = time.Date(2023, time.September, 15, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_1_Date                               = time.Date(2024, time.March, 15, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_2_Date                               = time.Date(2024, time.January, 8, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_3_Date                               = time.Date(2024, time.April, 15, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_4_Date                               = time.Date(2024, time.May, 15, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_5_Date                               = time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_6_Date                               = time.Date(2024, time.August, 6, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_7_Date                               = time.Date(2024, time.September, 6, 0, 0, 0, 0, time.UTC)
	CABFBRs_2_0_8_Date                               = time.Date(2024, time.October, 2, 0, 0, 0, 0, time.UTC)
	NoReservedDomainLabelsDate                       = time.Date(2021, time.October, 1, 0, 0, 0, 0, time.UTC)
	CABFBRs_OU_Prohibited_Date                       = time.Date(2022, time.September, 1, 0, 0, 0, 0, time.UTC)
	SC16EffectiveDate                                = time.Date(2019, time.April, 16, 0, 0, 0, 0, time.UTC)
	SC17EffectiveDate                                = time.Date(2019, time.June, 21, 0, 0, 0, 0, time.UTC)
	CABF_SMIME_BRs_1_0_0_Date                        = time.Date(2023, time.September, 1, 0, 0, 0, 0, time.UTC)
	// Date of deprecation of S/MIME legacy policies from Ballot SMC08
	SMC08EffectiveDate = time.Date(2025, time.July, 15, 0, 0, 0, 0, time.UTC)
	// Enforcement date of CRL reason codes from Ballot SC 061
	CABFBRs_1_8_7_Date = time.Date(2023, time.July, 15, 0, 0, 0, 0, time.UTC)
	// Updates to the CABF BRs and EVGLs from Ballot SC 062 https://cabforum.org/2023/03/17/ballot-sc62v2-certificate-profiles-update/
	SC62EffectiveDate = time.Date(2023, time.September, 15, 0, 0, 0, 0, time.UTC)
	// Updates to the CABF BRs from Ballot SC 063 https://cabforum.org/2023/07/14/ballot-sc063v4-make-ocsp-optional-require-crls-and-incentivize-automation/
	SC63EffectiveDate = time.Date(2024, time.March, 15, 0, 0, 0, 0, time.UTC)
	// Date when section 9.2.8 of CABF EVG became effective
	CABFEV_Sec9_2_8_Date        = time.Date(2020, time.January, 31, 0, 0, 0, 0, time.UTC)
	CABF_CS_BRs_1_2_Date        = time.Date(2019, time.August, 13, 0, 0, 0, 0, time.UTC)
	CABF_SC081_FIRST_MILESTONE  = time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC)
	CABF_SC081_SECOND_MILESTONE = time.Date(2027, time.March, 15, 0, 0, 0, 0, time.UTC)
	CABF_SC081_THIRD_MILESTONE  = time.Date(2029, time.March, 15, 0, 0, 0, 0, time.UTC)
)

var (
	CABFEV_9_8_2 = CABV170Date
)

var (
	DAY_LENGTH = 86400 * time.Second.Seconds()
)

func FindTimeType(firstDate, secondDate asn1.RawValue) (int, int) {
	return firstDate.Tag, secondDate.Tag
}

// TODO(@cpu): This function is a little bit rough around the edges (especially
// after my quick fixes for the ineffassigns) and would be a good candidate for
// clean-up/refactoring.
func GetTimes(cert *x509.Certificate) (asn1.RawValue, asn1.RawValue) {
	var outSeq, firstDate, secondDate asn1.RawValue
	// Unmarshal into the sequence
	_, err := asn1.Unmarshal(cert.RawTBSCertificate, &outSeq)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	// Start unmarshalling the bytes
	rest, err := asn1.Unmarshal(outSeq.Bytes, &outSeq)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	// This is here to account for if version is not included
	if outSeq.Tag == 0 {
		rest, err = asn1.Unmarshal(rest, &outSeq)
		if err != nil {
			return asn1.RawValue{}, asn1.RawValue{}
		}
	}
	rest, err = asn1.Unmarshal(rest, &outSeq)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	rest, err = asn1.Unmarshal(rest, &outSeq)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	_, err = asn1.Unmarshal(rest, &outSeq)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	// Finally at the validity date, load them into a different RawValue
	rest, err = asn1.Unmarshal(outSeq.Bytes, &firstDate)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	_, err = asn1.Unmarshal(rest, &secondDate)
	if err != nil {
		return asn1.RawValue{}, asn1.RawValue{}
	}
	return firstDate, secondDate
}

// BeforeOrOn returns whether left is before or strictly equal to right.
func BeforeOrOn(left, right time.Time) bool {
	return !left.After(right)
}

// OnOrAfter returns whether left is after or strictly equal to right.
func OnOrAfter(left, right time.Time) bool {
	return !left.Before(right)
}

func CertificateValidityInSeconds(cert *x509.Certificate) float64 {
	return cert.NotAfter.Add(1 * time.Second).Sub(cert.NotBefore).Seconds()
}

func CertificateValidityInDays(cert *x509.Certificate) float64 {
	return math.Ceil(CertificateValidityInSeconds(cert) / DAY_LENGTH)
}

// GreaterThan returns true if the validity of this cert in days is greater than
// this maxDaysAllowed, false otherwise
func GreaterThan(cert *x509.Certificate, maxDaysAllowed float64) bool {
	maxValidity := maxDaysAllowed * DAY_LENGTH
	return CertificateValidityInSeconds(cert) > maxValidity
}
