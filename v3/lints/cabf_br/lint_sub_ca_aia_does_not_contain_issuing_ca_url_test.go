package cabf_br

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
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

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestSubCaAiaNoIssuerUrl(t *testing.T) {
	inputPath := "subCAWOcspURL.pem"
	expected := lint.Warn
	out := test.TestLint("w_sub_ca_aia_does_not_contain_issuing_ca_url", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCaAiaHasIssuerUrl(t *testing.T) {
	inputPath := "subCAWBothURL.pem"
	expected := lint.Pass
	out := test.TestLint("w_sub_ca_aia_does_not_contain_issuing_ca_url", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCaAiaNoIssuerUrlAfterIneffective(t *testing.T) {
	inputPath := "subCAAIANoIssuerIneffective.pem"
	expected := lint.NE
	out := test.TestLint("w_sub_ca_aia_does_not_contain_issuing_ca_url", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
