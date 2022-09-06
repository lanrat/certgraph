package censys

import "time"

// cSpell:ignore spki noct zlint fatals precert

type certSearchParam struct {
	Query   string   `json:"query"`
	Page    uint     `json:"page"`
	Fields  []string `json:"fields"`
	Flatten bool     `json:"flatten"`
}

type certSearchResponse struct {
	Status   string `json:"status"`
	Metadata struct {
		Query       string `json:"query"`
		Count       uint   `json:"count"`
		BackendTime uint   `json:"backend_time"`
		Page        uint   `json:"page"`
		Pages       uint   `json:"pages"`
	} `json:"metadata"`
	Results []struct {
		Names       []string `json:"parsed.names"`
		Fingerprint string   `json:"parsed.fingerprint_sha256"`
	} `json:"results"`
}

type certViewResponse struct {
	Raw                          string `json:"raw"`
	FingerprintSha256            string `json:"fingerprint_sha256"`
	ParentSpkiSubjectFingerprint string `json:"parent_spki_subject_fingerprint"`
	Metadata                     struct {
		PostProcessedAt time.Time `json:"post_processed_at"`
		PostProcessed   bool      `json:"post_processed"`
		Source          string    `json:"source"`
		ParseVersion    int       `json:"parse_version"`
		ParseStatus     string    `json:"parse_status"`
		AddedAt         time.Time `json:"added_at"`
		UpdatedAt       time.Time `json:"updated_at"`
		SeenInScan      bool      `json:"seen_in_scan"`
	} `json:"metadata"`
	Ct struct {
		GoogleXenon2022 struct {
			Index        int       `json:"index"`
			CtToCensysAt time.Time `json:"ct_to_censys_at"`
			AddedToCtAt  time.Time `json:"added_to_ct_at"`
		} `json:"google_xenon_2022"`
	} `json:"ct"`
	Parsed struct {
		Version            int    `json:"version"`
		SerialNumber       string `json:"serial_number"`
		SignatureAlgorithm struct {
			Name string `json:"name"`
			Oid  string `json:"oid"`
		} `json:"signature_algorithm"`
		Issuer struct {
			CommonName   []string `json:"common_name"`
			Country      []string `json:"country"`
			Organization []string `json:"organization"`
		} `json:"issuer"`
		IssuerDn string `json:"issuer_dn"`
		Validity struct {
			Start  time.Time `json:"start"`
			End    time.Time `json:"end"`
			Length int       `json:"length"`
		} `json:"validity"`
		Subject struct {
			CommonName []string `json:"common_name"`
		} `json:"subject"`
		SubjectDn      string `json:"subject_dn"`
		SubjectKeyInfo struct {
			KeyAlgorithm struct {
				Name string `json:"name"`
			} `json:"key_algorithm"`
			EcdsaPublicKey struct {
				B      string `json:"b"`
				Curve  string `json:"curve"`
				Gx     string `json:"gx"`
				Gy     string `json:"gy"`
				Length int    `json:"length"`
				N      string `json:"n"`
				P      string `json:"p"`
				Pub    string `json:"pub"`
				X      string `json:"x"`
				Y      string `json:"y"`
			} `json:"ecdsa_public_key"`
			FingerprintSha256 string `json:"fingerprint_sha256"`
		} `json:"subject_key_info"`
		Extensions struct {
			KeyUsage struct {
				DigitalSignature bool `json:"digital_signature"`
				Value            int  `json:"value"`
			} `json:"key_usage"`
			BasicConstraints struct {
				IsCa bool `json:"is_ca"`
			} `json:"basic_constraints"`
			SubjectAltName struct {
				DNSNames []string `json:"dns_names"`
			} `json:"subject_alt_name"`
			AuthorityKeyID   string `json:"authority_key_id"`
			SubjectKeyID     string `json:"subject_key_id"`
			ExtendedKeyUsage struct {
				ServerAuth bool `json:"server_auth"`
				ClientAuth bool `json:"client_auth"`
			} `json:"extended_key_usage"`
			CertificatePolicies []struct {
				ID  string   `json:"id"`
				Cps []string `json:"cps,omitempty"`
			} `json:"certificate_policies"`
			AuthorityInfoAccess struct {
				OcspUrls   []string `json:"ocsp_urls"`
				IssuerUrls []string `json:"issuer_urls"`
			} `json:"authority_info_access"`
			SignedCertificateTimestamps []struct {
				Version   int    `json:"version"`
				LogID     string `json:"log_id"`
				Timestamp int    `json:"timestamp"`
				Signature string `json:"signature"`
			} `json:"signed_certificate_timestamps"`
		} `json:"extensions"`
		Signature struct {
			SignatureAlgorithm struct {
				Name string `json:"name"`
				Oid  string `json:"oid"`
			} `json:"signature_algorithm"`
			Value      string `json:"value"`
			Valid      bool   `json:"valid"`
			SelfSigned bool   `json:"self_signed"`
		} `json:"signature"`
		FingerprintMd5         string   `json:"fingerprint_md5"`
		FingerprintSha1        string   `json:"fingerprint_sha1"`
		FingerprintSha256      string   `json:"fingerprint_sha256"`
		TbsNoctFingerprint     string   `json:"tbs_noct_fingerprint"`
		SpkiSubjectFingerprint string   `json:"spki_subject_fingerprint"`
		TbsFingerprint         string   `json:"tbs_fingerprint"`
		ValidationLevel        string   `json:"validation_level"`
		Names                  []string `json:"names"`
		Redacted               bool     `json:"redacted"`
	} `json:"parsed"`
	Tags       []string `json:"tags"`
	Validation struct {
		Nss struct {
			Blacklisted     bool       `json:"blacklisted"`
			HadTrustedPath  bool       `json:"had_trusted_path"`
			InRevocationSet bool       `json:"in_revocation_set"`
			TrustedPath     bool       `json:"trusted_path"`
			WasValid        bool       `json:"was_valid"`
			Whitelisted     bool       `json:"whitelisted"`
			Paths           [][]string `json:"paths"`
			Parents         []string   `json:"parents"`
			Type            string     `json:"type"`
			Valid           bool       `json:"valid"`
		} `json:"nss"`
		Microsoft struct {
			Blacklisted     bool       `json:"blacklisted"`
			HadTrustedPath  bool       `json:"had_trusted_path"`
			InRevocationSet bool       `json:"in_revocation_set"`
			TrustedPath     bool       `json:"trusted_path"`
			WasValid        bool       `json:"was_valid"`
			Whitelisted     bool       `json:"whitelisted"`
			Paths           [][]string `json:"paths"`
			Parents         []string   `json:"parents"`
			Type            string     `json:"type"`
			Valid           bool       `json:"valid"`
		} `json:"microsoft"`
		Apple struct {
			Blacklisted     bool       `json:"blacklisted"`
			HadTrustedPath  bool       `json:"had_trusted_path"`
			InRevocationSet bool       `json:"in_revocation_set"`
			TrustedPath     bool       `json:"trusted_path"`
			WasValid        bool       `json:"was_valid"`
			Whitelisted     bool       `json:"whitelisted"`
			Paths           [][]string `json:"paths"`
			Parents         []string   `json:"parents"`
			Type            string     `json:"type"`
			Valid           bool       `json:"valid"`
		} `json:"apple"`
		Revoked         bool `json:"revoked"`
		GoogleCtPrimary struct {
			Blacklisted     bool       `json:"blacklisted"`
			HadTrustedPath  bool       `json:"had_trusted_path"`
			InRevocationSet bool       `json:"in_revocation_set"`
			TrustedPath     bool       `json:"trusted_path"`
			WasValid        bool       `json:"was_valid"`
			Whitelisted     bool       `json:"whitelisted"`
			Paths           [][]string `json:"paths"`
			Parents         []string   `json:"parents"`
			Type            string     `json:"type"`
			Valid           bool       `json:"valid"`
		} `json:"google_ct_primary"`
		OcspRevocation struct {
			NextUpdate time.Time `json:"next_update"`
			Revoked    bool      `json:"revoked"`
		} `json:"ocsp_revocation"`
		CrlRevocation struct {
			Revoked bool `json:"revoked"`
		} `json:"crl_revocation"`
		CrlError string `json:"crl_error"`
	} `json:"validation"`
	Zlint struct {
		NoticesPresent  bool `json:"notices_present"`
		WarningsPresent bool `json:"warnings_present"`
		ErrorsPresent   bool `json:"errors_present"`
		FatalsPresent   bool `json:"fatals_present"`
		Lints           struct {
			NSubjectCommonNameIncluded bool `json:"n_subject_common_name_included"`
		} `json:"lints"`
		Version int `json:"version"`
	} `json:"zlint"`
	Precert bool `json:"precert"`
}

type errorResponse struct {
	Error     string `json:"error"`
	ErrorCode int    `json:"error_code"`
}
