package oracleoval

import (
	"errors"
	"os"
	"testing"

	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name           string
		cacheDir       string
		batchUpdateErr error
		expectedError  error
		expectedVulns  []types.Advisory
	}{
		{
			name:     "happy path",
			cacheDir: "testdata",
		},
		{
			name:          "cache dir doesnt exist",
			cacheDir:      "badpathdoesnotexist",
			expectedError: errors.New("error in Oracle Linux OVAL walk: error in file walk: lstat badpathdoesnotexist/vuln-list/oval/oracle: no such file or directory"),
		},
		{
			name:           "unable to save oracle linux oval defintions",
			cacheDir:       "testdata",
			batchUpdateErr: errors.New("unable to batch update"),
			expectedError:  errors.New("error in Oracle Linux OVAL save: error in batch update: unable to batch update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("BatchUpdate", mock.Anything).Return(tc.batchUpdateErr)
			ac := VulnSrc{dbc: mockDBConfig}

			err := ac.Update(tc.cacheDir)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}

func TestVulnSrc_Commit(t *testing.T) {
	type putAdvisoryInput struct {
		source   string
		pkgName  string
		cveID    string
		advisory types.Advisory
	}
	type putAdvisory struct {
		input  putAdvisoryInput
		output error
	}

	type putVulnerabilityDetailInput struct {
		cveID  string
		source string
		vuln   types.VulnerabilityDetail
	}
	type putVulnerabilityDetail struct {
		input  putVulnerabilityDetailInput
		output error
	}

	type putSeverityInput struct {
		cveID    string
		severity types.Severity
	}
	type putSeverity struct {
		input  putSeverityInput
		output error
	}
	testCases := []struct {
		name                       string
		cves                       []OracleOVAL
		putAdvisoryList            []putAdvisory
		putVulnerabilityDetailList []putVulnerabilityDetail
		putSeverityList            []putSeverity
		expectedErrorMsg           string
	}{
		{
			name: "happy path",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
					Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-devel is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: "bind-devel is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "MODERATE",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0493",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0494",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0493",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0493.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0494",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0494.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0493",
						severity: types.SeverityUnknown,
					},
				},
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0494",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path duplicate reference",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
					Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-devel is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: "bind-devel is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "MODERATE",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0493",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0494",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0493",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0493.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0494",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0494.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0493",
						severity: types.SeverityUnknown,
					},
				},
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0494",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path multi platform",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2019-4510: Unbreakable Enterprise kernel security update (IMPORTANT)",
					Description: "[4.1.12-124.24.3]\n- ext4: update i_disksize when new eof exceeds it (Shan Hai)  [Orabug: 28940828] \n- ext4: update i_disksize if direct write past ondisk size (Eryu Guan)  [Orabug: 28940828] \n- ext4: protect i_disksize update by i_data_sem in direct write path (Eryu Guan)  [Orabug: 28940828] \n- ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c (Hui Peng)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Replace probing flag with active refcount (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Avoid nested autoresume calls (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ext4: validate that metadata blocks do not overlap superblock (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: update inline int ext4_has_metadata_csum(struct super_block *sb) (John Donnelly)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: always initialize the crc32c checksum driver (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094} {CVE-2018-1094}\n- Revert 'bnxt_en: Reduce default rings on multi-port cards.' (Brian Maly)  [Orabug: 28687746] \n- mlx4_core: Disable P_Key Violation Traps (Hakon Bugge)  [Orabug: 27693633] \n- rds: RDS connection does not reconnect after CQ access violation error (Venkat Venkatsubra)  [Orabug: 28733324]\n\n[4.1.12-124.24.2]\n- KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL (KarimAllah Ahmed)  [Orabug: 28069548] \n- KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL - reloaded (Mihai Carabas)  [Orabug: 28069548] \n- KVM/x86: Add IBPB support (Ashok Raj)  [Orabug: 28069548] \n- KVM: x86: pass host_initiated to functions that read MSRs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson)  [Orabug: 28069548] \n- KVM: nVMX: fix msr bitmaps to prevent L2 from accessing L0 x2APIC (Radim Krcmar)  [Orabug: 28069548] \n- ocfs2: dont clear bh uptodate for block read (Junxiao Bi)  [Orabug: 28762940] \n- ocfs2: clear journal dirty flag after shutdown journal (Junxiao Bi)  [Orabug: 28924775] \n- ocfs2: fix panic due to unrecovered local alloc (Junxiao Bi)  [Orabug: 28924775] \n- net: rds: fix rds_ib_sysctl_max_recv_allocation error (Zhu Yanjun)  [Orabug: 28947481] \n- x86/speculation: Always disable IBRS in disable_ibrs_and_friends() (Alejandro Jimenez)  [Orabug: 29139710]",
					Platform:    []string{"Oracle Linux 6", "Oracle Linux 7"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2019-4510.html",
							ID:     "ELSA-2019-4510",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2018-1094.html",
							ID:     "CVE-2018-1094",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2018-19824.html",
							ID:     "CVE-2018-19824",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator: "OR",
										Criterias: []Criteria{
											{
												Operator:  "AND",
												Criterias: nil,
												Criterions: []Criterion{
													{
														Comment: "kernel-uek-doc is earlier than 0:4.1.12-124.24.3.el6uek",
													},
													{
														Comment: "kernel-uek-doc is signed with the Oracle Linux 6 key",
													},
												},
											},
											{
												Operator:  "AND",
												Criterias: nil,
												Criterions: []Criterion{
													{
														Comment: "kernel-uek-firmware is earlier than 0:4.1.12-124.24.3.el6uek",
													},
													{
														Comment: "kernel-uek-firmware is signed with the Oracle Linux 6 key",
													},
												},
											},
										},
										Criterions: nil,
									},
								},
								Criterions: []Criterion{
									{
										Comment: "Oracle Linux 6 is installed",
									},
								},
							},
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator: "OR",
										Criterias: []Criteria{
											{
												Operator:  "AND",
												Criterias: nil,
												Criterions: []Criterion{
													{
														Comment: "kernel-uek-doc is earlier than 0:4.1.12-124.24.3.el7uek",
													},
													{
														Comment: "kernel-uek-doc is signed with the Oracle Linux 7 key",
													},
												},
											},
											{
												Operator:  "AND",
												Criterias: nil,
												Criterions: []Criterion{
													{
														Comment: "kernel-uek-firmware is earlier than 0:4.1.12-124.24.3.el7uek",
													},
													{
														Comment: "kernel-uek-firmware is signed with the Oracle Linux 7 key",
													},
												},
											},
										},
										Criterions: nil,
									},
								},
								Criterions: []Criterion{
									{
										Comment: "Oracle Linux 7 is installed",
									},
								},
							},
						},
					},
					Severity: "IMPORTANT",
					Cves: []Cve{
						{
							Impact: "CVE",
							Href:   "http://linux.oracle.com/cve/CVE-2018-1094.html",
							ID:     "CVE-2018-1094",
						},
						{
							Impact: "CVE",
							Href:   "http://linux.oracle.com/cve/CVE-2018-19824.html",
							ID:     "CVE-2018-19824",
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 6",
						pkgName:  "kernel-uek-doc",
						cveID:    "CVE-2018-1094",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el6uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 6",
						pkgName:  "kernel-uek-doc",
						cveID:    "CVE-2018-19824",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el6uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 6",
						pkgName:  "kernel-uek-firmware",
						cveID:    "CVE-2018-1094",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el6uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 6",
						pkgName:  "kernel-uek-firmware",
						cveID:    "CVE-2018-19824",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el6uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 7",
						pkgName:  "kernel-uek-doc",
						cveID:    "CVE-2018-1094",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el7uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 7",
						pkgName:  "kernel-uek-doc",
						cveID:    "CVE-2018-19824",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el7uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 7",
						pkgName:  "kernel-uek-firmware",
						cveID:    "CVE-2018-1094",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el7uek"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 7",
						pkgName:  "kernel-uek-firmware",
						cveID:    "CVE-2018-19824",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.1.12-124.24.3.el7uek"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2018-1094",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[4.1.12-124.24.3]\n- ext4: update i_disksize when new eof exceeds it (Shan Hai)  [Orabug: 28940828] \n- ext4: update i_disksize if direct write past ondisk size (Eryu Guan)  [Orabug: 28940828] \n- ext4: protect i_disksize update by i_data_sem in direct write path (Eryu Guan)  [Orabug: 28940828] \n- ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c (Hui Peng)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Replace probing flag with active refcount (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Avoid nested autoresume calls (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ext4: validate that metadata blocks do not overlap superblock (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: update inline int ext4_has_metadata_csum(struct super_block *sb) (John Donnelly)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: always initialize the crc32c checksum driver (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094} {CVE-2018-1094}\n- Revert 'bnxt_en: Reduce default rings on multi-port cards.' (Brian Maly)  [Orabug: 28687746] \n- mlx4_core: Disable P_Key Violation Traps (Hakon Bugge)  [Orabug: 27693633] \n- rds: RDS connection does not reconnect after CQ access violation error (Venkat Venkatsubra)  [Orabug: 28733324]\n\n[4.1.12-124.24.2]\n- KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL (KarimAllah Ahmed)  [Orabug: 28069548] \n- KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL - reloaded (Mihai Carabas)  [Orabug: 28069548] \n- KVM/x86: Add IBPB support (Ashok Raj)  [Orabug: 28069548] \n- KVM: x86: pass host_initiated to functions that read MSRs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson)  [Orabug: 28069548] \n- KVM: nVMX: fix msr bitmaps to prevent L2 from accessing L0 x2APIC (Radim Krcmar)  [Orabug: 28069548] \n- ocfs2: dont clear bh uptodate for block read (Junxiao Bi)  [Orabug: 28762940] \n- ocfs2: clear journal dirty flag after shutdown journal (Junxiao Bi)  [Orabug: 28924775] \n- ocfs2: fix panic due to unrecovered local alloc (Junxiao Bi)  [Orabug: 28924775] \n- net: rds: fix rds_ib_sysctl_max_recv_allocation error (Zhu Yanjun)  [Orabug: 28947481] \n- x86/speculation: Always disable IBRS in disable_ibrs_and_friends() (Alejandro Jimenez)  [Orabug: 29139710]",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2018-1094.html",
								"http://linux.oracle.com/errata/ELSA-2019-4510.html",
							},
							Title:    "ELSA-2019-4510: Unbreakable Enterprise kernel security update (IMPORTANT)",
							Severity: types.SeverityHigh,
						},
					},
				},
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2018-19824",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[4.1.12-124.24.3]\n- ext4: update i_disksize when new eof exceeds it (Shan Hai)  [Orabug: 28940828] \n- ext4: update i_disksize if direct write past ondisk size (Eryu Guan)  [Orabug: 28940828] \n- ext4: protect i_disksize update by i_data_sem in direct write path (Eryu Guan)  [Orabug: 28940828] \n- ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c (Hui Peng)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Replace probing flag with active refcount (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Avoid nested autoresume calls (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ext4: validate that metadata blocks do not overlap superblock (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: update inline int ext4_has_metadata_csum(struct super_block *sb) (John Donnelly)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: always initialize the crc32c checksum driver (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094} {CVE-2018-1094}\n- Revert 'bnxt_en: Reduce default rings on multi-port cards.' (Brian Maly)  [Orabug: 28687746] \n- mlx4_core: Disable P_Key Violation Traps (Hakon Bugge)  [Orabug: 27693633] \n- rds: RDS connection does not reconnect after CQ access violation error (Venkat Venkatsubra)  [Orabug: 28733324]\n\n[4.1.12-124.24.2]\n- KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL (KarimAllah Ahmed)  [Orabug: 28069548] \n- KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL - reloaded (Mihai Carabas)  [Orabug: 28069548] \n- KVM/x86: Add IBPB support (Ashok Raj)  [Orabug: 28069548] \n- KVM: x86: pass host_initiated to functions that read MSRs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson)  [Orabug: 28069548] \n- KVM: nVMX: fix msr bitmaps to prevent L2 from accessing L0 x2APIC (Radim Krcmar)  [Orabug: 28069548] \n- ocfs2: dont clear bh uptodate for block read (Junxiao Bi)  [Orabug: 28762940] \n- ocfs2: clear journal dirty flag after shutdown journal (Junxiao Bi)  [Orabug: 28924775] \n- ocfs2: fix panic due to unrecovered local alloc (Junxiao Bi)  [Orabug: 28924775] \n- net: rds: fix rds_ib_sysctl_max_recv_allocation error (Zhu Yanjun)  [Orabug: 28947481] \n- x86/speculation: Always disable IBRS in disable_ibrs_and_friends() (Alejandro Jimenez)  [Orabug: 29139710]",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2018-19824.html",
								"http://linux.oracle.com/errata/ELSA-2019-4510.html",
							},
							Title:    "ELSA-2019-4510: Unbreakable Enterprise kernel security update (IMPORTANT)",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2018-1094",
						severity: types.SeverityUnknown,
					},
				},
				{
					input: putSeverityInput{
						cveID:    "CVE-2018-19824",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path multi package",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
					Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-devel is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: "bind-devel is signed with the Oracle Linux 5 key",
											},
										},
									},
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-sdb is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: "bind-sdb is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "MODERATE",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0493",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0494",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-sdb",
						cveID:    "CVE-2007-0493",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-sdb",
						cveID:    "CVE-2007-0494",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "30:9.3.3-8.el5"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0493",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0493.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0494",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0494.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0493",
						severity: types.SeverityUnknown,
					},
				},
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0494",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path epoch 0",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
					Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-devel is earlier than 0:9.3.3-8.el5",
											},
											{
												Comment: "bind-devel is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "MODERATE",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
							ID:     "CVE-2007-0494",
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0493",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "9.3.3-8.el5"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "CVE-2007-0494",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "9.3.3-8.el5"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0493",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0493.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2007-0494",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/cve/CVE-2007-0494.html",
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0493",
						severity: types.SeverityUnknown,
					},
				},
				{
					input: putSeverityInput{
						cveID:    "CVE-2007-0494",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path nonCves",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
					Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
							ID:     "ELSA-2007-0057",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
							ID:     "CVE-2007-0493",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "bind-devel is earlier than 0:9.3.3-8.el5",
											},
											Criterion{
												Comment: "bind-devel is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "MODERATE",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Oracle Linux 5",
						pkgName:  "bind-devel",
						cveID:    "ELSA-2007-0057",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "9.3.3-8.el5"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "ELSA-2007-0057",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
							References: []string{
								"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							},
							Title:    "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "ELSA-2007-0057",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "empty package name",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-0001-0001:  Moderate: empty security update  (N/A)",
					Description: "empty description",
					Platform:    []string{"Oracle Linux 5"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-0001-0001.html",
							ID:     "ELSA-0001-0001",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-0001-0001.html",
							ID:     "CVE-0001-0001",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: " is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: " is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 5 is installed",
							},
						},
					},
					Severity: "N/A",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-0001-0001.html",
							ID:     "CVE-0001-0001",
						},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-0001-0001",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "empty description",
							References: []string{
								"http://linux.oracle.com/cve/CVE-0001-0001.html",
								"http://linux.oracle.com/errata/ELSA-0001-0001.html",
							},
							Title:    "ELSA-0001-0001:  Moderate: empty security update  (N/A)",
							Severity: types.SeverityUnknown,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-0001-0001",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "unknown platform",
			cves: []OracleOVAL{
				{
					Title:       "ELSA-0001-0001:  Moderate: unknown security update  (N/A)",
					Description: "unknown description",
					Platform:    []string{"Oracle Linux 1"},
					References: []Reference{
						{
							Source: "elsa",
							URI:    "http://linux.oracle.com/errata/ELSA-0001-0001.html",
							ID:     "ELSA-0001-0001",
						},
						{
							Source: "CVE",
							URI:    "http://linux.oracle.com/cve/CVE-0001-0001.html",
							ID:     "CVE-0001-0001",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "test is earlier than 30:9.3.3-8.el5",
											},
											{
												Comment: "test is signed with the Oracle Linux 5 key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "Oracle Linux 1 is installed",
							},
						},
					},
					Severity: "N/A",
					Cves: []Cve{
						{
							Impact: "",
							Href:   "http://linux.oracle.com/cve/CVE-0001-0001.html",
							ID:     "CVE-0001-0001",
						},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-0001-0001",
						source: vulnerability.OracleOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "unknown description",
							References: []string{
								"http://linux.oracle.com/cve/CVE-0001-0001.html",
								"http://linux.oracle.com/errata/ELSA-0001-0001.html",
							},
							Title:    "ELSA-0001-0001:  Moderate: unknown security update  (N/A)",
							Severity: types.SeverityUnknown,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-0001-0001",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockDBConfig)

			for _, pa := range tc.putAdvisoryList {
				mockDBConfig.On("PutAdvisory", tx, pa.input.source, pa.input.pkgName,
					pa.input.cveID, pa.input.advisory).Return(pa.output)
			}
			for _, pvd := range tc.putVulnerabilityDetailList {
				mockDBConfig.On("PutVulnerabilityDetail", tx, pvd.input.cveID,
					pvd.input.source, pvd.input.vuln).Return(pvd.output)
			}
			for _, ps := range tc.putSeverityList {
				mockDBConfig.On("PutSeverity", tx, ps.input.cveID,
					ps.input.severity).Return(ps.output)
			}

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.cves)

			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"LOW":       types.SeverityLow,
		"MODERATE":  types.SeverityMedium,
		"IMPORTANT": types.SeverityHigh,
		"CRITICAL":  types.SeverityCritical,
		"N/A":       types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type getAdvisoriesInput struct {
		version string
		pkgName string
	}
	type getAdvisoriesOutput struct {
		advisories []types.Advisory
		err        error
	}
	type getAdvisories struct {
		input  getAdvisoriesInput
		output getAdvisoriesOutput
	}

	testCases := []struct {
		name          string
		version       string
		pkgName       string
		getAdvisories getAdvisories
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path",
			version: "8",
			pkgName: "bind",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "Oracle Linux 8",
					pkgName: "bind",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{
						{VulnerabilityID: "ELSA-2019-1145", FixedVersion: "32:9.11.4-17.P2.el8_0"},
					},
					err: nil,
				},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{{VulnerabilityID: "ELSA-2019-1145", FixedVersion: "32:9.11.4-17.P2.el8_0"}},
		},
		{
			name:    "no advisories are returned",
			version: "8",
			pkgName: "no-package",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "Oracle Linux 8",
					pkgName: "no-package",
				},
				output: getAdvisoriesOutput{advisories: []types.Advisory{}, err: nil},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{},
		},
		{
			name: "oracle GetAdvisories return an error",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: mock.Anything,
					pkgName: mock.Anything,
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{},
					err:        xerrors.New("unable to get advisories"),
				},
			},
			expectedError: errors.New("failed to get Oracle Linux advisories: unable to get advisories"),
			expectedVulns: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("GetAdvisories",
				tc.getAdvisories.input.version, tc.getAdvisories.input.pkgName).Return(
				tc.getAdvisories.output.advisories, tc.getAdvisories.output.err,
			)

			ac := VulnSrc{dbc: mockDBConfig}
			vuls, err := ac.Get(tc.version, tc.pkgName)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expectedVulns, vuls, tc.name)

			mockDBConfig.AssertExpectations(t)
		})
	}
}
