package metadata

import (
	"fmt"
	"os"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v4"
)

const (
	AnalyzerVendor = "GitLab"

	AnalyzerID = "phpcs-security-audit"

	AnalyzerName = scannerName

	analyzerURL = "https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit"

	scannerVendor = AnalyzerVendor
	scannerURL    = "https://github.com/FloeDesignTechnologies/phpcs-security-audit"

	scannerID = "phpcs_security_audit"

	scannerName = "phpcs-security-audit v2"

	Type report.Category = report.CategorySast
)

var (
	AnalyzerVersion = "not-configured"

	ScannerVersion = os.Getenv("SCANNER_VERSION")

	AnalyzerDetails = report.ScannerDetails{
		ID:   AnalyzerID,
		Name: AnalyzerName,
		URL:  analyzerURL,
		Vendor: report.Vendor{
			Name: AnalyzerVendor,
		},
		Version: AnalyzerVersion,
	}

	IssueScanner = report.Scanner{
		ID:   scannerID,
		Name: scannerName,
	}

	ReportScanner = report.ScannerDetails{
		ID:      scannerID,
		Name:    scannerName,
		Version: ScannerVersion,
		Vendor: report.Vendor{
			Name: scannerVendor,
		},
		URL: scannerURL,
	}

	AnalyzerUsage = fmt.Sprintf("%s %s analyzer v%s", AnalyzerVendor, AnalyzerName, AnalyzerVersion)
)
