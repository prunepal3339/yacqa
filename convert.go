package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit/v2/metadata"
	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	ruleset "gitlab.com/gitlab-org/security-products/analyzers/ruleset/v2"
)

func convert(reader io.Reader, prependPath string) (*report.Report, error) {
	var newReport Report

	err := json.NewDecoder(reader).Decode(&newReport)
	if err != nil {
		return nil, err
	}

	root := os.Getenv("ANALYZER_TARGET_DIR")
	if root == "" {
		root = os.Getenv("CI_PROJECT_DIR")
	}

	// Process PHP CodeSniffer report
	vulns := []report.Vulnerability{}
	for path, fileReport := range newReport.Files {
		for _, m := range fileReport.Messages {
			rel := filepath.Join(prependPath, strings.TrimPrefix(path, root))
			vulns = append(vulns, report.Vulnerability{
				Category:    metadata.Type,
				Scanner:     metadata.IssueScanner,
				Name:        m.Message,
				CompareKey:  m.CompareKey(rel),
				Severity:    m.Severity(),
				Location:    m.Location(rel),
				Identifiers: m.Identifiers(),
				Description: m.Message,
			})
		}
	}

	var dsReport = report.NewReport()
	dsReport.Analyzer = metadata.AnalyzerID
	dsReport.Config.Path = ruleset.PathSAST
	dsReport.Vulnerabilities = vulns
	return &dsReport, nil
}

type Report struct {
	Files map[string]FileReport
}

type FileReport struct {
	Messages []Message
}

type Message struct {
	Column  int
	Source  string
	Message string
	Type    string
	Line    int
}

func (m Message) CompareKey(filepath string) string {
	return strings.Join([]string{filepath, m.Source}, ":")
}

func (m Message) Severity() report.SeverityLevel {
	switch m.Type {
	case "ERROR":
		return report.SeverityLevelHigh
	case "WARNING":
		return report.SeverityLevelLow
	}
	return report.SeverityLevelUnknown
}

func (m Message) Location(rel string) report.Location {
	return report.Location{
		File:      rel,
		LineStart: m.Line,
	}
}

func (m Message) Identifiers() []report.Identifier {
	return []report.Identifier{
		m.PSAIdentifier(),
	}
}

func (m Message) PSAIdentifier() report.Identifier {
	return report.Identifier{
		Type:  "phpcs_security_audit_source",
		Name:  m.Source,
		Value: m.Source,
	}
}
