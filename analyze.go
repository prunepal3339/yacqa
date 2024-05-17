package main

import (
	"io"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit/plugin"
)

const (
	flagParanoiaMode  = "paranoia-mode"
	flagPHPExtensions = "extensions"

	pathHome        = "/home/php"
	pathCodeSniffer = "./vendor/bin/phpcs"
	pathOutput      = "/tmp/output.json"
	pathRuleset     = "ruleset.xml"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    flagParanoiaMode,
			Usage:   "phpcs-security-audit paranoia mode",
			EnvVars: []string{"PHPCS_SECURITY_AUDIT_PARANOIA_MODE"},
		},
		&cli.StringFlag{
			Name:    flagPHPExtensions,
			Usage:   "Comma separated list of additional PHP Extensions",
			EnvVars: []string{"PHPCS_SECURITY_AUDIT_PHP_EXTENSIONS"},
		},
	}
}

func analyze(c *cli.Context, path string) (io.ReadCloser, error) {
	var (
		phpExtensions = append(plugin.PhpExtensions, "inc", "lib", "module", "info")
		paranoiaMode  = "0"
	)

	// Convert paranoia mode
	if c.Bool(flagParanoiaMode) {
		paranoiaMode = "1"
	}

	// Handle adding more file extensions if set
	if c.IsSet(flagPHPExtensions) {
		phpExtensions = append(phpExtensions, strings.Split(c.String(flagPHPExtensions), ",")...)
	}

	// Run CodeSniffer with phpcs-security-audit rules
	args := []string{
		"--extensions=" + strings.Join(phpExtensions, ","),
		"--standard=" + pathRuleset,
		"--report=json",
		"--report-file=" + pathOutput,
		"--runtime-set", "ParanoiaMode", paranoiaMode,
		path,
	}
	cmd := exec.Command(pathCodeSniffer, args...)
	cmd.Dir = pathHome
	cmd.Env = os.Environ()

	output, _ := cmd.CombinedOutput()
	log.Debugf("%s\n%s", cmd.String(), output)

	return os.Open(pathOutput)
}
