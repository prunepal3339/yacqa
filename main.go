package main

import (
	"os"

	metadata "github.com/prunepal3339/yacqa/metadata"
	log "github.com/sirupsen/logrus"
	command "gitlab.com/gitlab-org/security-products/analyzers/command/v2"
)

func main() {
	app := command.NewApp(metadata.AnalyzerDetails)

	app.Commands = command.NewCommands(command.Config{
		Analyze:      analyze,
		Analyzer:     metadata.AnalyzerDetails,
		AnalyzeFlags: analyzeFlags(),
		AnalyzeAll:   true,
		Convert:      convert,
		Scanner:      metadata.ReportScanner,
		ScanType:     metadata.Type,
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err.Error())
	}
}
