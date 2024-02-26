package jsonhandler

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"github.com/CloudDefenseAI/datahandler/models"
)

// ReadJsonFileIntoGrypeDataModel is a function to read the JSON file into the Grype Data Model
// {
//		argument: filepath
// 		return: VulnerabilityReportList, error
// }
func ReadJsonFileIntoGrypeDataModel(
	filepath string,
) (models.VulnerabilityReportList, error) {

	jsonData, err := os.ReadFile(filepath)

	var vulnerabilityReportList models.VulnerabilityReportList

	if err != nil {
		return vulnerabilityReportList,
			fmt.Errorf("failed to read file with error: %s", err)
	}

	err = json.Unmarshal(jsonData, &vulnerabilityReportList)

	if err != nil {
		return vulnerabilityReportList,
			fmt.Errorf("failed to unmarshal JSON with error: %s", err)
	}

	return vulnerabilityReportList, nil
}

// ProcessGrypeDataModel is a function to process the JSON data from Grype into the ReportList
// {
// 		argument: VulnerabilityReportList
// 		return: ReportList, error
//}
func ProcessGrypeDataModel(
	vulnerabilityReportList models.VulnerabilityReportList,
) (models.ReportList, error) {

	lengthOfMatches := len(vulnerabilityReportList.Matches)

	var finalReport models.ReportList

	if lengthOfMatches == 0 {
		return finalReport,
			fmt.Errorf("no vulnerabilities found in the JSON file")
	}

	for _, vulnerabilityReport := range vulnerabilityReportList.Matches {
		if !containsGHSA(vulnerabilityReport.Vulnerability.ID) {
			var report models.Report

			report.CVE = vulnerabilityReport.Vulnerability.ID

			// report.DataSource = vulnerabilityReport.Vulnerability.DataSource
			// if DataSource is not empty
			if vulnerabilityReport.Vulnerability.DataSource != "" {
				report.DataSource = vulnerabilityReport.Vulnerability.DataSource
			}

			// logic to handle Vulnerability.URLs,
			// if it is not empty then add each URL to report.URLs
			if len(vulnerabilityReport.Vulnerability.URLs) > 0 {
				report.URLs = append(report.URLs, vulnerabilityReport.Vulnerability.URLs...)
			}

			if vulnerabilityReport.Vulnerability.Description != "" {
				report.Description = vulnerabilityReport.Vulnerability.Description
			}

			// Need to ask Shivang what is Reject_SEV
			if vulnerabilityReport.Vulnerability.Severity != "" {
				report.Severity = vulnerabilityReport.Vulnerability.Severity
			}

			if vulnerabilityReport.Artifact.Name != "" {
				report.Package = vulnerabilityReport.Artifact.Name
			}

			// Need to ask Shivang about change_package_type
			if vulnerabilityReport.Artifact.Type != "" {
				report.TypeOfPackage = vulnerabilityReport.Artifact.Type
			}

			if vulnerabilityReport.Artifact.Version != "" {
				report.Version = vulnerabilityReport.Artifact.Version
			}

			if len(vulnerabilityReport.Artifact.Locations) > 0 {
				for _, location := range vulnerabilityReport.Artifact.Locations {
					report.Location = append(report.Location, location.Path)
				}
			}

			if vulnerabilityReport.Artifact.Language != "" {
				report.Type = "Operating System"
			}else {
				report.Type = "Installed Application"
			}

			finalReport.Reports = append(finalReport.Reports, report)

		} 
	}

	return finalReport, nil
}

// containsGHSA is a function to check if the input string contains "GHSA"
// {
//		argument: input string
// 		return: bool
// }
func containsGHSA(input string) bool {
	return strings.Contains(input, "GHSA")
}

// WriteReportListIntoJsonFile is a function to write the ReportList into a JSON file
// {
//		argument: ReportList, filepath
// 		return: error
// }
func WriteReportListIntoJsonFile(
	reportList models.ReportList,
	filepath string,
) error {

	jsonData, err := json.MarshalIndent(reportList, "", "  ")

	if err != nil {
		return fmt.Errorf("failed to marshal JSON with error: %s", err)
	}

	err = os.WriteFile(filepath, jsonData, 0644)

	if err != nil {
		return fmt.Errorf("failed to write file with error: %s", err)
	}

	return nil
}