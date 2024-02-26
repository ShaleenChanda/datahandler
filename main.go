package main

import (
	"fmt"
	"github.com/CloudDefenseAI/datahandler/filehandles"
	"github.com/CloudDefenseAI/datahandler/models"
)

func main() {
	filepath := "grype.json"

	var vulnerabilityReportList models.VulnerabilityReportList

	vulnerabilityReportList, err := jsonhandler.ReadJsonFileIntoGrypeDataModel(filepath)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(len(vulnerabilityReportList.Matches))

	reportList, err := jsonhandler.ProcessGrypeDataModel(vulnerabilityReportList)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(reportList.Reports[2])

	fmt.Println(len(reportList.Reports))

	err = jsonhandler.WriteReportListIntoJsonFile(reportList, "report.json")

	if err != nil {
		fmt.Println(err)
	}
}