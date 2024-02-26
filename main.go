package main

import (
	"fmt"
	"github.com/CloudDefenseAI/datahandler/filehandlers"
	"github.com/CloudDefenseAI/datahandler/models"
)

func main() {
	filepath := "grype.json"

	var vulnerabilityReportList models.VulnerabilityReportList

	vulnerabilityReportList, err := jsonhandler.ReadJsonFileIntoGrypeDataModel(filepath)
	if err != nil {
		fmt.Println(err)
	}


	temp := []string{"Unknown", "Negligible"}
	temp2 := map[string]string{"go-module":"GO", "java-archive": "Java", "deb":"Debian"}
	
	reportList, err := jsonhandler.ProcessGrypeDataModel(vulnerabilityReportList, temp, temp2)
	if err != nil {
		fmt.Println(err)
	}

	err = jsonhandler.WriteReportListIntoJsonFile(reportList, "report.json")

	if err != nil {
		fmt.Println(err)
	}
}