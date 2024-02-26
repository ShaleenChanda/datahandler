package models

// ReportList is the struct to store output report data
type ReportList struct {
	Reports []Report `json:"reports"`
}

// Report is the struct for the object to store vulnerability report
type Report struct {
	CVE           string   `json:"cve"`
	DataSource    string   `json:"dataSource"`
	URLs          []string `json:"urls"`
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	TypeOfPackage string   `json:"typeOfPackage"`
	Location      []string `json:"location"`
	Type          string   `json:"type"`
}