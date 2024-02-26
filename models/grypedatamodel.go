package models

// VulnerabilityReportList is the struct for the JSON from Grypedata API
type VulnerabilityReportList struct {
	Matches []VulnerabilityReport `json:"matches"`
}

// VulnerabilityReport is the struct for the object present in matches array in the JSON from Grypedata API
type VulnerabilityReport struct {
    Vulnerability Vulnerability `json:"vulnerability"`
    RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities"`
    MatchDetails []MatchDetail `json:"matchDetails"`
    Artifact Artifact `json:"artifact"`
}

// Vulnerability is sub-struct of VulnerabilityReport
type Vulnerability struct {
    ID          string   `json:"id"`
    DataSource  string   `json:"dataSource"`
    Namespace   string   `json:"namespace"`
    Severity    string   `json:"severity"`
    URLs        []string `json:"urls"`
    Description string   `json:"description"`
    Cvss        []Cvss   `json:"cvss"`
    Fix         Fix      `json:"fix"`
}

// Cvss is sub-struct of Vulnerability
type Cvss struct {
    Version         string `json:"version"`
    Vector          string `json:"vector"`
    Metrics         Metrics `json:"metrics"`
    VendorMetadata  VendorMetadata `json:"vendorMetadata"`
}

// Metrics is sub-struct of Cvss
type Metrics struct {
    BaseScore           float64 `json:"baseScore"`
    ExploitabilityScore float64 `json:"exploitabilityScore"`
    ImpactScore         float64 `json:"impactScore"`
}

// VendorMetadata is sub-struct of Cvss
type VendorMetadata struct {
    BaseSeverity string `json:"base_severity"`
    Status       string `json:"status"`
}

// Fix is sub-struct of Vulnerability
type Fix struct {
    Versions []string `json:"versions"`
    State    string   `json:"state"`
}

// RelatedVulnerability is sub-struct of VulnerabilityReport
type RelatedVulnerability struct {
    ID          string   `json:"id"`
    DataSource  string   `json:"dataSource"`
    Namespace   string   `json:"namespace"`
    Severity    string   `json:"severity"`
    URLs        []string `json:"urls"`
    Description string   `json:"description"`
    Cvss        []Cvss   `json:"cvss"`
}

// MatchDetail is sub-struct of VulnerabilityReport
type MatchDetail struct {
    Type       string `json:"type"`
    Matcher    string `json:"matcher"`
    SearchedBy SearchedBy `json:"searchedBy"`
    Found      Found `json:"found"`
}

// SearchedBy is sub-struct of MatchDetail
type SearchedBy struct {
    Language  string `json:"language"`
    Namespace string `json:"namespace"`
    Package   Package `json:"package"`
}

// Package is sub-struct of SearchedBy
type Package struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

// Found is sub-struct of MatchDetail
type Found struct {
    VersionConstraint string `json:"versionConstraint"`
    VulnerabilityID   string `json:"vulnerabilityID"`
}

// Artifact is sub-struct of VulnerabilityReport
type Artifact struct {
    ID        string   `json:"id"`
    Name      string   `json:"name"`
    Version   string   `json:"version"`
    Type      string   `json:"type"`
    Locations []Location `json:"locations"`
    Language  string   `json:"language"`
    Cpes      []string `json:"cpes"`
    Purl      string   `json:"purl"`
}

// Location is sub-struct of Artifact
type Location struct {
    Path string `json:"path"`
}
