package g3

type ScanMetadata struct {
	ScanID string          `json:"scanid"           validate:"required,uuid"`
	Config *ReportConfig   `json:"config,omitempty" validate:"omitempty"`
}

// ReportConfig mirrors Magenta's SCHEMA_METADATA exactly: it carries the
// report-rendering options the Magenta reporter understands. Every field is
// optional; absent fields fall back to Magenta's DEFAULT_METADATA at render
// time, so we keep omitempty throughout to preserve the absent-vs-set
// distinction rather than forcing zero values onto the wire.
type ReportConfig struct {
	Title             string                 `json:"title,omitempty"                   validate:"omitempty"`
	Language          string                 `json:"language,omitempty"                validate:"omitempty"`
	MinSeverity       string                 `json:"min_severity,omitempty"            validate:"omitempty,oneof=none low medium high critical"`
	ChartType         string                 `json:"chart_type,omitempty"              validate:"omitempty,oneof=none pie bars"`
	ShowEmptySummary  bool                   `json:"show_empty_summary,omitempty"      validate:"omitempty"`
	ShowEmptyChart    bool                   `json:"show_empty_chart,omitempty"        validate:"omitempty"`
	SeverityColors    *ReportSeverityColors  `json:"severity_colors,omitempty"         validate:"omitempty"`
	ReportSectionsOrder   []string           `json:"report_sections_order,omitempty"   validate:"omitempty,dive,oneof=header summary tools issues notes"`
	IssueSubsectionsOrder []string           `json:"issue_subsections_order,omitempty" validate:"omitempty,dive,oneof=severity affects taxonomy description details recommendations tools references"`
	ProjectInfo       *ReportProjectInfo     `json:"project_info,omitempty"            validate:"omitempty"`
}

// ReportSeverityColors mirrors the fixed-key severity_colors object from
// Magenta's schema. Keys are the closed SEVERITY_KEYS set, so they're modeled
// as struct fields rather than a map. Magenta's pattern requires exactly six
// hex digits (^#[0-9A-Fa-f]{6}$); validator's built-in hexcolor is the closest
// match but also accepts 3/4/8-digit forms (it has no inline-regex option).
type ReportSeverityColors struct {
	None     string `json:"none,omitempty"     validate:"omitempty,hexcolor"`
	Low      string `json:"low,omitempty"      validate:"omitempty,hexcolor"`
	Medium   string `json:"medium,omitempty"   validate:"omitempty,hexcolor"`
	High     string `json:"high,omitempty"     validate:"omitempty,hexcolor"`
	Critical string `json:"critical,omitempty" validate:"omitempty,hexcolor"`
}

// ReportProjectInfo mirrors Magenta's project_info object. In the schema all
// eight fields are required *when project_info is present*, so each carries a
// required tag; validator only descends here when the parent pointer is non-nil.
type ReportProjectInfo struct {
	ReportTeam   string `json:"report_team"   validate:"required"` // Your company or team.
	ReportAuthor string `json:"report_author" validate:"required"` // Your name.
	ClientName   string `json:"client_name"   validate:"required"` // The client company.
	ProductName  string `json:"product_name"  validate:"required"` // The product being pentested.
	TestType     string `json:"test_type"     validate:"required"` // Kind of pentest.
	StartDate    string `json:"start_date"    validate:"required"` // Start of testing window.
	EndDate      string `json:"end_date"      validate:"required"` // End of testing window.
	ReportDate   string `json:"report_date"   validate:"required"` // When the report is due.
}
