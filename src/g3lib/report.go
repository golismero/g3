package g3lib

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type ReportConfig struct {
	MinSeverity         int      `json:"min_severity"`
	ReportSectionsOrder []string `json:"report_sections_order"`
	IssueSectionsOrder  []string `json:"issue_sections_order"`
}

var DefaultConfig = ReportConfig {
	MinSeverity:         0,
	ReportSectionsOrder: []string{"header", "summary", "tools", "issues"},
	IssueSectionsOrder:  []string{"severity", "affects", "description", "recommendations", "details", "taxonomy", "references"},
}

type MarkdownReporter struct {
	config       ReportConfig
	plugins      G3PluginMetadata
	templates    G3PluginTemplatesCache
	translations G3TranslatedStrings
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Constructor for the MarkdownReporter class.
func NewMarkdownReporter(config ReportConfig, plugins G3PluginMetadata, templates G3PluginTemplatesCache, translations G3TranslatedStrings) MarkdownReporter {
	var reporter MarkdownReporter
	reporter.config       = config
	reporter.plugins      = plugins
	reporter.templates    = templates
	reporter.translations = translations
	return reporter
}

// Generates a Markdown text for a report.
func (reporter *MarkdownReporter) Build(lang, title string, inputArray []G3Data, tools []string) (string, []error) {

	// Build the report sections.
	reportSections, _, errorArray := reporter.BuildReportSections(lang, title, inputArray, tools)

	// Concatenate the report sections in order.
	orderedSections := []string{}
	if len(reportSections) > 0 {
		for _, name := range reporter.config.ReportSectionsOrder {
			if text, ok := reportSections[name]; ok {
				orderedSections = append(orderedSections, text)
			}
		}
	}
	return strings.Join(orderedSections, "\n"), errorArray
}

// Generates a Markdown text for a report, split into sections.
func (reporter *MarkdownReporter) BuildReportSections(lang, title string, inputArray []G3Data, tools []string) (map[string]string, []map[string]string, []error) {
	var errorArray []error
	L := reporter.translations[lang]

	// We'll save the report text here.
	reportSections := map[string]string{}

	// Count how many issues we have.
	totalVulnCount := 0
	lowVulnCount := 0
	mediumVulnCount := 0
	highVulnCount := 0
	criticalVulnCount := 0
	issueArray := []G3Data{}
	for _, data := range inputArray {
		if data["_type"].(string) != "issue" {
			continue
		}
		severityVal := int(data["severity"].(float64))
		if severityVal >= reporter.config.MinSeverity {
			issueArray = append(issueArray, data)
			switch severityVal {
			case 0:
				lowVulnCount++
			case 1:
				mediumVulnCount++
			case 2:
				highVulnCount++
			case 3:
				criticalVulnCount++
			}
		}
	}
	totalVulnCount = lowVulnCount + mediumVulnCount + highVulnCount + criticalVulnCount

	// Build the Markdown text for all of the issues.
	issues, errA := reporter.BuildAllIssues(lang, issueArray)
	if len(errA) > 0 {
		errorArray = append(errorArray, errA...)
	}

	// Build the report header.
	reportHeader := fmt.Sprintf("# %s\n", title)
	counts := make(map[string]int)
	counts["critical"] = criticalVulnCount
	counts["high"] = highVulnCount
	counts["medium"] = mediumVulnCount
	counts["low"] = lowVulnCount
	counts["total"] = totalVulnCount
	countText, err := ExpandTemplate(L["issue_count_template"], counts)
	if err != nil {
		errorArray = append(errorArray, err)
	} else {
		reportHeader = reportHeader + countText + "\n\n"
	}																		// https://htmlcolorcodes.com/colors/
	styleCritical := chart.Style{FillColor: drawing.ColorFromHex("9F2B68")}	// Amaranth
	styleHigh := chart.Style{FillColor: drawing.ColorFromHex("D2042D")}		// Cherry
	styleMedium := chart.Style{FillColor: drawing.ColorFromHex("EC5800")}	// Persimmon
	styleLow := chart.Style{FillColor: drawing.ColorFromHex("FFBF00")}		// Amber
	pie := chart.PieChart{
		Width:  512,
		Height: 512,
		Values: []chart.Value{
			{Value: float64(counts["critical"]), Label: L["CRITICAL"], Style: styleCritical},
			{Value: float64(counts["high"]), Label: L["HIGH"], Style: styleHigh},
			{Value: float64(counts["medium"]), Label: L["MEDIUM"], Style: styleMedium},
			{Value: float64(counts["low"]), Label: L["LOW"], Style: styleLow},
		},
	}
	buffer := bytes.NewBuffer([]byte{})
	err = pie.Render(chart.PNG, buffer)
	if err != nil {
		errorArray = append(errorArray, err)
	} else {
		data := make([]byte, base64.StdEncoding.EncodedLen(buffer.Len()))
		base64.StdEncoding.Encode(data, buffer.Bytes())
		pieChartText, err := ExpandTemplate(L["issue_chart_header"], string(data))
		if err != nil {
			errorArray = append(errorArray, err)
		} else {
			reportHeader = reportHeader + pieChartText + "\n\n"
		}
	}
	if strings.HasSuffix(reportHeader, "\n\n") {
		reportHeader = reportHeader[:len(reportHeader)-1]
	}
	reportSections["header"] = reportHeader

	// Build the tools section.
	if len(tools) > 0 {
		ok := true
		for _, name := range tools {
			_, ok := reporter.plugins[name]
			if !ok {
				errorArray = append(errorArray, errors.New("missing tool: " + name))
				break
			}
		}
		if ok {
			toolsText := ""
			toolsText = toolsText + fmt.Sprintf("# %s\n", L["tools"])
			toolsText = toolsText + fmt.Sprintf("%s\n\n", L["tools_header"])
			toolsText = toolsText + fmt.Sprintf("| %s | %s | %s |\n", L["name"], L["link"], L["description"])
			toolsText = toolsText + "| --- | --- | --- |\n"
			for _, name := range tools {
				plugin := reporter.plugins[name]
				pluginDescription, ok := plugin.Description[lang]
				if !ok {
					pluginDescription, ok = plugin.Description["en"]
					if !ok {
						errorArray = append(errorArray, errors.New("invalid tools section"))
					}
				}
				if ok {
					toolsText = toolsText + fmt.Sprintf("| %s | [%s](%s) | %s |\n", plugin.Name, plugin.URL, plugin.URL, pluginDescription)
				}
			}
			reportSections["tools"] = toolsText
		}
	}

	// Build the issues summary table.
	if totalVulnCount > 1 {
		lowSummaryTable := fmt.Sprintf("\n| %s |\n| --- |\n", L["issues_low"])
		mediumSummaryTable := fmt.Sprintf("\n| %s |\n| --- |\n", L["issues_medium"])
		highSummaryTable := fmt.Sprintf("\n| %s |\n| --- |\n", L["issues_high"])
		criticalSummaryTable := fmt.Sprintf("\n| %s |\n| --- |\n", L["issues_critical"])
		trLow := L["LOW"]
		trMedium := L["MEDIUM"]
		trHigh := L["HIGH"]
		trCritical := L["CRITICAL"]
		for index, issue := range issues {
			switch issue["severity"] {
			case trLow:
				lowSummaryTable = lowSummaryTable + fmt.Sprintf("| ***%d: %s***<br>%s |\n", index + 1, issue["title"], issue["summary"])
			case trMedium:
				mediumSummaryTable = mediumSummaryTable + fmt.Sprintf("| ***%d: %s***<br>%s |\n", index + 1, issue["title"], issue["summary"])
			case trHigh:
				highSummaryTable = highSummaryTable + fmt.Sprintf("| ***%d: %s***<br>%s |\n", index + 1, issue["title"], issue["summary"])
			case trCritical:
				criticalSummaryTable = criticalSummaryTable + fmt.Sprintf("| ***%d: %s***<br>%s |\n", index + 1, issue["title"], issue["summary"])
			}
		}
		summaryText := "# " + L["summary"] + "\n"
		if criticalVulnCount > 0 {
			summaryText = summaryText + criticalSummaryTable
		}
		if highVulnCount > 0 {
			summaryText = summaryText + highSummaryTable
		}
		if mediumVulnCount > 0 {
			summaryText = summaryText + mediumSummaryTable
		}
		if lowVulnCount > 0 {
			summaryText = summaryText + lowSummaryTable
		}
		reportSections["summary"] = summaryText
	}

	// Build the issues section.
	if len(issues) > 0 {
		reportSections["issues"] = reporter.BuildIssuesSection(lang, issues)
	}

	// Return the map of parsed sections.
	return reportSections, issues, errorArray
}

// Concatenates the issues in order.
func (reporter *MarkdownReporter) BuildIssuesSection(lang string, issues []map[string]string) string {
	L := reporter.translations[lang]
	issuesText := ""
	if len(issues) > 0 {
		issuesText = "# " + L["issues"] + "\n"
		for index, issue := range issues {
			issuesText = issuesText + fmt.Sprintf("## %d: %s\n", index + 1, issue["title"])
			for _, sectionName := range reporter.config.IssueSectionsOrder {
				sectionText := issue[sectionName]
				if sectionText != "" {
					issuesText = issuesText + "\n### " + L[sectionName] + "\n" + sectionText + "\n"
				}
			}
			issuesText = issuesText + "\n"
		}
	}
	return issuesText
}

// Filter out an input array looking only for issues.
// Sort the issues by severity and title.
// Generate the Markdown text for each one of them.
func (reporter *MarkdownReporter) BuildAllIssues(lang string, inputArray []G3Data) ([]map[string]string, []error) {
	var errorArray []error

	// Iterate over the input data, filtering out non issues, and sorting them by severity.
	crit_issues := [4][]G3Data{}
	crit_issues[0] = []G3Data{}
	crit_issues[1] = []G3Data{}
	crit_issues[2] = []G3Data{}
	crit_issues[3] = []G3Data{}
	for _, data := range inputArray {

		// Ignore all data that is not an issue.
		if data["_type"].(string) != "issue" {
			continue
		}

		// Get the severity for the issue.
		severityVal := int(data["severity"].(float64))

		// Add the issue to the corresponding bucket.
		crit_issues[severityVal] = append(crit_issues[severityVal], data)
	}

	// Build the issues sections and sort them by title.
	issues := []map[string]string{}
	for severityVal := 3; severityVal >= reporter.config.MinSeverity; severityVal-- {
		dataList := crit_issues[severityVal]

		// Build the sections for the issues in this severity level.
		parsedIssues := []map[string]string{}
		for _, data := range dataList {
			sections, errA := reporter.BuildIssue(lang, data)
			if len(errA) > 0 {
				errorArray = append(errorArray, errA...)
			}
			parsedIssues = append(parsedIssues, sections)
		}

		// Sort them by title.
		sort.Slice(parsedIssues, func(i, j int) bool {
			iIssue := parsedIssues[i]
			jIssue := parsedIssues[j]
			iTitle := iIssue["title"]
			jTitle := jIssue["title"]
			return iTitle < jTitle
		})

		// Append them to the complete list of parser issues.
		issues = append(issues, parsedIssues...)
	}

	// Return the parsed and sorted list of issues.
	return issues, errorArray
}

// Generates a Markdown text for an issue.
func (reporter *MarkdownReporter) BuildIssue(lang string, issue G3Data) (map[string]string, []error) {
	var errorArray []error
	var err error

	L := reporter.translations[lang]
	severityRating := [...]string{L["LOW"], L["MEDIUM"], L["HIGH"], L["CRITICAL"]}

	// Issues are reported using sections. These are the supported sections:
	//
	// Title:
	//  Single line with the title of the issue.
	//
	// Severity:
	//  Integer representing the severity level: LOW (0), MEDIUM (1), HIGH (2), CRITICAL (3)
	//
	// Summary:
	//  Single paragraph with a short summary of the issue.
	//
	// Taxonomy:
	//  List of taxonomy tags, such as CVE or CWE for example.
	//
	// Affects:
	//  List of affected resources.
	//
	// Description:
	//  Multiple paragraphs with a longer description of the issue type.
	//
	// Recommendations:
	//  Multiple paragraphs with a list of recommendations for this type of issue.
	//
	// References:
	//  List of links with external references.
	//
	// Details:
	//  Multiple paragraphs with a detailed description of this instance of the issue.
	//
	sections := map[string]string{}

	// Make sure this is an issue and not some random data.
	if datatype, ok := issue["_type"]; !ok || datatype != "issue" {
		panic("Malformed data received!")
	}

	// Get the strings for this plugin and this language.
	// If the language is not supported, default to English.
	tool, ok := issue["_tool"].(string)
	if !ok {
		panic("Malformed data received!")
	}
	pluginTemplatesAllLangs, ok := reporter.templates[tool]
	if ! ok {
		errorArray = append(errorArray, errors.New("Plugin " + tool + "does not define i18n templates"))
		return sections, errorArray
	}
	pluginTemplate, ok := pluginTemplatesAllLangs[lang]
	if ! ok {
		pluginTemplate, ok = pluginTemplatesAllLangs["en"]
		if ! ok {
			panic("Malformed i18n templates!")
		}
	}

	// Build the title.
	title := "title"
	value, ok := issue["title"]
	if ok {
		title = value.(string)
	}
	title, err = ExpandTemplate(fmt.Sprintf("%s{{template \"%s\" .}}", pluginTemplate, title), issue)
	if err != nil {
		errorArray = append(errorArray, err)
	}
	sections["title"] = title

	// Build the severity section.
	severityVal := int(issue["severity"].(float64))
	severity := severityRating[severityVal]
	sections["severity"] = L[severity]

	// Build the taxonomy section.
	sections["taxonomy"] = buildIssueTaxonomySection(issue, "taxonomy")

	// Build the simple sections.
	for _, name := range [...]string{"affects", "references"} {
		sections[name], err = buildIssueSimpleSection(pluginTemplate, issue, name)
		if err != nil {
			errorArray = append(errorArray, err)
		}
	}

	// Build the paragraph sections.
	for _, name := range [...]string{"summary", "description", "recommendations", "details"} {
		sections[name], err = buildIssueParagraphSection(pluginTemplate, issue, name)
		if err != nil {
			errorArray = append(errorArray, err)
		}
	}

	// Return the parsed sections and parsing errors.
	return sections, errorArray
}

// Helper function for BuildIssue().
// FIXME use regexp for matching the different formats instead of just checking the prefix
func buildIssueTaxonomySection(issue G3Data, sectionName string) string {
	section := []string{}
	value, ok := issue[sectionName]
	if ok {
		section = make([]string, len(value.([]interface{})))
		for i := 0; i < len(value.([]interface{})); i++ {
			tag := value.([]interface{})[i].(string)
			url := ""
			if strings.HasPrefix(tag, "CVE-") {
				url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + tag
			} else if strings.HasPrefix(tag, "CWE-") {
				url = "https://cwe.mitre.org/data/definitions/" + tag[4:] + ".html"
			} else if strings.HasPrefix(tag, "CAPEC-") {
				url = "https://capec.mitre.org/data/definitions/" + tag[6:] + ".html"
			} else if strings.HasPrefix(tag, "CNVD-") {
				url = "https://www.cnvd.org.cn/flaw/show/" + tag
			} else if strings.HasPrefix(tag, "JVNDB-") {
				url = "https://jvndb.jvn.jp/ja/contents/" + tag[6:10] + "/" + tag + ".html"
			} else if strings.HasPrefix(tag, "JVN") {
				url = "https://jvn.jp/jp/" + tag + "/index.html"
			} else if strings.HasPrefix(tag, "BDU:") {
				url = "https://bdu.fstec.ru/vul/" + tag[4:]
			} else if strings.HasPrefix(tag, "USN-") {
				url = "https://ubuntu.com/security/notices/" + tag[4:]
			} else if strings.HasPrefix(tag, "RHSA-") {
				url = "https://access.redhat.com/errata/" + tag
			} else if strings.HasPrefix(tag, "DSA-") {
				url = "https://www.debian.org/security/" + strings.ToLower(tag)
			} else if strings.HasPrefix(tag, "KB") {
				url = "https://support.microsoft.com/kb/" + tag[2:]
			} else if strings.HasPrefix(tag, "MS") {
				url = "https://docs.microsoft.com/en-us/security-updates/securitybulletins/20" + tag[2:4] + "/" + strings.ToLower(tag)
			} else if strings.HasPrefix(tag, "MFSA") {
				url = "https://www.mozilla.org/en-US/security/advisories/" + strings.ToLower(tag) + "/"
			} else if strings.HasPrefix(tag, "EDB-ID:") {
				url = "https://www.exploit-db.com/exploits/" + tag[7:]
			} else if strings.HasPrefix(tag, "1337DAY-ID-") {
				url = "https://0day.today/exploit/" + tag[11:]
			} else if strings.HasPrefix(tag, "SECURITYVULNS:DOC:") {
				url = "https://vulners.com/securityvulns/" + tag
			} else if strings.HasPrefix(tag, "OBB-") {
				url = "https://www.openbugbounty.org/reports/" + tag[4:] + "/"
			} else if strings.HasPrefix(tag, "RFC ") {
				url = "https://datatracker.ietf.org/doc/html/" + strings.ToLower(tag[:3]) + tag[4:]
			}
			if url != "" {
				section[i] = fmt.Sprintf("* [%s](%s)", tag, url)
			} else {
				section[i] = fmt.Sprintf("* %s", tag)
			}
		}
	}
	return strings.Join(section, "\n")
}

// Helper function for BuildIssue().
func buildIssueParagraphSection(pluginTemplate string, issue G3Data, sectionName string) (string, error) {

	// Issues are expected to build paragraphs of text by referencing templates in the plugin's .json file.
	// No actual text is allowed in the issue itself, to ensure every piece of text gets translated in the report.
	// Since each template in the .json file is concatenated and prepended, we can cross reference them too.

	// Get each paragraph in the section. Each paragraph is represented by the name of a template.
	// We turn each paragraph into a template execution and concatenate them all.
	value, ok := issue[sectionName]
	if ok {
		for i := 0; i < len(value.([]interface{})); i++ {
			pluginTemplate = fmt.Sprintf("%s{{template \"%s\" .}}\n", pluginTemplate, value.([]interface{})[i].(string))
		}
	} else {
		pluginTemplate = fmt.Sprintf("%s{{template \"%s\" .}}\n", pluginTemplate, sectionName)
	}

	// Expand the section template.
	return expandIssueTemplate(pluginTemplate, issue)
}

// Helper function for BuildIssue().
func buildIssueSimpleSection(pluginTemplate string, issue G3Data, sectionName string) (string, error) {

	// This function is used for sections that do not contain paragraphs of text but just simple lists.
	// Examples are the Affects and References sections.

	// Add the execution of the corresponding template.
	pluginTemplate = fmt.Sprintf("%s{{template \"%s\" .}}\n", pluginTemplate, sectionName)

	// Expand the section template.
	return expandIssueTemplate(pluginTemplate, issue)
}

// Helper function for BuildIssue().
func expandIssueTemplate(pluginTemplate string, issue G3Data) (string, error) {

	// Expand the section template.
	sectionText, err := ExpandTemplate(pluginTemplate, issue)
	if err != nil {
		return sectionText, err
	}

	// Remove extra newlines. This makes things more consistent when concatenating sections later.
	for strings.HasPrefix(sectionText, "\n") {
		sectionText = sectionText[1:]
	}
	for strings.HasSuffix(sectionText, "\n") {
		sectionText = sectionText[:len(sectionText) - 1]
	}

	// Return the parsed text.
	return sectionText, err
}
