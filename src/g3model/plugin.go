package g3model

import "fmt"

type PluginDescription struct {
	Name        string `json:"name"         validate:"omitempty,g3name"`      // Tool name. Must be unique.
	Category    string `json:"category"     validate:"omitempty,g3name"`      // Defaults to parent directory name.
	Description string `json:"description"  validate:"omitempty,paragraph"`   // Description for humans.
	URL         string `json:"url"          validate:"omitempty,url"`         // URL for humans.
}

type PluginListItem struct {
	PluginDescription
	IsImporter  bool   `json:"importer,omitempty,omitzero"`
	IsReporter  bool   `json:"reporter,omitempty,omitzero"`
	IsRunnable  bool   `json:"runnable,omitempty,omitzero"`
}

func (plugin PluginDescription) String() string {
	output := ""
	output += fmt.Sprintln("Name:        " + plugin.Name)
	output += fmt.Sprintln("Category:    " + plugin.Category)
	output += fmt.Sprintln("Homepage:    " + plugin.URL)
	output += fmt.Sprintln("Description: " + plugin.Description)
	return output
}

func (plugin PluginListItem) String() string {
	output := plugin.PluginDescription.String()
	output += fmt.Sprintf("Is Importer? %t\n", plugin.IsImporter)
	output += fmt.Sprintf("Is Reporter? %t\n", plugin.IsReporter)
	output += fmt.Sprintf("Is Runnable? %t\n", plugin.IsRunnable)
	return output
}
