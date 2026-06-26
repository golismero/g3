package g3model

import "fmt"

type G3PluginDescription struct {
	Name        string `json:"name"`                        // Tool name. Must be unique.
	Category    string `json:"category"`                    // Defaults to parent directory name.
	Description string `json:"description"`                 // Description for humans.
	URL         string `json:"url"          validate:"url"` // URL for humans.
	Image       string `json:"image"`                       // Docker image.
}

func (plugin G3PluginDescription) String() string {
	output := ""
	output = output + fmt.Sprintln("Name:        " + plugin.Name)
	output = output + fmt.Sprintln("Category:    " + plugin.Category)
	output = output + fmt.Sprintln("Homepage:    " + plugin.URL)
	output = output + fmt.Sprintln("Description: " + plugin.Description)
	return output
}
