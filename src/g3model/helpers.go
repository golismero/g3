package g3model

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-playground/validator/v10"
)

// Global validator cache.
var Validate *validator.Validate = validator.New(validator.WithRequiredStructEnabled())

// Validate struct and marshal to JSON.
func EncodeJSON(pointer any) ([]byte, error) {
	err := Validate.Struct(pointer)
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(pointer)
}

// Unmarshal from JSON and validate struct.
func DecodeJSON(data []byte, pointer any) error {
	err := json.Unmarshal(data, pointer)
	if err != nil {
		return err
	}
	return Validate.Struct(pointer)
}

// shellCompletionSnippets are the registration lines a user adds to their
// shell rc (or that the Makefile drops into a system completion directory)
// to enable Tab-completion. The actual completion engine is provided by
// kongplete inside each binary — these snippets only tell the shell to
// consult the binary on Tab.
var shellCompletionSnippets = map[string]string{
	"bash": "complete -C %s %s\n",
	"zsh": `autoload -U +X bashcompinit && bashcompinit
complete -C %s %s
`,
	"fish": `function __complete_%s
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    %s
end
complete -f -c %s -a "(__complete_%s)"
`,
}

// EmitShellCompletion writes a shell-registration snippet for cmdName to w.
// shell must be "bash", "zsh", or "fish"; any other value returns an error.
// The binary path embedded in the snippet is resolved via os.Executable()
// and made absolute so the snippet keeps working regardless of $PATH.
func EmitShellCompletion(shell, cmdName string, w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}

	tmpl, ok := shellCompletionSnippets[shell]
	if !ok {
		return fmt.Errorf("unsupported shell %q", shell)
	}

	switch shell {
	case "bash", "zsh":
		fmt.Fprintf(w, tmpl, bin, cmdName)
	case "fish":
		// fish template uses cmdName four times and bin once.
		fmt.Fprintf(w, tmpl, cmdName, bin, cmdName, cmdName)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// A string set type for Golang.

type StringSetInterface interface {
	Add(s string)
	AddMulti(a []string)
	Exists(s string) bool
	AnyExist(a []string) bool
	AllExist(a []string) bool
	Delete(s string)
	DeleteMulti(a []string)
	Length() int
	ToArray() []string
}

type void struct{}
var member void

// Non-concurrent version (faster).
type StringSet map[string]void

func (ss StringSet) Add(s string) {
	ss[s] = member
}
func (ss StringSet) AddMulti(a []string) {
	for i := 0; i < len(a); i++ {
		ss[a[i]] = member
	}
}
func (ss StringSet) Exists(s string) bool {
	_, ok := ss[s]
	return bool(ok)
}
func (ss StringSet) AnyExist(a []string) bool {
	for i := 0; i < len(a); i++ {
		if _, ok := ss[a[i]]; ok {
			return true
		}
	}
	return false
}
func (ss StringSet) AllExist(a []string) bool {
	for i := 0; i < len(a); i++ {
		if _, ok := ss[a[i]]; !ok {
			return false
		}
	}
	return true
}
func (ss StringSet) Delete(s string) {
	delete(ss, s)
}
func (ss StringSet) DeleteMulti(a []string) {
	for i := 0; i < len(a); i++ {
		delete(ss, a[i])
	}
}
func (ss StringSet) Length() int {
	return len(ss)
}
func (ss StringSet) Clear() {
	ss.DeleteMulti(ss.ToArray())
}
func (ss StringSet) ToArray() []string {
	keys := make([]string, len(ss))
	i := 0
	for k := range ss {
		keys[i] = k
		i++
	}
	return keys
}
func (ss StringSet) String() string {
	return fmt.Sprintf("%v", ss.ToArray())
}

// Concurrent version (safe for use in goroutines).
type SyncStringSet struct {
	sync.RWMutex
	internal StringSet
}
func NewSyncStringSet() *SyncStringSet {
	return &SyncStringSet{
		internal: make(StringSet),
	}
}
func (sss *SyncStringSet) Add(s string) {
	sss.Lock()
	sss.internal.Add(s)
	sss.Unlock()
}
func (sss *SyncStringSet) AddMulti(a []string) {
	sss.Lock()
	sss.internal.AddMulti(a)
	sss.Unlock()
}
func (sss *SyncStringSet) Exists(s string) bool {
	sss.Lock()
	value := sss.internal.Exists(s)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) AnyExist(a []string) bool {
	sss.Lock()
	value := sss.internal.AnyExist(a)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) AllExist(a []string) bool {
	sss.Lock()
	value := sss.internal.AllExist(a)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) Delete(s string) {
	sss.Lock()
	sss.internal.Delete(s)
	sss.Unlock()
}
func (sss *SyncStringSet) DeleteMulti(a []string) {
	sss.Lock()
	sss.internal.DeleteMulti(a)
	sss.Unlock()
}
func (sss *SyncStringSet) Length() int {
	sss.Lock()
	value := sss.internal.Length()
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) Clear() {
	sss.Lock()
	sss.internal.Clear()
	sss.Unlock()
}
func (sss *SyncStringSet) ToArray() []string {
	sss.Lock()
	value := sss.internal.ToArray()
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) String() string {
	return fmt.Sprintf("%v", sss.ToArray())
}
