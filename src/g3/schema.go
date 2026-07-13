package g3

// It reflects a Go struct, reads the go-playground `validate:"..."` struct tags,
// and emits a JSON Schema (draft 2020-12) as a plain map[string]any. That single
// output is "dual-use": it can be json.Marshal'd to a portable .json file for
// cross-language consumers (e.g. the Python plugins) AND handed to a JSON Schema
// validator (or Huma) at runtime. No govalidator dependency in the output.
//
// Design note: this is a lookup table + a couple of valued keywords, NOT a
// parser for govalidator's expression grammar. We deliberately never handle the
// `|` alternation operator. Compound rules are expected to hide behind named
// validators (g3name, paragraph, g3type), which are single table entries here.

import (
	"reflect"
	"strconv"
	"strings"
)

func GetPortableSchema(a any) map[string]any {
	return schemaForStruct(reflect.TypeOf(a))
}

// customTags maps a registered govalidator validator name to the schema fragment
// it should contribute. This is the "name table" — the adapter never introspects
// the Go validation function, it just knows the equivalent schema. Adding a new
// custom validator server-side means adding one line here.
var customTags = map[string]func(m map[string]any){
	// g3name: ^[a-z][a-z0-9_-]*$  (the FIXED regex — no stray backslash)
	"g3name":    func(m map[string]any) { m["pattern"] = `^[a-z][a-z0-9_-]*$` },
	"paragraph": func(m map[string]any) { m["pattern"] = `^[^\r\n]+$` },
	// g3type is a govalidator alias for "alpha,lowercase,min=3" — which collapses
	// to a single lowercase-letters pattern plus a length floor.
	"g3type": func(m map[string]any) { m["pattern"] = `^[a-z]+$`; m["minLength"] = 3 },
}

func schemaForStruct(t reflect.Type) map[string]any {
	props := map[string]any{}
	required := []string{}
	collect(t, props, &required)
	s := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false, // strict: a wire contract should reject typo'd keys
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// collect walks a struct's fields, flattening embedded structs the way Go/JSON
// promotion does (so ProgressUpdate absorbs StatusUpdate's seq/status).
func collect(t reflect.Type, props map[string]any, required *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			collect(f.Type, props, required)
			continue
		}
		name := jsonName(f)
		if name == "" {
			continue
		}
		fieldSchema, req := schemaForField(f)
		props[name] = fieldSchema
		if req {
			*required = append(*required, name)
		}
	}
}

func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}

func baseType(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": baseType(t.Elem())}
	case reflect.Struct:
		return schemaForStruct(t)
	case reflect.Map:
		// Open on purpose: g3.Data is opaque to OpenAPI and validated only
		// server-side. Emit additionalProperties:true so the artifact says so.
		return map[string]any{"type": "object", "additionalProperties": true}
	default:
		return map[string]any{}
	}
}

func schemaForField(f reflect.StructField) (schema map[string]any, required bool) {
	s := baseType(f.Type)
	tag := f.Tag.Get("validate")
	if tag == "" {
		return s, false
	}
	atoms := strings.Split(tag, ",")

	// Split at `dive`: atoms before it constrain the field/array, atoms after it
	// constrain each element.
	fieldAtoms, itemAtoms := atoms, []string(nil)
	for i, a := range atoms {
		if a == "dive" {
			fieldAtoms = atoms[:i]
			itemAtoms = atoms[i+1:]
			break
		}
	}

	for _, a := range fieldAtoms {
		applyAtom(a, s, &required, f.Type)
	}
	if len(itemAtoms) > 0 {
		items, _ := s["items"].(map[string]any)
		if items == nil {
			items = map[string]any{}
			s["items"] = items
		}
		elem := f.Type.Elem()
		for _, a := range itemAtoms {
			if a == "required" && elem.Kind() == reflect.String {
				items["minLength"] = 1 // "required" on a string element == non-empty
				continue
			}
			var ignore bool
			applyAtom(a, items, &ignore, elem)
		}
	}
	return s, required
}

func applyAtom(a string, s map[string]any, required *bool, t reflect.Type) {
	key, val, _ := strings.Cut(a, "=")
	switch key {
	case "required":
		*required = true
	case "omitempty", "omitzero":
		// optional — no schema constraint
	case "uuid", "uuid4":
		s["format"] = "uuid" // note: uuid4's v4-specificity is lost; pattern if it matters
	case "url":
		s["format"] = "uri"
	case "ipv4":
		s["format"] = "ipv4"
	case "ipv6":
		s["format"] = "ipv6"
	case "hostname_rfc1123":
		s["format"] = "hostname"
	case "mongodb":
		s["pattern"] = `^[0-9a-fA-F]{24}$`
	case "hexcolor":
		s["pattern"] = `^#[0-9A-Fa-f]{6}$`
	case "gte":
		s["minimum"] = num(val)
	case "lte":
		s["maximum"] = num(val)
	case "gt":
		s["exclusiveMinimum"] = num(val)
	case "lt":
		s["exclusiveMaximum"] = num(val)
	case "min":
		applyBound(s, "min", num(val), t)
	case "max":
		applyBound(s, "max", num(val), t)
	case "oneof":
		s["enum"] = strings.Fields(val)
	case "eq":
		s["const"] = val
	case "ne":
		s["not"] = map[string]any{"const": val}
	default:
		if fn, ok := customTags[key]; ok {
			fn(s)
		} else if a != "" {
			panic("unknown tag: " + a)
		}
	}
}

// applyBound maps min/max to the kind-appropriate JSON Schema keyword.
func applyBound(s map[string]any, which string, n int, t reflect.Type) {
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		if which == "min" {
			s["minItems"] = n
		} else {
			s["maxItems"] = n
		}
	case reflect.String:
		if which == "min" {
			s["minLength"] = n
		} else {
			s["maxLength"] = n
		}
	default:
		if which == "min" {
			s["minimum"] = n
		} else {
			s["maximum"] = n
		}
	}
}

func num(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
