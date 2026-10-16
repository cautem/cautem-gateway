package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cautem/quarshell-gateway/internal/httpapi"
	"gopkg.in/yaml.v3"
)

type openAPISchema struct {
	Ref                  string                   `yaml:"$ref"`
	Type                 string                   `yaml:"type"`
	Required             []string                 `yaml:"required"`
	Properties           map[string]openAPISchema `yaml:"properties"`
	Items                *openAPISchema           `yaml:"items"`
	AdditionalProperties yaml.Node                `yaml:"additionalProperties"`
	AllOf                []openAPISchema          `yaml:"allOf"`
	Enum                 []any                    `yaml:"enum"`
	Const                *string                  `yaml:"const"`
	Format               string                   `yaml:"format"`
	Minimum              *float64                 `yaml:"minimum"`
	MinItems             *int                     `yaml:"minItems"`
}

type openAPIResponse struct {
	Ref     string `yaml:"$ref"`
	Content map[string]struct {
		Schema openAPISchema `yaml:"schema"`
	} `yaml:"content"`
}

func validateOpenAPIResponse(t *testing.T, response openAPIResponse, components map[string]openAPISchema, shared map[string]openAPIResponse, status int, headers http.Header, body []byte) {
	t.Helper()
	if response.Ref != "" {
		const prefix = "#/components/responses/"
		if !strings.HasPrefix(response.Ref, prefix) {
			t.Fatalf("unsupported response reference %q", response.Ref)
		}
		var ok bool
		response, ok = shared[strings.TrimPrefix(response.Ref, prefix)]
		if !ok {
			t.Fatalf("unknown response reference %q", response.Ref)
		}
	}
	if len(response.Content) == 0 {
		if status == http.StatusNoContent && len(body) != 0 {
			t.Errorf("204 response has a body: %q", body)
		}
		return
	}
	media := strings.TrimSpace(strings.Split(headers.Get("Content-Type"), ";")[0])
	content, ok := response.Content[media]
	if !ok {
		t.Errorf("Content-Type %q is not documented; want one of %v", media, responseMediaTypes(response.Content))
		return
	}
	var value any
	switch media {
	case "application/json":
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("decode JSON response %q: %v", body, err)
		}
	case "text/plain", "application/yaml", "text/event-stream":
		value = string(body)
	default:
		t.Fatalf("unsupported response media type %q", media)
	}
	if err := content.Schema.validate(value, components, "response"); err != nil {
		t.Errorf("%v", err)
	}
}

func responseMediaTypes(content map[string]struct {
	Schema openAPISchema `yaml:"schema"`
}) []string {
	media := make([]string, 0, len(content))
	for name := range content {
		media = append(media, name)
	}
	sort.Strings(media)
	return media
}

func (s openAPISchema) validate(value any, components map[string]openAPISchema, path string) error {
	const prefix = "#/components/schemas/"
	if s.Ref != "" {
		if !strings.HasPrefix(s.Ref, prefix) {
			return fmt.Errorf("%s: unsupported schema reference %q", path, s.Ref)
		}
		resolved, ok := components[strings.TrimPrefix(s.Ref, prefix)]
		if !ok {
			return fmt.Errorf("%s: unknown schema reference %q", path, s.Ref)
		}
		return resolved.validate(value, components, path)
	}
	for _, part := range s.AllOf {
		if err := part.validate(value, components, path); err != nil {
			return err
		}
	}
	switch s.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, value)
		}
		for _, key := range s.Required {
			if _, ok := object[key]; !ok {
				return fmt.Errorf("%s: missing required field %q", path, key)
			}
		}
		for key, child := range object {
			property, ok := s.Properties[key]
			if !ok && s.AdditionalProperties.Kind == yaml.MappingNode {
				if err := s.AdditionalProperties.Decode(&property); err != nil {
					return fmt.Errorf("%s: decode additionalProperties: %w", path, err)
				}
				ok = true
			} else if !ok && s.AdditionalProperties.Kind == yaml.ScalarNode && s.AdditionalProperties.Value == "false" {
				return fmt.Errorf("%s: unexpected field %q", path, key)
			}
			if ok {
				if err := property.validate(child, components, path+"."+key); err != nil {
					return err
				}
			}
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s: want array, got %T", path, value)
		}
		if s.MinItems != nil && len(items) < *s.MinItems {
			return fmt.Errorf("%s: want at least %d items, got %d", path, *s.MinItems, len(items))
		}
		if s.Items != nil {
			for i, item := range items {
				if err := s.Items.validate(item, components, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s: want string, got %T", path, value)
		}
	case "integer", "number":
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("%s: want %s, got %T", path, s.Type, value)
		}
		if s.Type == "integer" && strings.ContainsAny(string(value.(json.Number)), ".eE") {
			return fmt.Errorf("%s: want integer, got %v", path, value)
		}
		if s.Minimum != nil {
			number, err := value.(json.Number).Float64()
			if err != nil || number < *s.Minimum {
				return fmt.Errorf("%s: %v is below minimum %v", path, value, *s.Minimum)
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: want boolean, got %T", path, value)
		}
	case "":
	default:
		return fmt.Errorf("%s: unsupported schema type %q", path, s.Type)
	}
	if len(s.Enum) > 0 {
		matched := false
		for _, choice := range s.Enum {
			if fmt.Sprint(value) == fmt.Sprint(choice) {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %v is outside enum %v", path, value, s.Enum)
		}
	}
	if s.Const != nil && value != *s.Const {
		return fmt.Errorf("%s: want constant %q, got %v", path, *s.Const, value)
	}
	if str, ok := value.(string); ok {
		switch s.Format {
		case "date-time":
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				return fmt.Errorf("%s: invalid date-time %q: %w", path, str, err)
			}
		case "uri":
			parsed, err := url.ParseRequestURI(str)
			if err != nil || parsed.Scheme == "" {
				return fmt.Errorf("%s: invalid URI %q", path, str)
			}
		}
	}
	return nil
}

// This keeps a small set of important public HTTP contracts tied to both the
// checked-in OpenAPI description and the behavior of the real gateway handler.
func TestOpenAPIHTTPContract(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]yaml.Node `yaml:"paths"`
		Components struct {
			Schemas   map[string]openAPISchema   `yaml:"schemas"`
			Responses map[string]openAPIResponse `yaml:"responses"`
		} `yaml:"components"`
	}
	specPath := filepath.Join("..", "..", "api", "openapi.yaml")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	g := newTestGateway(t, httpapi.Options{})
	checks := []struct {
		method, path, openAPIPath, openAPIMethod string
		want                                     int
		body                                     any
	}{
		{method: http.MethodGet, path: "/healthz", openAPIPath: "/healthz", openAPIMethod: "get", want: http.StatusOK},
	}
	for _, check := range checks {
		t.Run(check.method+" "+check.openAPIPath, func(t *testing.T) {
			operationNode, ok := spec.Paths[check.openAPIPath][check.openAPIMethod]
			if !ok {
				t.Fatalf("OpenAPI is missing %s %s", check.openAPIMethod, check.openAPIPath)
			}
			var operation struct {
				Responses   map[string]openAPIResponse `yaml:"responses"`
				RequestBody struct {
					Required bool `yaml:"required"`
					Content  map[string]struct {
						Schema openAPISchema `yaml:"schema"`
					} `yaml:"content"`
				} `yaml:"requestBody"`
			}
			if err := operationNode.Decode(&operation); err != nil {
				t.Fatalf("decode OpenAPI operation %s %s: %v", check.openAPIMethod, check.openAPIPath, err)
			}
			response, ok := operation.Responses[strconv.Itoa(check.want)]
			if !ok {
				t.Fatalf("OpenAPI %s %s does not document status %d", check.openAPIMethod, check.openAPIPath, check.want)
			}
			if check.body != nil && operation.RequestBody.Required {
				encoded, err := json.Marshal(check.body)
				if err != nil {
					t.Fatal(err)
				}
				var request any
				decoder := json.NewDecoder(bytes.NewReader(encoded))
				decoder.UseNumber()
				if err := decoder.Decode(&request); err != nil {
					t.Fatalf("encode request fixture: %v", err)
				}
				for _, media := range operation.RequestBody.Content {
					if err := media.Schema.validate(request, spec.Components.Schemas, "request"); err != nil {
						t.Errorf("%s %s request: %v", check.method, check.openAPIPath, err)
					}
				}
			}
			code, headers, body := openAPIRequest(t, g, check.method, check.path, check.body)
			if code != check.want {
				t.Fatalf("%s %s = %d (%s), want %d", check.method, check.path, code, body, check.want)
			}
			validateOpenAPIResponse(t, response, spec.Components.Schemas, spec.Components.Responses, code, headers, body)
		})
	}
}

func openAPIRequest(t *testing.T, g *testGateway, method, path string, body any) (int, http.Header, []byte) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, g.srv.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header, out
}

// Exercise every documented method against the live router. These requests use
// missing resources or bodies where provisioning requires external services;
// successful JSON responses receive deeper checks in TestOpenAPIHTTPContract.
func TestOpenAPIOperationCoverage(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]yaml.Node `yaml:"paths"`
		Components struct {
			Schemas   map[string]openAPISchema   `yaml:"schemas"`
			Responses map[string]openAPIResponse `yaml:"responses"`
		} `yaml:"components"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	g := newTestGateway(t, httpapi.Options{})
	var paths []string
	for path := range spec.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, template := range paths {
		for method, node := range spec.Paths[template] {
			if method != "get" && method != "post" && method != "put" && method != "delete" && method != "patch" {
				continue
			}
			t.Run(strings.ToUpper(method)+" "+template, func(t *testing.T) {
				var operation struct {
					Responses map[string]openAPIResponse `yaml:"responses"`
				}
				if err := node.Decode(&operation); err != nil {
					t.Fatal(err)
				}
				path := template
				for _, parameter := range []string{"name", "provider", "proposalId", "id", "key", "subject"} {
					path = strings.ReplaceAll(path, "{"+parameter+"}", "contract-missing")
				}
				code, headers, body := openAPIRequest(t, g, strings.ToUpper(method), path, nil)
				response, ok := operation.Responses[strconv.Itoa(code)]
				if !ok {
					t.Errorf("%s %s returned undocumented status %d: %s", method, template, code, body)
					return
				}
				validateOpenAPIResponse(t, response, spec.Components.Schemas, spec.Components.Responses, code, headers, body)
			})
		}
	}
}
