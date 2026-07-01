// Backend-compatibility harness: unmarshals SDK-emitted hook spans with the
// REAL Core SpanData struct shape and reports what parsed.
//
// The struct below is copied verbatim from
// openbox-core/internal/content/governance.go (SpanData + SpanStatus +
// SpanEvent) — internal packages cannot be imported from an external module,
// so the fixture pins the contract by copy, cited to its source.
//
// Usage: go run main.go < spans.json
// Input: JSON array of span dicts. Output: JSON array of parse reports.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// SpanData represents a single OTel span (governance.go:266).
type SpanData struct {
	SpanID          string                 `json:"span_id"`
	TraceID         string                 `json:"trace_id"`
	ParentSpanID    *string                `json:"parent_span_id,omitempty"`
	Name            string                 `json:"name"`
	Kind            *string                `json:"kind,omitempty"`
	StartTime       int64                  `json:"start_time"`
	EndTime         int64                  `json:"end_time"`
	DurationNs      *int64                 `json:"duration_ns,omitempty"`
	Attributes      map[string]interface{} `json:"attributes,omitempty"`
	Status          *SpanStatus            `json:"status,omitempty"`
	Events          []SpanEvent            `json:"events,omitempty"`
	RequestHeaders  map[string]string      `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string      `json:"response_headers,omitempty"`
	RequestBody     *string                `json:"request_body,omitempty"`
	ResponseBody    *string                `json:"response_body,omitempty"`
	SemanticType    string                 `json:"semantic_type,omitempty"`
	Stage           string                 `json:"stage,omitempty"`
	Data            interface{}            `json:"data,omitempty"`

	HookType                string   `json:"hook_type,omitempty"`
	AttributeKeyIdentifiers []string `json:"attribute_key_identifiers,omitempty"`
	SpanError               *string  `json:"error,omitempty"`

	HTTPMethod     *string `json:"http_method,omitempty"`
	HTTPURL        *string `json:"http_url,omitempty"`
	HTTPStatusCode *int    `json:"http_status_code,omitempty"`

	DBSystem    *string `json:"db_system,omitempty"`
	DBName      *string `json:"db_name,omitempty"`
	DBOperation *string `json:"db_operation,omitempty"`
	DBStatement *string `json:"db_statement,omitempty"`
	ServerAddr  *string `json:"server_address,omitempty"`
	ServerPort  *int    `json:"server_port,omitempty"`
	Rowcount    *int    `json:"rowcount,omitempty"`

	FilePath      *string `json:"file_path,omitempty"`
	FileMode      *string `json:"file_mode,omitempty"`
	FileOperation *string `json:"file_operation,omitempty"`
	BytesRead     *int64  `json:"bytes_read,omitempty"`
	BytesWritten  *int64  `json:"bytes_written,omitempty"`
	LinesCount    *int    `json:"lines_count,omitempty"`

	FuncName   *string     `json:"function,omitempty"`
	Module     *string     `json:"module,omitempty"`
	Args       interface{} `json:"args,omitempty"`
	FuncResult interface{} `json:"result,omitempty"`
}

type SpanStatus struct {
	Code        string  `json:"code"`
	Description *string `json:"description,omitempty"`
}

type SpanEvent struct {
	Name       string                 `json:"name"`
	Timestamp  int64                  `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
}

type report struct {
	SpanID         string  `json:"span_id"`
	TraceID        string  `json:"trace_id"`
	Stage          string  `json:"stage"`
	HookType       string  `json:"hook_type"`
	Name           string  `json:"name"`
	StartTime      int64   `json:"start_time"`
	EndTime        int64   `json:"end_time"`
	HasDurationNs  bool    `json:"has_duration_ns"`
	HTTPURL        *string `json:"http_url"`
	HTTPMethod     *string `json:"http_method"`
	DBStatement    *string `json:"db_statement"`
	FilePath       *string `json:"file_path"`
	FuncName       *string `json:"function"`
	HasData        bool    `json:"has_data"`
	ParentSpanID   *string `json:"parent_span_id"`
	HTTPStatusCode *int    `json:"http_status_code"`
}

func main() {
	var spans []SpanData
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields() // strict: SDK must not send unknown top-level fields
	if err := decoder.Decode(&spans); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal failed: %v\n", err)
		os.Exit(1)
	}
	reports := make([]report, 0, len(spans))
	for _, s := range spans {
		reports = append(reports, report{
			SpanID: s.SpanID, TraceID: s.TraceID, Stage: s.Stage,
			HookType: s.HookType, Name: s.Name,
			StartTime: s.StartTime, EndTime: s.EndTime,
			HasDurationNs: s.DurationNs != nil,
			HTTPURL:       s.HTTPURL, HTTPMethod: s.HTTPMethod,
			DBStatement: s.DBStatement, FilePath: s.FilePath, FuncName: s.FuncName,
			HasData: s.Data != nil, ParentSpanID: s.ParentSpanID,
			HTTPStatusCode: s.HTTPStatusCode,
		})
	}
	out, _ := json.Marshal(reports)
	fmt.Println(string(out))
}
