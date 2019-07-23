package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"../parse"
	"github.com/matryer/m"
	"github.com/xeipuuv/gojsonschema"
)

const indent = " "

// T represents types to which failures may be reported.
// The testing.T type is one such example.
type T interface {
	FailNow()
	Log(...interface{})
}

// Runner runs parsed tests.
type Runner struct {
	t       T
	rootURL string
	user    string
	pass    string
	vars    map[string]*parse.Value
	// DoRequest makes the request and returns the response.
	// By default uses http.DefaultClient.Do.
	DoRequest func(r *http.Request) (*http.Response, error)
	// ParseBody is the function to use to attempt to parse
	// response bodies to make data available for assertions.
	ParseBody func(r io.Reader) (interface{}, error)
	// Log is the function to log to.
	Log func(string)
	// Verbose is the function that logs verbose debug information.
	Verbose func(...interface{})
}

// New makes a new Runner with the given testing T target and the
// root URL.
func New(t T, URL string, user string, pass string) *Runner {
	r := &Runner{
		t:         t,
		rootURL:   URL,
		user:      user,
		pass:      pass,
		vars:      make(map[string]*parse.Value),
		DoRequest: http.DefaultTransport.RoundTrip,
		Log: func(s string) {
			fmt.Println(s)
		},
		Verbose: func(args ...interface{}) {
			if !testing.Verbose() {
				return
			}
			fmt.Println(args...)
		},
		ParseBody: ParseJSONBody,
	}
	// capture environment variables by default
	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		r.vars[pair[0]] = parse.ParseValue([]byte(pair[1]))
	}
	return r
}

func (r *Runner) NewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err == nil {
		// Add basic authentication credentials.
		if r.user != "" && r.pass != "" {
			req.SetBasicAuth(r.user, r.pass)
		}
	}
	return req, err
}

func (r *Runner) log(args ...interface{}) {
	var strs []string
	for _, arg := range args {
		strs = append(strs, fmt.Sprint(arg))
	}
	strs = append(strs, " ")
	r.Log(strings.Join(strs, " "))
}

// RunGlob is a helper that runs the files returned by filepath.Glob.
//     runner.RunGlob(filepath.Glob("pattern"))
func (r *Runner) RunGlob(files []string, err error) {
	if err != nil {
		r.t.Log("silk:", err)
		r.t.FailNow()
		return
	}
	r.RunFile(files...)
}

// RunFile parses and runs the specified file(s).
func (r *Runner) RunFile(filenames ...string) {
	groups, err := parse.ParseFile(filenames...)
	if err != nil {
		r.log(err)
		return
	}
	r.RunGroup(groups...)
}

// RunGroup runs a parse.Group.
// Consider RunFile instead.
func (r *Runner) RunGroup(groups ...*parse.Group) {
	for _, group := range groups {
		r.runGroup(group)
	}
}

func (r *Runner) runGroup(group *parse.Group) {
	for _, req := range group.Requests {
		r.runRequest(group, req)
	}
}

func (r *Runner) runRequest(group *parse.Group, req *parse.Request) {
	m := string(req.Method)
	p := string(req.Path)
	absPath := r.resolveVars(r.rootURL + p)
	m = r.resolveVars(m)
	r.Verbose(string(req.Method), absPath)
	var body io.Reader
	var bodyStr string
	if len(req.Body) > 0 {
		bodyStr = r.resolveVars(req.Body.String())
		body = strings.NewReader(bodyStr)
	}
	// make request
	httpReq, err := r.NewRequest(m, absPath, body)
	if err != nil {
		r.log("invalid request: ", err)
		r.t.FailNow()
		return
	}
	// set body
	bodyLen := len(bodyStr)
	if bodyLen > 0 {
		httpReq.ContentLength = int64(bodyLen)
	}
	// set request headers
	for _, line := range req.Details {
		detail := line.Detail()
		val := fmt.Sprintf("%v", detail.Value.Data)
		val = r.resolveVars(val)
		detail.Value = parse.ParseValue([]byte(val))
		r.Verbose(indent, detail.String())
		httpReq.Header.Add(detail.Key, val)
	}
	// set parameters
	q := httpReq.URL.Query()
	for _, line := range req.Params {
		detail := line.Detail()
		val := fmt.Sprintf("%v", detail.Value.Data)
		val = r.resolveVars(val)
		detail.Value = parse.ParseValue([]byte(val))
		r.Verbose(indent, detail.String())
		q.Add(detail.Key, val)
	}
	httpReq.URL.RawQuery = q.Encode()

	// print request body
	if bodyLen > 0 {
		r.Verbose("```")
		r.Verbose(bodyStr)
		r.Verbose("```")
	}
	// perform request
	httpRes, err := r.DoRequest(httpReq)
	if err != nil {
		r.log(err)
		r.t.FailNow()
		return
	}

	// collect response details
	responseDetails := make(map[string]interface{})
	for k, vs := range httpRes.Header {
		for _, v := range vs {
			responseDetails[k] = v
		}
	}
	// add cookies to repsonse details
	var cookieStrs []string
	for _, cookie := range httpRes.Cookies() {
		cookieStrs = append(cookieStrs, cookie.String())
	}
	responseDetails["Set-Cookie"] = strings.Join(cookieStrs, "|")

	// set other details
	responseDetails["Status"] = float64(httpRes.StatusCode)

	actualBody, err := ioutil.ReadAll(httpRes.Body)
	if err != nil {
		r.log("failed to read body: ", err)
		r.t.FailNow()
		return
	}
	if len(actualBody) > 0 {
		r.Verbose("```")
		r.Verbose(string(actualBody))
		r.Verbose("```")
	}

	// set the body as a field (see issue #15)
	responseDetails["Body"] = string(actualBody)

	/*
		Assertions
		---------------------------------------------------------
	*/

	// assert the body
	if len(req.ExpectedBody) > 0 {
		// check body against expected body
		exp := r.resolveVars(req.ExpectedBody.String())

		// depending on the expectedBodyType:
		// json*: check if expectedBody as JSON is a subset of the actualBody as json
		// json(strict): check JSON for deep equality (avoids checking diffs in white space and order)
		// *: check string for verbatim equality

		expectedTypeIsJSON := strings.HasPrefix(req.ExpectedBodyType, "json")
		if expectedTypeIsJSON {
			// decode json from string
			var expectedJSON interface{}
			var actualJSON interface{}
			json.Unmarshal([]byte(exp), &expectedJSON)
			json.Unmarshal(actualBody, &actualJSON)

			// Check that the expected body and the response body match exactly.
			if strings.Contains(req.ExpectedBodyType, "strict") {
				if !reflect.DeepEqual(actualJSON, expectedJSON) {
					r.fail(group, req, req.ExpectedBody.Number(), "- body (strict) doesn't match:")
					return
				}
				// Check that the expected body and the response body have the same
				// structure or that the expected body structure is a subset of the
				// response body's.
			} else if strings.Contains(req.ExpectedBodyType, "schema") {
				schemaLoader := gojsonschema.NewStringLoader(string(exp))
				documentLoader := gojsonschema.NewStringLoader(string(actualBody))

				result, err := gojsonschema.Validate(schemaLoader, documentLoader)
				if err != nil {
					r.fail(group, req, req.ExpectedBody.Number(), "- schema validation failed:", err)
					return
				}
				if !result.Valid() {
					var b bytes.Buffer
					for _, desc := range result.Errors() {
						b.WriteString(fmt.Sprintf("- %s\n", desc))
					}
					r.fail(group, req, req.ExpectedBody.Number(), "- response body doesn't match schema:", b.String())
					return
				}
				// Check that the expected body is a subset of the response body with
				// equal values.
			} else {
				eq, err := r.assertJSONIsEqualOrSubset(expectedJSON, actualJSON)
				if !eq {
					r.fail(group, req, req.ExpectedBody.Number(), "- body doesn't match:", err)
					return
				}
			}
		} else if !r.assertBody(actualBody, []byte(exp)) {
			r.fail(group, req, req.ExpectedBody.Number(), "- body doesn't match")
			return
		}
	}

	// assert the details
	var parseDataOnce sync.Once
	var data interface{}
	var errData error
	if len(req.ExpectedDetails) > 0 {
		for _, line := range req.ExpectedDetails {
			detail := line.Detail()
			// resolve any variables mentioned in this detail value
			if detail.Value.Type() == "string" {
				detail.Value.Data = r.resolveVars(detail.Value.Data.(string))
			}
			if strings.HasPrefix(detail.Key, "Data") {
				parseDataOnce.Do(func() {
					data, errData = r.ParseBody(bytes.NewReader(actualBody))
				})
				if !r.assertData(line, data, errData, detail.Key, detail.Value) {
					r.fail(group, req, line.Number, "- "+detail.Key+" doesn't match")
					return
				}
				continue
			}
			var actual interface{}
			var present bool
			if actual, present = responseDetails[detail.Key]; !present {
				r.log(detail.Key, fmt.Sprintf("expected %s: %s  actual %T: %s", detail.Value.Type(), detail.Value, actual, "(missing)"))
				r.fail(group, req, line.Number, "- "+detail.Key+" doesn't match")
				return
			}
			if !r.assertDetail(line, detail.Key, actual, detail.Value) {
				r.fail(group, req, line.Number, "- "+detail.Key+" doesn't match")
				return
			}
		}
	}

}

func (r *Runner) resolveVars(s string) string {
	for k, v := range r.vars {
		match := "{" + k + "}"
		s = strings.Replace(s, match, fmt.Sprintf("%v", v.Data), -1)
	}
	return s
}

func (r *Runner) fail(group *parse.Group, req *parse.Request, line int, args ...interface{}) {
	logargs := []interface{}{"--- FAIL:", string(req.Method), string(req.Path), "\n", group.Filename + ":" + strconv.FormatInt(int64(line), 10)}
	r.log(append(logargs, args...)...)
	r.t.FailNow()
}

func (r *Runner) assertBody(actual, expected []byte) bool {
	if !reflect.DeepEqual(actual, expected) {
		r.log("body expected:")
		r.log("```")
		r.log(string(expected))
		r.log("```")
		r.Log("")
		r.log("actual:")
		r.log("```")
		r.log(string(actual))
		r.log("```")
		return false
	}
	return true
}

func (r *Runner) assertDetail(line *parse.Line, key string, actual interface{}, expected *parse.Value) bool {
	if !expected.Equal(actual) {
		actualVal := parse.ParseValue([]byte(fmt.Sprintf("%v", actual)))
		actualString := actualVal.String()
		if v, ok := actual.(string); ok {
			actualString = fmt.Sprintf(`"%s"`, v)
		}

		if expected.Type() == actualVal.Type() {
			r.log(key, fmt.Sprintf("expected: %s  actual: %s", expected, actualString))
		} else {
			r.log(key, fmt.Sprintf("expected %s: %s  actual %T: %s", expected.Type(), expected, actual, actualString))
		}

		return false
	}
	// capture any vars (// e.g. {placeholder})
	if capture := line.Capture(); len(capture) > 0 {
		r.capture(capture, actual)
	}
	return true
}

func (r *Runner) assertData(line *parse.Line, data interface{}, errData error, key string, expected *parse.Value) bool {
	if errData != nil {
		r.log(key, fmt.Sprintf("expected %s: %s  actual: failed to parse body: %s", expected.Type(), expected, errData))
		return false
	}
	if data == nil {
		r.log(key, fmt.Sprintf("expected %s: %s  actual: no data", expected.Type(), expected))
		return false
	}
	actual, ok := m.GetOK(map[string]interface{}{"Data": data}, key)
	if !ok && expected.Data != nil {
		r.log(key, fmt.Sprintf("expected %s: %s  actual: (missing)", expected.Type(), expected))
		return false
	}
	// capture any vars (// e.g. {placeholder})
	if capture := line.Capture(); len(capture) > 0 {
		r.capture(capture, actual)
	}
	if !ok && expected.Data == nil {
		return true
	}
	if !expected.Equal(actual) {
		actualVal := parse.ParseValue([]byte(fmt.Sprintf("%v", actual)))
		actualString := actualVal.String()
		if v, ok := actual.(string); ok {
			actualString = fmt.Sprintf(`"%s"`, v)
		}
		if expected.Type() == actualVal.Type() {
			r.log(key, fmt.Sprintf("expected: %s  actual: %s", expected, actualString))
		} else {
			r.log(key, fmt.Sprintf("expected %s: %s  actual %T: %s", expected.Type(), expected, actual, actualString))
		}
		return false
	}
	return true
}

// assertJSONIsEqualOrSubset returns true if v1 and v2 are equal in value
// or if both are maps (of type map[string]interface{}) and v1 is a subset of v2, where
// all keys that are present in v1 are present with the same value in v2.
func (r *Runner) assertJSONIsEqualOrSubset(v1 interface{}, v2 interface{}) (bool, error) {
	if (v1 == nil) && (v2 == nil) {
		return true, nil
	}

	value1 := reflect.ValueOf(v1)
	value2 := reflect.ValueOf(v2)

	// Check if both are non nil and that type matches.
	if v1 == nil || v2 == nil || value1.Kind() != value2.Kind() {
		return false, fmt.Errorf("types do not match")
	}

	switch value1.Kind() {
	case reflect.Map:
		iter := value1.MapRange()
		for iter.Next() {
			key := iter.Key()
			val1 := iter.Value()
			val2 := value2.MapIndex(key)
			if !val2.IsValid() {
				return false, fmt.Errorf("missing key '%s' in response body", key)
			}
			equal, err := r.assertJSONIsEqualOrSubset(val1.Interface(), val2.Interface())
			if !equal {
				return false, fmt.Errorf("mismatch for key '%s': %s", key, err)
			}
		}
		return true, nil
	case reflect.Slice:
		for i := 0; i < value1.Len(); i++ {
			val1 := value1.Index(i)
			val2 := value2.Index(i)
			if !val2.IsValid() {
				return false, fmt.Errorf("missing item with index '%d'", i)
			}
			equal, err := r.assertJSONIsEqualOrSubset(val1.Interface(), val2.Interface())
			if !equal {
				return false, fmt.Errorf("mismatch for item with index '%d': %s", i, err)
			}
		}
		return true, nil
	default:
		// All non-map/slice types must be deep equal.
		if !reflect.DeepEqual(v1, v2) {
			return false, fmt.Errorf("values do not match - %s != %s", v1, v2)
		}
		// Return true as we already checked that the values are of the same type.
		return true, nil
	}
}

func (r *Runner) capture(key string, val interface{}) {
	r.vars[key] = &parse.Value{Data: val}
	r.Verbose("captured", key, "=", val)
}
