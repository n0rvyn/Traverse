package caddy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTraverseJSONTypeIdentity(t *testing.T) {
	if !isJSONRawMessage(reflect.TypeFor[json.RawMessage]()) {
		t.Fatal("existing RawMessage identity correction is missing")
	}
	if !isModuleMapType(reflect.TypeFor[ModuleMap]()) || !isModuleMapType(reflect.TypeFor[map[string]json.RawMessage]()) {
		t.Fatal("module map identity was lost")
	}
	if isJSONRawMessage(reflect.TypeFor[[]byte]()) || isModuleMapType(reflect.TypeFor[map[string][]byte]()) {
		t.Fatal("non-module byte data was admitted")
	}
}
