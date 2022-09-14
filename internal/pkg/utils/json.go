package utils

import (
	"encoding/json"
)

func JsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func JsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func IsValidJson(data []byte) bool {
	return json.Valid(data)
}
