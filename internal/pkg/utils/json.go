package utils

import (
	"encoding/json"
	"io"
)

func JsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func JsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func JsonDecode(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}
