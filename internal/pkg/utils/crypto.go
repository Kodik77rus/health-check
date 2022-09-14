package utils

import "encoding/base64"

func Base64Decode(data []byte) ([]byte, error) {
	message := base64.StdEncoding.EncodeToString(data)
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	n, err := base64.StdEncoding.Decode(base64Text, []byte(message))
	if err != nil {
		return nil, err
	}
	return base64Text[:n], nil
}
