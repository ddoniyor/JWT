package jwt

import (
	"testing"
	"time"
)

type headerStruct = struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
var header = headerStruct{
	Alg: "HS512",
	Typ: "JWT",
}

type payloadStruct struct {
	Id  int   `json:"id"`
	Exp int64 `json:"exp"`
}

var	payload = payloadStruct{
	Id:  1,
	Exp: time.Now().Add(time.Hour * 10).Unix(),
}



func Test_Enc_Dec_ok(t *testing.T) {
	secret := "top_secret"

	_,err := Encode( payload, []byte(secret))
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTg0MDExOTAyLCJleHAiOjE1ODQwNDc5MDJ9.BcumALTIODycz_uESHilA5xGbUmEst3T6RAHUCAwcIc", &payload)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}

}
func TestCanNot_Decode(t *testing.T) {

	err := Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.8985465.BcumALTIODycz_uESHilA5xGbUmEst3T6RAHUCAwcIc", &payload)
	if err == nil {
		t.Errorf("Decode() error %v", err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTg0MDExOTAyLCJleHAiOjE1ODQwNDc5MDJ9.BcumALTIODycz_uESHilA5xGbUmEst3T6RAHUCAwcIc", &payload)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}
}
func TestDecode_Ok(t *testing.T){
	err := Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTg0MDExOTAyLCJleHAiOjE1ODQwNDc5MDJ9.BcumALTIODycz_uESHilA5xGbUmEst3T6RAHUCAwcIc", &payload)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}
}

func TestEncode_ok(t *testing.T) {
	secret := "top_secret"
	encode, err := Encode(payload, []byte(secret))
	if err != nil {
		t.Errorf("Encode() error %v", err)
	}
	if encode != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0Fla3oY" {
		t.Errorf("Encode() error: %s", encode)
	}
}

func TestVerify(t *testing.T) {
	secret := "top_secret"
	verify, err := Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0Fla3oY", []byte("Admin"))
	if err != nil {
		t.Errorf("... %v", err)
	}
	if !verify {
		t.Errorf("Error")
	}
	verify ,err= Verify("rrr.rrr.rrr.rrr.", []byte(secret))
	if err == nil{
		t.Errorf("Bad token %v", err)
	}
	verify, err = Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0F55la3oY", []byte(secret))
	if verify {
		t.Errorf("Not correct token")
	}
}