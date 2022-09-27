package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

func init() {
	log.SetFlags(log.Ltime | log.Lshortfile)
}

// error check
func check(e error) {
	if e != nil {
		log.Fatalln(e)
	}
}

// Eğer OTP'miz 6 karakterden az ise sol başa 0'lar ekler
// "1234" ise "001234" haline çevirir.
func prefix0(otp string) string {
	if len(otp) == 6 {
		return otp
	}
	for i := 6 - len(otp); i > 0; i-- {
		otp = "0" + otp
	}
	return otp
}

func getHOTPToken(secret string, interval int64) string {

	// secret key'i base32 formata dönüştür.
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	check(err)
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	//Signing the value using HMAC-SHA1 Algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	o := h[19] & 15

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)

	check(err)
	//Ignore most significant bits as per RFC 4226.
	//Takes division from one million to generate a remainder less than < 7 digits
	h12 := (int(header) & 0x7fffffff) % 1000000

	otp := strconv.Itoa(h12)

	return prefix0(otp)
}

func getTOTPToken(secret string) string {
	// TOTP tokenimiz aslında 30 saniyede bir güncellenen HOTP tokenimizdir
	interval := time.Now().Unix() / 30
	return getHOTPToken(secret, interval)
}

func main() {

	// secret sadece alfabe harfleri olabilir
	secret := "dummysecretdummy" // Google Authenticator'da kullandığımız secret
	otp := getTOTPToken(secret)

	fmt.Println(otp)
}
