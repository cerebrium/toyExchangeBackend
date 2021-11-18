package main

import (
	"io/ioutil"
	"log"
	"net/http"
)

func getCryptoData() {
	resp, err := http.Get("https://api.coinmarketcap.com/v1/ticker/")
	
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatalln(err)
	}

	return body
}
