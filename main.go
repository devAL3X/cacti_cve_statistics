package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const ShodanURL = "https://api.shodan.io"

type ShodanResponse struct {
	Matches []interface{} `json:"matches"`
	Total   int           `json:"total"`
}

func searchShodan(query string, page uint) (*ShodanResponse, error) {
	apiKey := os.Getenv("SHODAN_API_KEY") // Get API key from Shodan

	client := http.Client{}

	// Build the URL for the Shodan API request
	u, err := url.Parse(fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&page=%d",
		ShodanURL, apiKey, url.QueryEscape(query), page))

	if err != nil {
		return nil, err
	}

	// Make the request to the Shodan API
	res, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Decode the JSON response
	var data ShodanResponse
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

var ErrNoVersion = errors.New("no version found")

func extractPhpVersion(s string) (string, error) {
	re := regexp.MustCompile(`PHP\/\d+\.\d+\.\d+`)
	ver := re.Find([]byte(s))
	if ver == nil {
		return "", ErrNoVersion
	}
	return string(ver)[4:], nil
}

func extractCactiVersion(s string) (string, error) {
	re := regexp.MustCompile(`Version \d+\.\d+\.\d+`)
	ver := re.Find([]byte(s))
	if ver == nil {
		return "", ErrNoVersion
	}
	return string(ver)[8:], nil
}

// CompareVersions compares two semantic versions
// returns 1 if first version is newer, -1 if second version is newer
// returns 0 if first version is equal to second
func CompareVersions(ver1 string, ver2 string) int {
	// Split the version strings into arrays of integers
	ver1Arr := strings.Split(ver1, ".")
	ver2Arr := strings.Split(ver2, ".")

	// Compare each integer in the arrays
	for i := 0; i < len(ver1Arr) && i < len(ver2Arr); i++ {
		ver1Num, _ := strconv.Atoi(ver1Arr[i])
		ver2Num, _ := strconv.Atoi(ver2Arr[i])

		if ver1Num > ver2Num {
			return 1
		} else if ver1Num < ver2Num {
			return -1
		}
	}

	// If all integers are equal up to this point, compare the lengths of the version arrays
	if len(ver1Arr) > len(ver2Arr) {
		return 1
	} else if len(ver1Arr) < len(ver2Arr) {
		return -1
	}

	// If both version strings are the same, return 0
	return 0
}

func main() {
	resp, err := searchShodan("cacti country:RU", 1)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}

	nPages := (resp.Total + 99) / 100 // integer ceiling. 100 results per page

	vulnerableCnt := 0
	for page := 1; page <= nPages; page++ {
		resp, err := searchShodan("cacti country:RU", uint(page))
		if err != nil {
			fmt.Printf("Error: %s", err)
			return
		}

		for _, host := range resp.Matches {
			if data, ok := host.(map[string]interface{}); ok {
				vulnerable := false
				cactiVer, err := extractCactiVersion(fmt.Sprintf("%v", data))
				if err == nil {
					if CompareVersions(cactiVer, "1.2.22") < 1 {
						vulnerable = true
					}
				}

				phpVer, err := extractPhpVersion(fmt.Sprintf("%v", data))
				if err == nil {
					if CompareVersions(phpVer, "8.0.0") < 0 {
						vulnerable = true
					}
				}

				if vulnerable {
					vulnerableCnt++
				}
			}
		}
	}
	fmt.Printf("Possible vulnerable %d of %d", vulnerableCnt, resp.Total)
}
