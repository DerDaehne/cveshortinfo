package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/api/getcveinfo", getCVEInfoHandler)

	fmt.Println("Server started on :8080")
	log.Println("Server started on :8080") // Hinzugefügte Log-Ausgabe
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Server start error: %v", err) // Fehlerausgabe
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s", r.Method, r.URL.Path) // Hinzugefügte Log-Ausgabe

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getCVEInfoHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("API Request: %s %s", r.Method, r.URL.Path)

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			log.Printf("Error parsing form: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	numbers := r.Form["numbers"]
	numbersStr := string(numbers[0])
	cves := strings.Split(numbersStr, "\n")
	log.Printf("numbersStr: %s", numbersStr)

	for _, cve := range cves {
		cve = strings.TrimSpace(cve) // Entferne führende und abschließende Leerzeichen
		if cve == "" {
			continue // Überspringe leere Zeilen
		}

		log.Printf("Received CVE number: %s", cve)
		// Abruf der CVE-Informationen von der API
		cveInfo, err := fetchCVEInfo(cve)
		if err != nil {
			log.Printf("Error fetching CVE info for %s: %v", cve, err)
			continue
		}
		fmt.Printf("CVE: %s, Base Score: %s, Description: %s\n", cve, cveInfo.BaseScore, cveInfo.Description)
	}
}

func fetchCVEInfo(cveNumber string) (CVEInfo, error) {
	resp, err := http.Get("https://v1.cveapi.com/" + cveNumber + ".json")
	if err != nil {
		log.Printf("Error fetching CVE info for %s: %v", cveNumber, err)
		return CVEInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("HTTP status code for %s: %d", cveNumber, resp.StatusCode)
		return CVEInfo{}, fmt.Errorf("HTTP status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body for %s: %v", cveNumber, err)
		return CVEInfo{}, err
	}

	var cveResponse struct {
		CVE struct {
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		Impact struct {
			BaseMetricV3 struct {
				CvssV3 struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
		} `json:"impact"`
	}

	if err := json.Unmarshal(body, &cveResponse); err != nil {
		log.Printf("Error unmarshaling JSON for %s: %v", cveNumber, err)
		return CVEInfo{}, err
	}

	cveInfo := CVEInfo{
		Description: cveResponse.CVE.Description.DescriptionData[0].Value,
		BaseScore:   strconv.FormatFloat(cveResponse.Impact.BaseMetricV3.CvssV3.BaseScore, 'f', -1, 64),
	}

	log.Printf("Received CVE info for %s: BaseScore: %s, Description: %s", cveNumber, cveInfo.BaseScore, cveInfo.Description)

	return cveInfo, nil
}

// Datenstruktur für die CVE-Informationen
type CVEInfo struct {
	BaseScore   string
	Description string
}
