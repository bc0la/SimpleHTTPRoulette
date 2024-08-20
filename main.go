package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const retryCount = 5
const retryDelay = time.Millisecond * 100 // Delay between retries if the database is locked

type ShodanResult struct {
	IPStr string `json:"ip_str"`
	Port  int    `json:"port"`
}

type ShodanResponse struct {
	Matches []ShodanResult `json:"matches"`
}

func fetchSimpleHTTPServerURLs(apiKey string) ([]string, error) {
	var allURLs []string
	page := 1
	for {

		// print out page number
		fmt.Printf("Shodan Results Page: %d\n", page)
		// Shodan API URL for searching with pagination
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=product:SimpleHTTPServer&page=%d", apiKey, page)

		// Make the HTTP request
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch data from Shodan API: %v", err)
		}
		defer resp.Body.Close()

		// Read and parse the response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		var shodanResp ShodanResponse
		err = json.Unmarshal(body, &shodanResp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %v", err)
		}

		// Break if no more matches are returned
		if len(shodanResp.Matches) == 0 {
			break
		}

		// Extract URLs
		for _, match := range shodanResp.Matches {
			url := fmt.Sprintf("http://%s:%d", match.IPStr, match.Port)
			allURLs = append(allURLs, url)
		}

		// Move to the next page
		page++
	}

	return allURLs, nil
}

func startShodanQuery(apiKey string) {
	// Run the Shodan query immediately the first time
	//log.Println("Querying Shodan for SimpleHTTPServer URLs...")
	// urls, err := fetchSimpleHTTPServerURLs(apiKey)
	// if err != nil {
	// 	log.Printf("Error querying Shodan API: %v", err)
	// } else {
	// 	// Write the URLs to the urls.txt file
	// 	err = overwriteURLsFile("urls.txt", urls)
	// 	if err != nil {
	// 		log.Printf("Error writing URLs to file: %v", err)
	// 	} else {
	// 		log.Printf("Successfully wrote %d URLs to urls.txt", len(urls))
	// 	}
	// }

	// Set up the ticker to query every minute after the first run
	ticker := time.NewTicker(768 * time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Println("Querying Shodan for SimpleHTTPServer URLs...")
				urls, err := fetchSimpleHTTPServerURLs(apiKey)
				if err != nil {
					log.Printf("Error querying Shodan API: %v", err)
					continue
				}

				// Write the URLs to the urls.txt file
				err = overwriteURLsFile("urls.txt", urls)
				if err != nil {
					log.Printf("Error writing URLs to file: %v", err)
				} else {
					log.Printf("Successfully wrote %d URLs to urls.txt", len(urls))
					updateDatabaseFromFile("urls.txt")
				}
			}
		}
	}()
}

func overwriteURLsFile(filePath string, urls []string) error {
	// Open the file for writing, overwriting if it exists
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Write each URL on a new line
	for _, url := range urls {
		_, err := file.WriteString(url + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	return nil
}

func initDB() {
	var err error
	// Use shared in-memory SQLite database
	db, err = sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		log.Fatal(err)
	}

	// Create the sites table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func ensureURLScheme(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "http://" + url
	}
	return url
}

func executeWithRetry(query string, args ...interface{}) error {
	var err error
	for i := 0; i < retryCount; i++ {
		_, err = db.Exec(query, args...)
		if err != nil && strings.Contains(err.Error(), "database is locked") {
			time.Sleep(retryDelay)
			continue
		} else if err != nil {
			log.Printf("Error executing query: %v", err)
			return err
		}
		return nil
	}
	log.Printf("Failed to execute query after %d retries: %v", retryCount, err)
	return err
}

func updateDatabaseFromFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return
	}
	defer file.Close()

	// Read all URLs from the file into a map
	urlMap := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	log.Println("Reading URLs from file...")
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			// Ensure the URL has the correct scheme
			url = ensureURLScheme(url)
			urlMap[url] = true
			log.Printf("URL from file: %s", url)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}

	// Get all URLs currently in the database
	log.Println("Fetching URLs from database...")
	rows, err := db.Query("SELECT url FROM sites")
	if err != nil {
		log.Printf("Failed to query database: %v", err)
		return
	}
	defer rows.Close()

	// Build a list of URLs currently in the database
	var dbURLs []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			log.Printf("Failed to scan database row: %v", err)
			return
		}
		dbURLs = append(dbURLs, url)
		log.Printf("URL from database: %s", url)
	}

	// Remove URLs from the database that are not in the file
	for _, dbURL := range dbURLs {
		if !urlMap[dbURL] {
			log.Printf("Deleting URL from database: %s", dbURL)
			err := executeWithRetry("DELETE FROM sites WHERE url = ?", dbURL)
			if err != nil {
				log.Printf("Failed to delete URL after retrying: %v", err)
			}
		}
	}

	// Add new URLs to the database
	for url := range urlMap {
		if !contains(dbURLs, url) {
			log.Printf("Inserting new URL into database: %s", url)
			err := executeWithRetry("INSERT INTO sites (url) VALUES (?)", url)
			if err != nil {
				log.Printf("Failed to insert URL after retrying: %v", err)
			}
		}
	}

	log.Printf("Database update complete. %d URLs in database.", len(urlMap))
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func shuffleHandler(w http.ResponseWriter, r *http.Request) {
	// Query a random site from the database
	var url string
	err := db.QueryRow("SELECT url FROM sites ORDER BY RANDOM() LIMIT 1").Scan(&url)
	if err != nil {
		log.Printf("Failed to fetch a random site: %v", err)
		http.Error(w, "Failed to fetch a random site", http.StatusInternalServerError)
		return
	}

	// Redirect the user to the random site
	log.Printf("Redirecting to: %s", url)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Load and render the HTML template
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// func startDatabaseUpdater(filePath string) {
// 	// Periodically update the database from the file every 2 minutes
// 	ticker := time.NewTicker(1 * time.Minute)
// 	go func() {
// 		for {
// 			select {
// 			case <-ticker.C:
// 				log.Println("Updating database from file...")
// 				updateDatabaseFromFile(filePath)
// 			}
// 		}
// 	}()
// }

func main() {
	// Initialize the database
	apiKey := os.Getenv("SHODAN_API_KEY")
	startShodanQuery(apiKey)

	initDB()
	rand.Seed(time.Now().UnixNano())

	// Populate the database immediately on start
	updateDatabaseFromFile("urls.txt")

	// Define routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/shuffle", shuffleHandler)

	// Start the server
	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
