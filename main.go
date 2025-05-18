package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	_ "net/http/pprof"
)

type Book struct {
	ID     int     `json:"id"`
	Title  string  `json:"title"`
	Author string  `json:"author"`
	Price  float64 `json:"price"`
}

var (
	books = []Book{}
	nextID = 1
	ctx = context.Background()
	rdb *redis.Client
	sanitizer *bluemonday.Policy
	notificationServer *NotificationServer
)

func init() {
	// Configure logrus
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// Initialize Redis
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Test Redis connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		logrus.WithError(err).Warning("Redis connection failed - caching will be disabled")
		rdb = nil
	}

	// Initialize sanitizer
	sanitizer = bluemonday.UGCPolicy()
}

func main() {
	// Start notification server
	notificationServer = NewNotificationServer(":9000")
	go func() {
		if err := notificationServer.Start(); err != nil {
			logrus.WithError(err).Fatal("Failed to start notification server")
		}
	}()

	router := mux.NewRouter()

	// CRUD endpoints
	router.HandleFunc("/books", getBooks).Methods("GET")
	router.HandleFunc("/books", createBook).Methods("POST")
	router.HandleFunc("/books/{id}", getBook).Methods("GET")
	router.HandleFunc("/books/{id}", updateBook).Methods("PUT")
	router.HandleFunc("/books/{id}", deleteBook).Methods("DELETE")

	// Debug endpoints
	router.HandleFunc("/debug/gc", triggerGC).Methods("POST")
	router.HandleFunc("/debug/memory", getMemoryStats).Methods("GET")

	// Enable pprof endpoints
	router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)

	logrus.WithFields(logrus.Fields{
		"port": 8080,
	}).Info("Server starting...")

	if err := http.ListenAndServe(":8080", router); err != nil {
		logrus.WithError(err).Fatal("Server failed to start")
	}
}

func getBooks(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": "GET",
		"path":   "/books",
	}).Info("Fetching all books")

	w.Header().Set("Content-Type", "application/json")

	// Try to get from cache first
	if rdb != nil {
		cachedBooks, err := rdb.Get(ctx, "books").Result()
		if err == nil {
			logrus.Info("Serving books from cache")
			w.Write([]byte(cachedBooks))
			return
		}
	}

	// If not in cache or cache failed, get from memory
	booksJSON, err := json.Marshal(books)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal books")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store in cache for future requests
	if rdb != nil {
		err = rdb.Set(ctx, "books", string(booksJSON), 5*time.Minute).Err()
		if err != nil {
			logrus.WithError(err).Warning("Failed to cache books")
		}
	}

	w.Write(booksJSON)
}

func getBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		logrus.WithError(err).Error("Invalid book ID format")
		http.Error(w, "Invalid book ID", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"method": "GET",
		"path":   "/books/{id}",
		"id":     id,
	}).Info("Fetching book by ID")

	for _, book := range books {
		if book.ID == id {
			json.NewEncoder(w).Encode(book)
			return
		}
	}
	http.Error(w, "Book not found", http.StatusNotFound)
}

func createBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var book Book
	if err := json.NewDecoder(r.Body).Decode(&book); err != nil {
		logrus.WithError(err).Error("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Sanitize input
	book.Title = sanitizer.Sanitize(book.Title)
	book.Author = sanitizer.Sanitize(book.Author)

	// Validate input
	if book.Title == "" || book.Author == "" {
		logrus.Error("Invalid book data: title and author are required")
		http.Error(w, "Title and author are required", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"method": "POST",
		"path":   "/books",
		"title":  book.Title,
		"author": book.Author,
	}).Info("Creating new book")
	book.ID = nextID
	nextID++
	books = append(books, book)

	// Notify connected clients about new book
	notificationServer.NotifyBookEvent("create", book)

	json.NewEncoder(w).Encode(book)
}

func updateBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		logrus.WithError(err).Error("Invalid book ID format")
		http.Error(w, "Invalid book ID", http.StatusBadRequest)
		return
	}

	var updatedBook Book
	if err := json.NewDecoder(r.Body).Decode(&updatedBook); err != nil {
		logrus.WithError(err).Error("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"method": "PUT",
		"path":   "/books/{id}",
		"id":     id,
		"title":  updatedBook.Title,
		"author": updatedBook.Author,
	}).Info("Updating book")

	for i, book := range books {
		if book.ID == id {
			updatedBook.ID = id
			books[i] = updatedBook
			
			// Notify connected clients about updated book
			notificationServer.NotifyBookEvent("update", updatedBook)
			
			json.NewEncoder(w).Encode(updatedBook)
			return
		}
	}
	http.Error(w, "Book not found", http.StatusNotFound)
}

// Debug endpoints
func triggerGC(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Triggering garbage collection")
	runtime.GC()
	w.WriteHeader(http.StatusOK)
}

func getMemoryStats(w http.ResponseWriter, r *http.Request) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alloc":      stats.Alloc,
		"totalAlloc": stats.TotalAlloc,
		"sys":        stats.Sys,
		"numGC":      stats.NumGC,
	})
}

func deleteBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		logrus.WithError(err).Error("Invalid book ID format")
		http.Error(w, "Invalid book ID", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"method": "DELETE",
		"path":   "/books/{id}",
		"id":     id,
	}).Info("Deleting book")

	for i, book := range books {
		if book.ID == id {
			deletedBook := books[i]
			books = append(books[:i], books[i+1:]...)
			
			// Notify connected clients about deleted book
			notificationServer.NotifyBookEvent("delete", deletedBook)
			
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Error(w, "Book not found", http.StatusNotFound)
}
