package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

const (
	DbHost     = "127.0.0.1"   
	DbPort     = "5432"        
	DbUser     = "admin"       
	DbPassword = "admin123"  
	DbName     = "tiketbioskop"     
	JwtSecret  = "tb3XK:zxH39b{U-[:}:£:`61!yUP39m%!xLD"  
)


var db *sql.DB

func main() {
	// Initialize database connection
	initDb()
	defer db.Close()

	// Initialize router
	router := mux.NewRouter()

	// Route handles & endpoints
	router.HandleFunc("/api/login", Login).Methods("POST")
	router.HandleFunc("/api/schedules", CreateSchedule).Methods("POST")
	router.HandleFunc("/api/schedules", GetAllSchedules).Methods("GET")
	router.HandleFunc("/api/schedules/{id}", GetSchedule).Methods("GET")
	router.HandleFunc("/api/schedules/{id}", UpdateSchedule).Methods("PUT")
	router.HandleFunc("/api/schedules/{id}", DeleteSchedule).Methods("DELETE")

	// Start server
	log.Fatal(http.ListenAndServe(":8000", router))
}

// Initialize database connection
func initDb() {
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		DbHost, DbPort, DbUser, DbPassword, DbName)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully connected to database")
}

// User struct for login
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Schedule struct for CRUD
type Schedule struct {
	ID       int    `json:"id"`
	MovieID  int    `json:"movie_id"`
	ScreenID int    `json:"screen_id"`
	Showtime string `json:"showtime"`
	Date     string `json:"date"`
}

// Function for user login
func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword := getUserPassword(user.Username)

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid login credentials")
		return
	}

	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &jwt.StandardClaims{
		Subject:   user.Username,
		ExpiresAt: expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(JwtSecret))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error while signing the token")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Bearer %s", tokenString)
}


// Function to get hashed password from DB
func getUserPassword(username string) (hashedPassword string) {
	// Query the database to get the hashed password for the given username
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", username).Scan(&hashedPassword)
	if err != nil {
		log.Println(err)
	}
	return hashedPassword
}

// Helper function to validate JWT
func validateToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JwtSecret), nil
	})
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return nil, err
	}
	return token, nil
}

// CreateSchedule handler
func CreateSchedule(w http.ResponseWriter, r *http.Request) {
	token, err := validateToken(w, r)
	if err != nil {
		// Token validation error is already handled in validateToken
		return
	}

	_, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	var schedule Schedule
	err = json.NewDecoder(r.Body).Decode(&schedule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sqlStatement := `
	INSERT INTO showtimes (movie_id, screen_id, showtime, date)
	VALUES ($1, $2, $3, $4)
	RETURNING showtime_id`
	id := 0
	err = db.QueryRow(sqlStatement, schedule.MovieID, schedule.ScreenID, schedule.Showtime, schedule.Date).Scan(&id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(id)
}


// GetAllSchedules handler
func GetAllSchedules(w http.ResponseWriter, r *http.Request) {
	_, err := validateToken(w, r)
	if err != nil {
		// Token validation error is already handled in validateToken
		return
	}

	var schedules []Schedule
	rows, err := db.Query("SELECT showtime_id, movie_id, screen_id, showtime, date FROM showtimes")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var s Schedule
		if err := rows.Scan(&s.ID, &s.MovieID, &s.ScreenID, &s.Showtime, &s.Date); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		schedules = append(schedules, s)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedules)
}

// GetSchedule handler
func GetSchedule(w http.ResponseWriter, r *http.Request) {
	_, err := validateToken(w, r)
	if err != nil {
		// Token validation error is already handled in validateToken
		return
	}

	params := mux.Vars(r)
	id := params["id"]

	var s Schedule
	sqlStatement := "SELECT showtime_id, movie_id, screen_id, showtime, date FROM showtimes WHERE showtime_id = $1"
	row := db.QueryRow(sqlStatement, id)
	err = row.Scan(&s.ID, &s.MovieID, &s.ScreenID, &s.Showtime, &s.Date)
	switch {
	case err == sql.ErrNoRows:
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// UpdateSchedule handler
func UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	_, err := validateToken(w, r)
	if err != nil {
		// Token validation error is already handled in validateToken
		return
	}

	params := mux.Vars(r)
	id := params["id"]

	var s Schedule
	err = json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sqlStatement := `
	UPDATE showtimes
	SET movie_id = $2, screen_id = $3, showtime = $4, date = $5
	WHERE showtime_id = $1;`
	_, err = db.Exec(sqlStatement, id, s.MovieID, s.ScreenID, s.Showtime, s.Date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteSchedule handler
func DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	_, err := validateToken(w, r)
	if err != nil {
		// Token validation error is already handled in validateToken
		return
	}

	params := mux.Vars(r)
	id := params["id"]

	sqlStatement := "DELETE FROM showtimes WHERE showtime_id = $1;"
	_, err = db.Exec(sqlStatement, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}


