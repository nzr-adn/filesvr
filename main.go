package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	Username string
	Password string
	Port string
	Hash string
	Path string
}

func NewApp(username, password, port, path string) *App {
	hash, err := HashPassword(password)
	if err != nil {
		log.Fatal(err)
	}
	return &App{
		Username: username,
		Password: password,
		Port: port,
		Path: path,
		Hash: hash,
	}
}


func getHomeDir() string {
	dirname, err := os.UserHomeDir()
    if err != nil {
        log.Fatal( err )
    }
	return dirname
}

func HashPassword(passwd string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(passwd), 8)
	if (err != nil) {
		return "", err
	}
	return string(bytes), nil
}

func ComparePasswordHash(passwd, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(passwd))
	return err == nil
}

func (app *App) checkCredential(usr, pass string) bool {
	if usr != app.Username {
		return false
	}
	if !ComparePasswordHash(pass, app.Hash) {
		return false
	}
	return true
}


func (app *App) HandleFileServer(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if ok {
		if app.checkCredential(user,pass) {
			http.FileServer(http.Dir(app.Path)).ServeHTTP(w,r)
			return
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return
	
} 

func (app *App) Start() {
	router := http.DefaultServeMux
	router.HandleFunc("/", app.HandleFileServer)

	svr := &http.Server{
		Addr: app.Port,
		Handler: router,
	}

    _, err := os.Stat(app.Path)
    if os.IsNotExist(err) {
        log.Fatalf("Directory '%s' not found.\n", app.Path)
    }

	fmt.Printf("Server started on Port %s \n", app.Port)
	log.Fatal(svr.ListenAndServe())
}

func main() {
	
	name := flag.String("name", "admin", "Credential Name")
	pass := flag.String("pass", "admin!23", "Credential Pass")
	port := flag.Int("port", 8000, "Port Server")
	path := flag.String("path", getHomeDir(), "Path Dir")

	flag.Parse()

	p := strconv.Itoa(*port)
	
	app := NewApp(*name,*pass, ":" + p, *path)
	app.Start()

	
}