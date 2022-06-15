package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	. "server/internal/token"
	. "server/pkg/token"
	. "server/repository/db/mongodb"

	"github.com/gorilla/mux"
)

//@title Authenntication Go
//version 1.0
//@description Тестовое задание BackDev

//@host lacalhost:8000
//@basePath /

type Guid struct {
	Guid string `json:"guid"`
}

type MessageJson struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func main() {
	router := mux.NewRouter()
	router.Handle("/api/get-token", GetTokensHandler).Methods("POST")
	router.Handle("/api/refresh-token", RefreshTokenHandler).Methods("PUT")
}

var GetTokensHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	log.Printf("Запрос на получение токена")
	body, _ := io.ReadAll(r.Body)
	var guid Guid
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Host", "localhost")

	err := json.Unmarshal(body, &guid)
	if err != nil {
		errHandler(err, "Ошибка при разборе json", &w)
		return
	}

	SendTokenResponse(guid.Guid, &w, InsertRefreshToken)
	log.Printf("Токен успешно сгенерирован")
})

var RefreshTokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Host", "localhost")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errHandler(err, "Ошибка при чтении тела запроса", &w)
	}
	token, err := DecodingJsonToken(body)
	if err != nil {
		errHandler(err, "Ошибка при разборе json", &w)
		return
	}

	if token.Refresh == "" || token.Access == "" {
		errHandler(nil, "Отсутствует токен(ы)", &w)
		return
	}

	if claims, err := ParseVerifiedAccessToken(token.Access); claims == nil || err != nil {
		errHandler(err, "Ошибка валидации access токена", &w)
		return
	} else {
		if err := RefreshTokenValidate(claims.Guid, token.Refresh); err == nil {
			SendTokenResponse(claims.Guid, &w, UpdateRefreshToken)
		} else {
			errHandler(err, "Ошибка валидации refresh токена", &w)
		}
	}
})

func errHandler(err error, errText string, w *http.ResponseWriter) {
	log.Println(err)
	(*w).WriteHeader(http.StatusBadRequest)
	message, _ := json.Marshal(MessageJson{Status: 0, Message: errText})
	_, _ = (*w).Write(message)
	return
}
func SendTokenResponse(guid string, w *http.ResponseWriter, query func(string, string) error) {
	if guid == "" {
		errHandler(nil, "Поле guid пустое или отсутствует", w)
		return
	}

	access, err := GetNewAccessToken(guid)
	if err != nil {
		errHandler(err, "Ошибка при генерации access токена", w)
		return
	}

	refresh, err := CreateRefreshToken(guid, query)
	if err != nil {
		errHandler(err, "Ошибка при создании refresh токена", w)
		return
	}

	response, err := TokenEncodingJson(Tokens{Status: 1, Access: access, Refresh: refresh, Guid: guid})
	(*w).WriteHeader(http.StatusCreated)
	_, err = (*w).Write(response)
	log.Printf("Токен успешно сгенерирован")
}
