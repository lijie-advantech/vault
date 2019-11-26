package model

type APISuccess struct {
	Message string `json:"message"`
}

type APIError struct {
	ErrorCode    int    `json:"errorCode"`
	ErrorMessage string `json:"errorMsg"`
}
