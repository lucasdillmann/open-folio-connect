package httpx

type APIError struct {
	Details any    `json:"details,omitempty"`
	Kind    string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Message
}
