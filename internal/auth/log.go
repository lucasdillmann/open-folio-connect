package auth

import "log/slog"

func logLoginCode(email, code, requestID string) {
	slog.Warn("one-time login code",
		"email", email, "code", code, "requestId", requestID)
}

func logOTPResult(email, token, result, requestID string) {
	if result == "success" {
		slog.Info("otp verified",
			"email", email, "result", result, "requestId", requestID)
		return
	}

	slog.Warn("otp check failed",
		"email", email, "result", result,
		"code", token, "requestId", requestID)
}
