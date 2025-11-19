package utils

import (
	"os"
)

func Ternary[K, V any](condition bool, trueValue K, falseValue V) any {
	if condition {
		return trueValue
	}

	return falseValue
}

func GetEnvFallback(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}
