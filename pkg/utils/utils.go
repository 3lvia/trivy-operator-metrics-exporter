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

/*
func getFunctionName() string {
	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)

	frames := runtime.CallersFrames(pc)
	frame, _ := frames.Next()

	slice := strings.SplitAfter(frame.Function, ".")
	return slice[len(slice)-1]
}
*/
