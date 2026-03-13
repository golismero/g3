package g3log

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/apsdehal/go-logger"
)

// Default logger object.
var log *logger.Logger

func init() {
	InitLogger()
}

// Set up the logger.
func InitLogger() {
	var err error
	log, err = logger.New("", 1, os.Stderr)
	if err != nil {
		panic(err)
	}
	SetFormat("%{message}")
	SetLogLevel(os.Getenv("G3_LOG_LEVEL"))
}

// Set the format.
func SetFormat(format string) {
	log.SetFormat(format)
}

// Set the log level.
var LogLevel = "INFO"
func SetLogLevel(level string) {
	level = strings.TrimSpace(strings.ToUpper(level))
	switch level {
	case "CRITICAL":
		log.SetLogLevel(logger.CriticalLevel)
		LogLevel = level
	case "ERROR":
		log.SetLogLevel(logger.ErrorLevel)
		LogLevel = level
	case "WARNING":
		log.SetLogLevel(logger.WarningLevel)
		LogLevel = level
	case "NOTICE":
		log.SetLogLevel(logger.NoticeLevel)
		LogLevel = level
	case "INFO":
		log.SetLogLevel(logger.InfoLevel)
		LogLevel = level
	case "DEBUG":
		log.SetLogLevel(logger.DebugLevel)
		LogLevel = level
	default:
		log.SetLogLevel(logger.InfoLevel)
		LogLevel = "INFO"
	}
}

// The following are wrappers for convenience.
// Syntactic sugar FTW! :)

func Debug(args ...interface{}) {log.Debug(fmt.Sprint(args...))}
func Debugf(format string, args ...interface{}) {log.DebugF(format, args...)}

func Info(args ...interface{}) {log.Info(fmt.Sprint(args...))}
func Infof(format string, args ...interface{}) {log.Infof(format, args...)}

func Notice(args ...interface{}) {log.Notice(fmt.Sprint(args...))}
func Noticef(format string, args ...interface{}) {log.Noticef(format, args...)}

func Warning(args ...interface{}) {log.Warning(fmt.Sprint(args...))}
func Warningf(format string, args ...interface{}) {log.Warningf(format, args...)}

func Error(args ...interface{}) {log.Error(fmt.Sprint(args...))}
func Errorf(format string, args ...interface{}) {log.Errorf(format, args...)}

func Critical(args ...interface{}) {log.Critical(fmt.Sprint(args...))}
func Criticalf(format string, args ...interface{}) {log.Criticalf(format, args...)}

func Traceback(err error) {log.Error(err.Error() + "\n" + string(debug.Stack()))}
