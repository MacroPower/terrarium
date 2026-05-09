package nflog

import "log/slog"

// Option configures optional behavior of a [Reader].
//
// The following options are available:
//
//   - [WithLogger]
type Option func(*readerOptions)

// readerOptions holds the resolved values configured by [Option] funcs.
type readerOptions struct {
	logger *slog.Logger
}

func defaultReaderOptions() readerOptions {
	return readerOptions{logger: slog.Default()}
}

// WithLogger sets the logger used for diagnostic messages. An [Option].
func WithLogger(l *slog.Logger) Option {
	return func(o *readerOptions) {
		if l != nil {
			o.logger = l
		}
	}
}
