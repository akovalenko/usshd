package utils

import (
	"context"
	"time"
)

func Run(ctx context.Context, pause time.Duration,
	startToStart bool, code func()) {
	if startToStart {
		go func() {
			ticker := time.NewTicker(pause)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					code()
				case <-ctx.Done():
					return
				}
			}
		}()
	} else {
		go func() {
			for {
				timer := time.NewTimer(pause)
				select {
				case <-timer.C:
					code()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}
