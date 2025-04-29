package ui

import (
	"fmt"
	"time"
)

type ByteRate struct {
	startTime      int64
	processedBytes int64
}

func (b *ByteRate) Read(p []byte) (n int, err error) {
	if b.startTime == 0 {
		b.startTime = time.Now().Unix()
	}
	b.processedBytes += int64(len(p))
	return n, nil
}

func (b *ByteRate) Write(p []byte) (n int, err error) {
	if b.startTime == 0 {
		b.startTime = time.Now().Unix()
	}
	b.processedBytes += int64(len(p))
	return n, nil
}

func (b *ByteRate) GetRate() string {
	rate := 0.0
	if b.startTime != 0 {
		elapsed := time.Now().Unix() - b.startTime
		if elapsed != 0 {
			rate = float64(b.processedBytes) / float64(elapsed)
		}
	}
	return asStat(rate) + "/s"
}

func (b *ByteRate) GetBytes() string {
	return asStat(float64(b.processedBytes))
}

func asStat(bytes float64) string {
	prefix := ""
	scale := 1
	for i, p := range []string{"B", "KB", "MB", "GB"} {
		newScale := 1 << (i * 10)
		if bytes > float64(newScale) {
			prefix = p
			scale = newScale
		}
	}
	return fmt.Sprintf("% 7.2f %s", bytes/float64(scale), prefix)
}
