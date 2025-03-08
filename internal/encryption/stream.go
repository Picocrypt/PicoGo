package encryption

type streamer interface {
	stream(p []byte) ([]byte, error)
}

type streamerFlusher interface {
	streamer
	flush() ([]byte, error)
}

func streamStack[T streamer](streams []T, p []byte) ([]byte, error) {
	var err error
	for _, stream := range streams {
		p, err = stream.stream(p)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			break
		}
	}
	return p, nil
}

func flushStack(streams []streamerFlusher) ([]byte, error) {
	p := []byte{}
	for _, stream := range streams {
		pStream, err := stream.stream(p)
		if err != nil {
			return nil, err
		}
		pFlush, err := stream.flush()
		if err != nil {
			return nil, err
		}
		p = append(pStream, pFlush...)
	}
	return p, nil
}
