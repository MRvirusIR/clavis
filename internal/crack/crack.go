// Package crack brute-forces the HMAC secret of an HS* JWT, either from a
// wordlist or by incremental character brute force. It is concurrent and
// stops as soon as a worker finds the key.
package crack

import (
	"bufio"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

type Result struct {
	Found   bool
	Secret  string
	Tried   uint64
	Elapsed time.Duration
}

// Progress is called periodically with the number of candidates tried so far.
type Progress func(tried uint64, last string)

// Wordlist tries each line of path as the HMAC secret.
func Wordlist(ctx context.Context, t *jwt.Token, path string, workers int, prog Progress) (Result, error) {
	start := time.Now()
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	alg := t.Alg()
	si := t.SigningInput()
	sig := t.Sig

	jobs := make(chan string, 4096)
	var tried uint64
	var found atomic.Bool
	var secret atomic.Value
	secret.Store("")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				if found.Load() {
					return
				}
				n := atomic.AddUint64(&tried, 1)
				if jwt.VerifyHMAC(alg, si, []byte(w), sig) {
					secret.Store(w)
					found.Store(true)
					cancel()
					return
				}
				if prog != nil && n%20000 == 0 {
					prog(n, w)
				}
			}
		}()
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
feed:
	for sc.Scan() {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- sc.Text():
		}
	}
	close(jobs)
	wg.Wait()

	res := Result{Tried: atomic.LoadUint64(&tried), Elapsed: time.Since(start)}
	if found.Load() {
		res.Found = true
		res.Secret = secret.Load().(string)
	}
	return res, sc.Err()
}

// Brute tries every combination of charset up to maxLen characters.
func Brute(ctx context.Context, t *jwt.Token, charset string, maxLen, workers int, prog Progress) Result {
	start := time.Now()
	alg := t.Alg()
	si := t.SigningInput()
	sig := t.Sig

	jobs := make(chan string, 4096)
	var tried uint64
	var found atomic.Bool
	var secret atomic.Value
	secret.Store("")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				if found.Load() {
					return
				}
				n := atomic.AddUint64(&tried, 1)
				if jwt.VerifyHMAC(alg, si, []byte(w), sig) {
					secret.Store(w)
					found.Store(true)
					cancel()
					return
				}
				if prog != nil && n%20000 == 0 {
					prog(n, w)
				}
			}
		}()
	}

	cs := []byte(charset)
	var gen func(prefix []byte, depth int) bool
	gen = func(prefix []byte, depth int) bool {
		if ctx.Err() != nil {
			return false
		}
		if depth == 0 {
			select {
			case <-ctx.Done():
				return false
			case jobs <- string(prefix):
			}
			return true
		}
		for _, ch := range cs {
			if !gen(append(prefix, ch), depth-1) {
				return false
			}
		}
		return true
	}
loop:
	for l := 1; l <= maxLen; l++ {
		if !gen(nil, l) {
			break loop
		}
	}
	close(jobs)
	wg.Wait()

	res := Result{Tried: atomic.LoadUint64(&tried), Elapsed: time.Since(start)}
	if found.Load() {
		res.Found = true
		res.Secret = secret.Load().(string)
	}
	return res
}
