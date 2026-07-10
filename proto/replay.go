package proto

import "sync"

const (
	wordBits   = 64
	wordCount  = 128
	totalBits  = wordBits * wordCount
	windowSize = totalBits - wordBits
)

type Filter struct {
	lastNonceIn   uint64
	lastNonceInMu sync.Mutex
	bitmap        [wordCount]uint64
}

func (f *Filter) Reset() {
	f.lastNonceInMu.Lock()
	defer f.lastNonceInMu.Unlock()
	f.lastNonceIn = 0
	clear(f.bitmap[:])
}

func (f *Filter) ValidateNonce(seq uint64) bool {
	f.lastNonceInMu.Lock()
	defer f.lastNonceInMu.Unlock()

	seq++

	if seq+windowSize < f.lastNonceIn {
		return false
	}

	if seq > f.lastNonceIn {
		oldGroup := f.lastNonceIn / wordBits
		newGroup := seq / wordBits
		steps := min(newGroup-oldGroup, wordCount)

		for i := uint64(1); i <= steps; i++ {
			f.bitmap[(oldGroup+i)%wordCount] = 0
		}
		f.lastNonceIn = seq
	}

	word := (seq / wordBits) & (wordCount - 1)
	bit := seq % wordBits
	mask := uint64(1) << bit

	if f.bitmap[word]&mask != 0 {
		return false
	}

	f.bitmap[word] |= mask
	return true
}
