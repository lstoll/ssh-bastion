package nassh

import (
	"errors"
)

var errBufferOverflow = errors.New("buffer overflow")
var errPosOutOfBounds = errors.New("pos out of bounds")

// buffer implements a circular buffer of fixed size that also supports
// tracking wrappable positions in the buffer. These positions can be used
// to implement an acknowledgement system where data can replayed if
// needed, or discarded after acknowledgement.
type buffer struct {
	// buf is the underlying buffer. It is allocated only once, in newBuffer,
	// and reused as a circular buffer.
	buf []byte

	// headPos is the position of the head index in buf. headPos is increased
	// when data is discarded via DiscardBefore and wrapped when it reaches
	// maxPos.
	headPos int
	// headIdx the head index in buf. headIdx is wrapped when it reaches
	// size, forming a circular buffer.
	headIdx int

	// tailPos is the position of the tail index in buf. tailPos is increased
	// when data is written via Write and wrapped when it reaches
	// maxPos.
	tailPos int
	// tailIdx the tail index in buf. tailIdx is wrapped when it reaches
	// size, forming a circular buffer.
	tailIdx int

	// size is the size of the circular buffer.
	size int
	// maxPos is the maximum position for headPos and tailPos before wrapping
	// around to zero.
	maxPos int
}

// newBuffer creates a new buffer of the specified size with the specified
// maxPos
func newBuffer(size int, maxPos int) *buffer {
	return &buffer{
		buf:    make([]byte, size),
		size:   size,
		maxPos: maxPos,
	}
}

// Write writes p to the buffer, returning the number of bytes written and
// the new position of the tail index.
//
// Write always succeeds unless writing p to the buffer would cause it to
// overflow. In that case, errBufferOverflow is returned.
func (b *buffer) Write(p []byte) (n int, pos int, err error) {
	n = len(p)
	if n+b.posDiff(b.headPos, b.tailPos) > b.size {
		return 0, 0, errBufferOverflow
	}

	nIdx := b.tailIdx + n
	if nIdx <= b.size {
		copy(b.buf[b.tailIdx:], p)
	} else {
		remaining := b.size - b.tailIdx
		copy(b.buf[b.tailIdx:], p)
		copy(b.buf, p[remaining:n])
	}

	b.tailPos = b.wrapPos(b.tailPos + n)
	b.tailIdx = b.wrapIdx(nIdx)

	return n, b.tailPos, nil
}

// Read reads len(p) bytes starting at the specified start position. If the
// start position is not valid, errPosOutOfBounds is returned.
func (b *buffer) Read(start int, p []byte) (n int, pos int, err error) {
	if !b.inBounds(start) {
		return 0, 0, errPosOutOfBounds
	}

	n = len(p)
	pd := b.posDiff(start, b.tailPos)
	if n > pd {
		n = pd
	}

	startIdx := b.headIdx + b.posDiff(b.headPos, start)
	nIdx := startIdx + n
	if nIdx <= b.size {
		copy(p, b.buf[startIdx:nIdx])
	} else {
		remaining := b.size - startIdx
		copy(p, b.buf[startIdx:])
		copy(p[remaining:n], b.buf)
	}

	return n, b.wrapPos(start + n), nil
}

// DiscardBefore discards data before the specified start position. This
// operation increases the capacity of the buffer to accept new data at the
// tail end.
func (b *buffer) DiscardBefore(start int) error {
	if !b.inBounds(start) {
		return errPosOutOfBounds
	}

	delta := b.posDiff(b.headPos, start)

	b.headPos = start
	b.headIdx = b.wrapIdx(b.headIdx + delta)

	return nil
}

// wrapIdx wraps the given index around size.
func (b *buffer) wrapIdx(idx int) int {
	for idx >= b.size {
		idx -= b.size
	}
	return idx
}

// wrapPos wraps the given index around maxPos.
func (b *buffer) wrapPos(pos int) int {
	for pos >= b.maxPos {
		pos -= b.maxPos
	}
	return pos
}

// posDiff subtraces p1 from p2 (p2-p1), considering wraparound if present.
func (b *buffer) posDiff(p1, p2 int) int {
	diff := p2 - p1
	if diff < 0 {
		diff += b.maxPos
	}
	return diff
}

// inBounds returns true if the position is a valid position in the buffer;
// otherwise, false.
func (b *buffer) inBounds(pos int) bool {
	if b.tailPos > b.headPos {
		return pos >= b.headPos && pos <= b.tailPos
	} else {
		return pos >= b.headPos || pos <= b.tailPos
	}
}
