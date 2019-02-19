package nassh

import (
	"bytes"
	"testing"
)

type testOp func(t *testing.T, buf *buffer)

func testWrite(p []byte, pos int) testOp {
	return func(t *testing.T, buf *buffer) {
		n, gotPos, err := buf.Write(p)
		if err != nil {
			t.Fatal(err)
		} else if len(p) != n {
			t.Fatalf("expected n=%d, but was %d", len(p), n)
		} else if pos != gotPos {
			t.Fatalf("expected pos=%d, but was %d", pos, gotPos)
		}
	}
}

func testRead(start int, psize int, expected []byte, pos int) testOp {
	return func(t *testing.T, buf *buffer) {
		p := make([]byte, psize)
		n, gotPos, err := buf.Read(start, p)
		if err != nil {
			t.Fatal(err)
		} else if len(expected) != n {
			t.Fatalf("expected n=%d, but was %d", len(expected), n)
		} else if !bytes.Equal(expected, p[:n]) {
			t.Fatalf("expected to read %q, but was %q", expected, p)
		} else if pos != gotPos {
			t.Fatalf("expected pos=%d, but was %d", pos, gotPos)
		}
	}
}

func testDiscard(start int) testOp {
	return func(t *testing.T, buf *buffer) {
		err := buf.DiscardBefore(start)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuffer(t *testing.T) {
	cases := []struct {
		name   string
		size   int
		maxPos int
		ops    []testOp
	}{
		{
			name:   "empty",
			size:   16,
			maxPos: 64,
			ops: []testOp{
				testRead(0, 16, []byte{}, 0),
			},
		},
		{
			name:   "write, then read",
			size:   16,
			maxPos: 64,
			ops: []testOp{
				testWrite([]byte("hello"), 5),
				testRead(0, 16, []byte("hello"), 5),
				testRead(2, 16, []byte("llo"), 5),
				testRead(2, 2, []byte("ll"), 4),
			},
		},
		{
			name:   "multiple writes",
			size:   16,
			maxPos: 64,
			ops: []testOp{
				testWrite([]byte("hello"), 5),
				testWrite([]byte(" "), 6),
				testWrite([]byte("world"), 11),
				testRead(0, 16, []byte("hello world"), 11),
				testRead(6, 16, []byte("world"), 11),
			},
		},
		{
			name:   "write causing wraparound",
			size:   16,
			maxPos: 64,
			ops: []testOp{
				testWrite([]byte("the quick brown"), 15),
				testDiscard(10),
				testRead(10, 16, []byte("brown"), 15),
				testWrite([]byte(" fox jumped"), 26),
				testRead(10, 16, []byte("brown fox jumped"), 26),
			},
		},
		{
			name:   "write causing pos wraparound",
			size:   16,
			maxPos: 32,
			ops: []testOp{
				testWrite([]byte("the quick brown "), 16),
				testDiscard(16),
				testRead(16, 16, []byte(""), 16),
				testWrite([]byte("fox jumped over "), 0),
				testRead(16, 16, []byte("fox jumped over "), 0),
				testDiscard(0),
				testRead(0, 16, []byte(""), 0),
				testWrite([]byte("the lazy dog"), 12),
				testRead(0, 16, []byte("the lazy dog"), 12),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			buf := newBuffer(tc.size, tc.maxPos)
			for i, op := range tc.ops {
				t.Logf("op #%d", i+1)
				op(t, buf)
			}
		})
	}
}

func TestBuffer_PosOutOfBounds(t *testing.T) {
	buf := newBuffer(16, 64)

	// write 11 bytes
	if _, _, err := buf.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}

	// attempt to read from pos 12, not valid
	p := make([]byte, 16)
	if _, _, err := buf.Read(12, p); err != errPosOutOfBounds {
		t.Fatalf("expected err=%#v, got %#v", errPosOutOfBounds, err)
	}

	// discard 6 bytes, leaving 5 valid
	if err := buf.DiscardBefore(6); err != nil {
		t.Fatal(err)
	}

	// invalid read, only pos [6,11] is valid
	if _, _, err := buf.Read(0, p); err != errPosOutOfBounds {
		t.Fatalf("expected err=%#v, got %#v", errPosOutOfBounds, err)
	}

	// attempt to discard from pos 12, not valid
	if err := buf.DiscardBefore(12); err != errPosOutOfBounds {
		t.Fatalf("expected err=%#v, got %#v", errPosOutOfBounds, err)
	}

	// valid read
	n, _, err := buf.Read(6, p)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal([]byte("world"), p[:n]) {
		t.Fatalf("expected to read %q, got %q", []byte("hello"), p[:n])
	}
}

func TestBuffer_BufferOverflow(t *testing.T) {
	buf := newBuffer(16, 64)
	if _, _, err := buf.Write([]byte("the quick brown")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buf.Write([]byte("fox jumped")); err != errBufferOverflow {
		t.Fatalf("expected err=%#v, got %#v", errBufferOverflow, err)
	}
}

func TestBuffer_BufferOverflowAfterWraparound(t *testing.T) {
	buf := newBuffer(16, 64)

	// write 15 bytes
	if _, _, err := buf.Write([]byte("the quick brown")); err != nil {
		t.Fatal(err)
	}

	// discard all 15 bytes
	if err := buf.DiscardBefore(15); err != nil {
		t.Fatal(err)
	}

	// write 3 more bytes, buffer will have wrapped around beyond 16
	if _, _, err := buf.Write([]byte("fox")); err != nil {
		t.Fatal(err)
	}

	// attempt to write 15 more bytes, causing a buffer overflow
	if _, _, err := buf.Write([]byte("jumped over the")); err != errBufferOverflow {
		t.Fatalf("expected err=%#v, got %#v", errBufferOverflow, err)
	}
}
