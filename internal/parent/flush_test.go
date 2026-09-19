package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

func TestFlushPersistsStreamBeforeClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: path, IsStream: true, StreamName: "metadata", streamBuf: []byte("committed"), streamWritten: true}
	if err := flushOpen(open); err != nil {
		t.Fatal(err)
	}
	got, err := readStreamXattr(path, "metadata")
	if err != nil || string(got) != "committed" {
		t.Fatalf("persisted = %q, %v", got, err)
	}
}

func TestFlushReportsSyncAndStreamErrors(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "closed"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, open := range []*Open{
		{File: f},
		{Path: filepath.Join(dir, "missing"), IsStream: true, StreamName: "metadata", streamBuf: []byte("uncommitted"), streamWritten: true},
	} {
		d, sess, _ := newTestDispatcher(t, dir)
		open.FileID = [16]byte{1}
		sess.AddOpen(open)
		body := make([]byte, 24)
		binary.LittleEndian.PutUint16(body, 24)
		copy(body[8:], open.FileID[:])
		var response bytes.Buffer
		d.handleFlush(&response, smb2.Header{Command: smb2.CommandFlush}, body, sess)
		if frameStatus(t, &response) == smb2.StatusSuccess {
			t.Fatal("FLUSH swallowed storage error")
		}
	}
}

func TestWriteThroughReportsSyncFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flag        uint32
		option      bool
		wantSuccess bool
	}{
		{"buffered", 0, false, true}, {"write flag", 1, false, false}, {"create option", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, sess, _ := newTestDispatcher(t, t.TempDir())
			// /dev/null accepts pwrite but cannot be synced, so this exercises a
			// successful write followed by a real sync error, without mocking storage.
			file, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			open := &Open{FileID: [16]byte{1}, File: file, WriteThrough: tc.option}
			sess.AddOpen(open)
			body := buildWriteBody(open.FileID, 0, []byte("backup"))
			binary.LittleEndian.PutUint32(body[44:], tc.flag)
			var response bytes.Buffer
			d.handleWrite(&response, smb2.Header{Command: smb2.CommandWrite}, body, sess)
			if got := frameStatus(t, &response); (got == smb2.StatusSuccess) != tc.wantSuccess {
				t.Fatalf("WRITE status = %v", got)
			}
		})
	}
}
