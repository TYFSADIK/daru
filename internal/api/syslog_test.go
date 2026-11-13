package api

import (
	"net"
	"strings"
	"testing"
)

func TestReadSyslogStream(t *testing.T) {
	client, server := net.Pipe()
	long := strings.Repeat("x", syslogMaxMessage+500)
	go func() {
		msg := "<13>1 - h a - - - octet framed"
		_, _ = client.Write([]byte("30 " + msg))
		_, _ = client.Write([]byte("<13>newline one\n<13>newline two\n"))
		_, _ = client.Write([]byte("<13>" + long + "\n<13>after long\n"))
		_ = client.Close()
	}()
	var got []string
	readSyslogStream(server, func(s string) { got = append(got, strings.TrimRight(s, "\n")) })
	want := []string{"<13>1 - h a - - - octet framed", "<13>newline one", "<13>newline two", "", "<13>after long"}
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d: %q", len(got), len(want), got)
	}
	for i, w := range want {
		if i == 3 {
			// The over-long line is cut to the buffer size, not dropped.
			if len(got[i]) != syslogMaxMessage || !strings.HasPrefix(got[i], "<13>xxx") {
				t.Errorf("long line: got %d bytes", len(got[i]))
			}
			continue
		}
		if got[i] != w {
			t.Errorf("message %d = %q, want %q", i, got[i], w)
		}
	}
}
