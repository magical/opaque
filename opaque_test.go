package opaque
import "testing"
import "fmt"
func TestExpandMessageXmd(t *testing.T) {
msg     := []byte("abc")
DST     := "QUUX-V01-CS02-with-expander-SHA256-128"
expected := "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
out := expand_message_xmd(msg, DST, 0x20)
actual := fmt.Sprintf("%x", out)
if expected != actual {
	t.Errorf("want %q got %q", expected, actual)
}
}
