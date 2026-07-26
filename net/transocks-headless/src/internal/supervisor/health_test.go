package supervisor

import "testing"

func TestHealthHysteresis(t *testing.T) {
	h := newHealthTracker(500, 3)
	if degraded, _ := h.Observe("a", 100, true); degraded {
		t.Fatal("healthy observation degraded")
	}
	for i := 0; i < 2; i++ {
		if degraded, _ := h.Observe("a", 900, true); degraded {
			t.Fatal("degraded too early")
		}
	}
	if degraded, _ := h.Observe("a", 900, true); !degraded {
		t.Fatal("expected degradation")
	}
	if _, switched := h.Observe("b", 100, true); !switched || h.switches != 1 {
		t.Fatal("expected switch detection")
	}
}
