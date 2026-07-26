package supervisor

type healthTracker struct {
	threshold int
	rounds    int
	bad       int
	selected  string
	switches  int
}

func newHealthTracker(threshold, rounds int) *healthTracker {
	return &healthTracker{threshold: threshold, rounds: rounds}
}

func (h *healthTracker) Observe(selected string, delay int, ok bool) (degraded bool, switched bool) {
	if selected != "" && h.selected != "" && selected != h.selected {
		h.switches++
		switched = true
	}
	if selected != "" {
		h.selected = selected
	}
	if !ok || delay <= 0 || delay > h.threshold {
		h.bad++
	} else {
		h.bad = 0
	}
	if h.bad >= h.rounds {
		h.bad = 0
		return true, switched
	}
	return false, switched
}
