package common

type CleanupStack struct {
	fns []func()
}

func (s *CleanupStack) Push(fn func()) {
	s.fns = append(s.fns, fn)
}

func (s *CleanupStack) Run() {
	for i := len(s.fns) - 1; i >= 0; i-- {
		s.fns[i]()
	}
}

func (s *CleanupStack) Clear() {
	s.fns = nil
}
