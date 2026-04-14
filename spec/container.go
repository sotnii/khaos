package spec

import "time"

type ContainerSpec struct {
	Name           string
	ImageRef       string
	Env            map[string]string
	StartDelay     time.Duration
	Files          map[string]string
	ReadinessProbe Probe
}

func NewContainer(name, imageRef string) ContainerSpec {
	return ContainerSpec{
		Name:     name,
		ImageRef: imageRef,
		Env:      map[string]string{},
		Files:    map[string]string{},
	}
}

func (s ContainerSpec) WithEnv(key, value string) ContainerSpec {
	s.Env[key] = value
	return s
}

func (s ContainerSpec) WithFile(path, content string) ContainerSpec {
	s.Files[path] = content
	return s
}

func (s ContainerSpec) WithStartDelay(delay time.Duration) ContainerSpec {
	s.StartDelay = delay
	return s
}

func (s ContainerSpec) WithReadiness(probe Probe) ContainerSpec {
	s.ReadinessProbe = probe
	return s
}
