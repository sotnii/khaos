package runtime

import "github.com/sotnii/pakostii/containers"

type clusterStateView interface {
	FindContainer(nodeID, containerName string) *containers.RunningContainer
}
