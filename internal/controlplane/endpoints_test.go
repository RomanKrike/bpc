package controlplane

import (
	"bytes"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestNodeEndpointsReplicateThroughRaft(t *testing.T) {
	nodes := []*testRaftNode{newTestRaftNode(t, "ru-01"), newTestRaftNode(t, "ru-02")}
	defer func() {
		for _, n := range nodes {
			_ = n.raft.Shutdown().Error()
			_ = n.store.Close()
		}
	}()
	connectTestCluster(nodes)
	if err := nodes[0].raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
		{ID: "ru-01", Address: "ru-01", Suffrage: raft.Voter},
		{ID: "ru-02", Address: "ru-02", Suffrage: raft.Voter},
	}}).Error(); err != nil {
		t.Fatal(err)
	}
	leader := waitLeader(t, nodes, 3*time.Second)
	records := map[string][]byte{
		"control/nodes/ru-01.json":   []byte(`{"name":"ru-01","endpoints":[{"host":"ru-01.blinpi.ru","public":true,"enabled":true}]}`),
		"control/nodes/ru-02.json":   []byte(`{"name":"ru-02","endpoints":[{"host":"ru-02.blinpi.ru","public":true,"enabled":true},{"host":"ru-02.internal","public":false,"enabled":false}]}`),
		"control/nodes/home-01.json": []byte(`{"name":"home-01","endpoints":[]}`),
	}
	for path, data := range records {
		applyMutation(t, leader, Mutation{Version: CommandVersion, ID: path, Kind: "EnrollNode", IssuedAt: 1,
			Operations: []Operation{{Op: "put", Path: path, Data: data, IfAbsent: true}}})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, n := range nodes {
			for path, want := range records {
				got, ok, err := n.store.canonicalGet(path)
				if err != nil || !ok || !bytes.Equal(got, want) {
					ready = false
				}
			}
		}
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Node endpoints did not replicate on both Controllers")
}
