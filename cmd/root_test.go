package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoordinatorMergesAccounts(t *testing.T) {
	c := &blocklistCoordinator{}
	c.Publish("a", []string{"1.1.1.1", "2.2.2.2"})
	c.Publish("b", []string{"2.2.2.2", "3.3.3.3"})
	require.Equal(t, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, c.snapshot())
}
