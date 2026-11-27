package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeSyncer struct{ calls int }

func (f *fakeSyncer) SyncGroup(ctx context.Context, members []string) error {
	f.calls++
	return nil
}

func TestCoordinatorMergesAccounts(t *testing.T) {
	c := &blocklistCoordinator{}
	c.Publish("a", []string{"1.1.1.1", "2.2.2.2"})
	c.Publish("b", []string{"2.2.2.2", "3.3.3.3"})
	require.Equal(t, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, c.snapshot())
}

func TestCoordinatorUsesPublishOrder(t *testing.T) {
	c := &blocklistCoordinator{}
	c.Publish("z", []string{"9.9.9.9"})
	c.Publish("a", []string{"1.1.1.1"})
	require.Equal(t, []string{"9.9.9.9", "1.1.1.1"}, c.snapshot())
}

func TestCoordinatorUsesConfiguredAccountOrder(t *testing.T) {
	c := &blocklistCoordinator{expected: []string{"z", "a"}, order: []string{"z", "a"}}
	c.Publish("a", []string{"1.1.1.1"})
	c.Publish("z", []string{"9.9.9.9"})
	require.Equal(t, []string{"9.9.9.9", "1.1.1.1"}, c.snapshot())
}

func TestCoordinatorRequiresAllAccountsBeforeFirstSync(t *testing.T) {
	fake := &fakeSyncer{}
	c := &blocklistCoordinator{client: fake, expected: []string{"a", "b"}}
	c.Publish("a", []string{"1.1.1.1"})
	require.NoError(t, c.Sync(context.Background()))
	require.Zero(t, fake.calls)

	c.Publish("b", []string{"2.2.2.2"})
	require.NoError(t, c.Sync(context.Background()))
	require.Equal(t, 1, fake.calls)
}

func TestCoordinatorSkipsSyncBeforeFirstPublish(t *testing.T) {
	fake := &fakeSyncer{}
	c := &blocklistCoordinator{client: fake}
	require.NoError(t, c.Sync(context.Background()))
	require.Equal(t, 0, fake.calls, "must not clear the UniFi group before IPs are known")

	c.Publish("a", nil)
	require.NoError(t, c.Sync(context.Background()))
	require.Equal(t, 1, fake.calls, "an empty published list is a valid deliberate clear")
}
