package allocrunner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/nomad/client/allocrunner/interfaces"
	"github.com/hashicorp/nomad/client/pluginmanager"
	"github.com/hashicorp/nomad/client/pluginmanager/csimanager"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/nomad/mock"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
)

var _ interfaces.RunnerPrerunHook = (*csiHook)(nil)
var _ interfaces.RunnerPostrunHook = (*csiHook)(nil)

// TODO: shouldn't we also implement Update?
// var _ interfaces.RunnerUpdateHook = (*csiHook)(nil)
// var _ interfaces.RunnerPreKillHook = (*csiHook)(nil)
// var _ interfaces.RunnerTaskRestartHook = (*csiHook)(nil)

func TestCSIHook(t *testing.T) {

	logger := testlog.HCLogger(t)

	alloc := mock.Alloc()
	alloc.Job.TaskGroups[0].Volumes = map[string]*structs.VolumeRequest{
		"vol0": {
			Name:           "vol0",
			Type:           structs.VolumeTypeCSI,
			Source:         "testvolume0",
			ReadOnly:       true,
			AccessMode:     structs.CSIVolumeAccessModeSingleNodeReader,
			AttachmentMode: structs.CSIVolumeAttachmentModeFilesystem,
			MountOptions:   &structs.CSIMountOptions{},
			PerAlloc:       false,
		},
		"vol1": {
			Name:           "vol1",
			Type:           structs.VolumeTypeCSI,
			Source:         "testvolume1",
			ReadOnly:       false,
			AccessMode:     structs.CSIVolumeAccessModeSingleNodeWriter,
			AttachmentMode: structs.CSIVolumeAttachmentModeFilesystem,
			MountOptions:   &structs.CSIMountOptions{},
			PerAlloc:       false,
		},
	}

	mgr := mockPluginManager{mounter: mockVolumeMounter{}}
	rpcer := mockRPCer{alloc: alloc}
	ar := mockAllocRunner{
		res: &cstructs.AllocHookResources{},
		caps: &drivers.Capabilities{
			FSIsolation:  drivers.FSIsolationChroot,
			MountConfigs: drivers.MountConfigSupportAll,
		},
	}
	hook := newCSIHook(alloc, logger, mgr, rpcer, ar, ar, "secret")
	require.NotNil(t, hook)

	require.NoError(t, hook.Prerun())
	mounts := ar.GetAllocHookResources().GetCSIMounts()
	require.NotNil(t, mounts)
	require.Len(t, mounts, 2)

	require.NoError(t, hook.Postrun())

	require.Equal(t, 2, rpcer.rpcCallsForClaim)
	require.Equal(t, 2, rpcer.rpcCallsForUnpublish)
	require.Equal(t, 2, mgr.mounter.callsForMountVolume)
	require.Equal(t, 2, mgr.mounter.callsForUnmountVolume)
}

// HELPERS AND MOCKS

func testVolume(id string) *structs.CSIVolume {
	vol := structs.NewCSIVolume(id, 0)
	vol.Schedulable = true
	vol.RequestedCapabilities = []*structs.CSIVolumeCapability{
		{
			AttachmentMode: structs.CSIVolumeAttachmentModeFilesystem,
			AccessMode:     structs.CSIVolumeAccessModeSingleNodeReader,
		},
		{
			AttachmentMode: structs.CSIVolumeAttachmentModeFilesystem,
			AccessMode:     structs.CSIVolumeAccessModeSingleNodeWriter,
		},
	}
	return vol
}

type mockRPCer struct {
	alloc                *structs.Allocation
	rpcCallsForClaim     int
	rpcCallsForUnpublish int
}

// RPC mocks the server RPCs, acting as though any request succeeds
func (rpc mockRPCer) RPC(method string, args interface{}, reply interface{}) error {
	switch method {
	case "CSIVolume.Claim":
		rpc.rpcCallsForClaim++
		req := args.(*structs.CSIVolumeClaimRequest)
		vol := testVolume(req.VolumeID)
		err := vol.Claim(req.ToClaim(), rpc.alloc)
		if err != nil {
			return err
		}

		resp := reply.(*structs.CSIVolumeClaimResponse)
		resp.PublishContext = map[string]string{}
		resp.Volume = vol
		resp.QueryMeta = structs.QueryMeta{}
	case "CSIVolume.Unpublish":
		rpc.rpcCallsForUnpublish++
		resp := reply.(*structs.CSIVolumeUnpublishResponse)
		resp.QueryMeta = structs.QueryMeta{}
	default:
		return fmt.Errorf("unexpected method")
	}
	return nil
}

type mockVolumeMounter struct {
	callsForMountVolume   int
	callsForUnmountVolume int
}

func (vm mockVolumeMounter) MountVolume(ctx context.Context, vol *structs.CSIVolume, alloc *structs.Allocation, usageOpts *csimanager.UsageOptions, publishContext map[string]string) (*csimanager.MountInfo, error) {
	vm.callsForMountVolume++
	return nil, nil
}
func (vm mockVolumeMounter) UnmountVolume(ctx context.Context, volID, remoteID, allocID string, usageOpts *csimanager.UsageOptions) error {
	vm.callsForUnmountVolume++
	return nil
}

type mockPluginManager struct {
	mounter mockVolumeMounter
}

func (mgr mockPluginManager) MounterForPlugin(ctx context.Context, pluginID string) (csimanager.VolumeMounter, error) {
	return mgr.mounter, nil
}

// no-op methods to fulfill the interface
func (mgr mockPluginManager) PluginManager() pluginmanager.PluginManager { return nil }
func (mgr mockPluginManager) Shutdown()                                  {}

type mockAllocRunner struct {
	res  *cstructs.AllocHookResources
	caps *drivers.Capabilities
}

func (ar mockAllocRunner) GetAllocHookResources() *cstructs.AllocHookResources {
	return ar.res
}

func (ar mockAllocRunner) SetAllocHookResources(res *cstructs.AllocHookResources) {
	ar.res = res
}

func (ar mockAllocRunner) GetTaskDriverCapabilities(taskName string) (*drivers.Capabilities, error) {
	return ar.caps, nil
}
