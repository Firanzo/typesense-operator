package controller

import (
	"context"
	"fmt"

	tsv1alpha1 "github.com/akyriako/typesense-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/util/version"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *TypesenseClusterReconciler) patchStatus(
	ctx context.Context,
	ts *tsv1alpha1.TypesenseCluster,
	patcher func(status *tsv1alpha1.TypesenseClusterStatus),
) error {
	patch := client.MergeFrom(ts.DeepCopy())
	patcher(&ts.Status)

	// Keep ObservedGeneration in sync with the current metadata.generation
	ts.Status.ObservedGeneration = ts.Generation

	err := r.Status().Patch(ctx, ts, patch)
	if err != nil {
		r.logger.Error(err, "unable to patch typesense cluster status")
		return err
	}

	return nil
}

func (r *TypesenseClusterReconciler) IsFeatureSupported(minimum string) (bool, string, error) {
	if r.serverVersion == "" {
		info, err := r.DiscoveryClient.ServerVersion()
		if err != nil {
			return false, "", err
		}
		r.serverVersion = info.GitVersion
	}

	ver, err := version.ParseGeneric(r.serverVersion)
	if err != nil {
		return false, r.serverVersion, err
	}

	req, err := version.ParseGeneric(fmt.Sprintf("v%s", minimum))
	if err != nil {
		return false, r.serverVersion, err
	}

	return ver.AtLeast(req), r.serverVersion, nil
}

func (r *TypesenseClusterReconciler) IsApiGroupDeployed(apiGroup string) (bool, error) {
	apiGroupList, err := r.DiscoveryClient.ServerGroups()
	if err != nil {
		return false, err
	}

	for _, ag := range apiGroupList.Groups {
		if ag.Name == apiGroup {
			return true, nil
		}
	}

	return false, nil
}
