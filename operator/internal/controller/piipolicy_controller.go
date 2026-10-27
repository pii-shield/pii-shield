/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/policyfile"
)

// PiiPolicyReconciler reconciles a PiiPolicy object
type PiiPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile validates a PiiPolicy enough to expose an auditable status without
// mutating the user's desired spec, and renders its rules into a ConfigMap
// (policyfile) that the webhook mounts into every sidecar injected for the
// policy. The sidecar reloads the file when it changes, so an edit to the
// policy reaches running pods without a restart.
func (r *PiiPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &corev1alpha1.PiiPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	effectiveMode := policy.Spec.InjectionMode
	if effectiveMode == "" {
		effectiveMode = "file"
	}

	condition := metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "PolicyAccepted",
		Message:            fmt.Sprintf("Policy is accepted. Effective injection mode: %s", effectiveMode),
		ObservedGeneration: policy.Generation,
	}

	switch effectiveMode {
	case "file", "pipe", "ebpf":
	default:
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidInjectionMode"
		condition.Message = fmt.Sprintf("Unsupported injection mode: %s", effectiveMode)
	}

	oldStatus := *policy.Status.DeepCopy()
	meta.SetStatusCondition(&policy.Status.Conditions, condition)

	rendered := metav1.Condition{
		Type:               "Rendered",
		Status:             metav1.ConditionTrue,
		Reason:             "ConfigMapUpToDate",
		ObservedGeneration: policy.Generation,
	}
	name, hash, err := r.renderConfigMap(ctx, policy)
	if err != nil {
		// The policy is still served through the sidecar env vars at
		// injection time; only the live reload path is missing, so the
		// condition says so and the reconcile is retried.
		log.Error(err, "failed to render the policy ConfigMap")
		rendered.Status = metav1.ConditionFalse
		rendered.Reason = "RenderFailed"
		rendered.Message = err.Error()
	} else {
		rendered.Message = fmt.Sprintf("Rules rendered into ConfigMap %s (hash %s)", name, hash)
		policy.Status.RenderedPolicyConfigMap = name
		policy.Status.RenderedPolicyHash = hash
	}
	meta.SetStatusCondition(&policy.Status.Conditions, rendered)

	if !reflect.DeepEqual(oldStatus, policy.Status) {
		if updateErr := r.Status().Update(ctx, policy); updateErr != nil {
			log.Error(updateErr, "failed to update PiiPolicy status")
			return ctrl.Result{}, updateErr
		}
	}

	return ctrl.Result{}, err
}

// renderConfigMap writes the policy's rules file into the ConfigMap named by
// policyfile.ConfigMapName, owned by the policy so it is garbage-collected
// with it, and returns the ConfigMap's name and the file's content hash. An
// unchanged file is left alone, so the kubelet sees no update and the
// sidecar does not reload.
func (r *PiiPolicyReconciler) renderConfigMap(ctx context.Context, policy *corev1alpha1.PiiPolicy) (string, string, error) {
	data, err := policyfile.Render(policy)
	if err != nil {
		return "", "", err
	}
	hash := policyfile.Hash(data)

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:      policyfile.ConfigMapName(policy.Name),
		Namespace: policy.Namespace,
	}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		if cm.Labels == nil {
			cm.Labels = map[string]string{}
		}
		cm.Labels["app.kubernetes.io/managed-by"] = "pii-shield-operator"
		cm.Labels[policyfile.LabelPolicy] = policy.Name
		if cm.Annotations == nil {
			cm.Annotations = map[string]string{}
		}
		cm.Annotations[policyfile.AnnotationHash] = hash
		cm.Data = map[string]string{policyfile.Key: string(data)}
		return controllerutil.SetControllerReference(policy, cm, r.Scheme)
	})
	if err != nil {
		return "", "", fmt.Errorf("ConfigMap %s: %w", cm.Name, err)
	}
	return cm.Name, hash, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PiiPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.PiiPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Named("piipolicy").
		Complete(r)
}
