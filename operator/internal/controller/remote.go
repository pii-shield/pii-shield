package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/policyfile"
	"github.com/pii-shield/pii-shield/operator/internal/remoterules"
)

// Condition reasons of RemoteSynced that are not fetch or validation reasons.
const (
	conditionRemoteSynced = "RemoteSynced"
	reasonSynced          = "Synced"
	reasonSecretNotFound  = "SecretNotFound"
)

// remoteOutcome is what one pull leaves for the reconcile: the remote
// document to merge (the new one, or the last good copy on failure), the raw
// file and ETag to keep in the ConfigMap, the condition to report and how
// long to wait before the next pull.
type remoteOutcome struct {
	doc       policyfile.Document
	haveDoc   bool
	raw       []byte
	etag      string
	condition metav1.Condition
	status    *corev1alpha1.RemoteStatus
	requeue   time.Duration
}

// syncRemote pulls spec.remoteConfig once. lastGood is the previous
// ConfigMap, which keeps the last accepted remote file and its ETag: on a
// 304 or on any failure that copy is used again, so the rules a sidecar
// runs never go backwards because the source is down, and a local edit of
// the policy still applies on top of them. An operator restart loses
// nothing, because the copy lives in the ConfigMap and not in memory.
func (r *PiiPolicyReconciler) syncRemote(ctx context.Context, policy *corev1alpha1.PiiPolicy, lastGood *corev1.ConfigMap) remoteOutcome {
	rc := policy.Spec.RemoteConfig
	now := metav1.Now()
	out := remoteOutcome{
		requeue: remoterules.Retry(rc.IntervalSeconds),
		status:  policy.Status.Remote.DeepCopy(),
		condition: metav1.Condition{
			Type:               conditionRemoteSynced,
			ObservedGeneration: policy.Generation,
		},
	}
	remoteSyncInterval.WithLabelValues(policy.Namespace, policy.Name).Set(remoterules.Interval(rc.IntervalSeconds).Seconds())

	// The last good copy, if the ConfigMap has one.
	var prevRaw []byte
	var prevETag string
	if lastGood != nil {
		if s, ok := lastGood.Data[policyfile.RemoteKey]; ok && s != "" {
			if doc, _, err := policyfile.Parse([]byte(s)); err == nil {
				prevRaw = []byte(s)
				prevETag = lastGood.Annotations[policyfile.AnnotationRemoteETag]
				out.doc, out.haveDoc, out.raw, out.etag = doc, true, prevRaw, prevETag
			}
		}
	}

	fail := func(reason string, err error) remoteOutcome {
		remoteSyncTotal.WithLabelValues("error").Inc()
		out.condition.Status = metav1.ConditionFalse
		out.condition.Reason = reason
		msg := err.Error()
		if out.haveDoc {
			msg += "; keeping the last good remote rules"
		} else {
			msg += "; no remote rules received yet, the local policy alone is rendered"
		}
		out.condition.Message = msg
		return out
	}

	src := remoterules.Source{URL: rc.URL, AllowInsecure: rc.AllowInsecure, ETag: prevETag}
	if rc.HeaderSecretRef != nil {
		v, err := r.secretValue(ctx, policy.Namespace, rc.HeaderSecretRef)
		if err != nil {
			return fail(reasonSecretNotFound, fmt.Errorf("headerSecretRef: %w", err))
		}
		src.Authorization = strings.TrimSpace(string(v))
	}
	if rc.CABundleSecretRef != nil {
		v, err := r.secretValue(ctx, policy.Namespace, rc.CABundleSecretRef)
		if err != nil {
			return fail(reasonSecretNotFound, fmt.Errorf("caBundleSecretRef: %w", err))
		}
		src.CABundle = v
	}

	res, err := remoterules.Fetch(ctx, src)
	if err != nil {
		var fe *remoterules.Error
		if errors.As(err, &fe) {
			return fail(fe.Reason, err)
		}
		return fail(remoterules.ReasonFetchFailed, err)
	}

	var ignored []string
	if res.NotModified {
		remoteSyncTotal.WithLabelValues("not_modified").Inc()
	} else {
		doc, ign, perr := policyfile.Parse(res.Body)
		if perr != nil {
			var ve *policyfile.ValidationError
			if errors.As(perr, &ve) {
				return fail(ve.Reason, perr)
			}
			return fail(policyfile.ReasonInvalidJSON, perr)
		}
		remoteSyncTotal.WithLabelValues("updated").Inc()
		ignored = ign
		out.doc, out.haveDoc, out.raw, out.etag = doc, true, res.Body, res.ETag
	}

	remoteSyncLastSuccess.WithLabelValues(policy.Namespace, policy.Name).Set(float64(now.Unix()))
	out.requeue = remoterules.Interval(rc.IntervalSeconds)
	out.status = &corev1alpha1.RemoteStatus{
		LastSyncTime: &now,
		ETag:         out.etag,
		Revision:     out.doc.Revision,
		Hash:         policyfile.Hash(out.raw),
	}
	out.condition.Status = metav1.ConditionTrue
	out.condition.Reason = reasonSynced
	var msg strings.Builder
	if res.NotModified {
		fmt.Fprintf(&msg, "Remote rules unchanged (304), revision %q", out.doc.Revision)
	} else {
		fmt.Fprintf(&msg, "Remote rules pulled, revision %q, hash %s", out.doc.Revision, out.status.Hash)
	}
	if len(ignored) > 0 {
		fmt.Fprintf(&msg, "; ignored keys in the remote file: %s", strings.Join(ignored, ", "))
	}
	if rc.AllowInsecure {
		msg.WriteString("; WARNING: allowInsecure is set, the transport is not verified")
	}
	out.condition.Message = msg.String()
	return out
}

// secretValue reads one key of a Secret in the policy's namespace through
// the API reader, so the manager needs no list/watch on Secrets and keeps no
// Secret in its cache.
func (r *PiiPolicyReconciler) secretValue(ctx context.Context, namespace string, ref *corev1.SecretKeySelector) ([]byte, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found", namespace, ref.Name)
		}
		return nil, fmt.Errorf("secret %s/%s: %w", namespace, ref.Name, err)
	}
	v, ok := secret.Data[ref.Key]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return v, nil
}

// previousConfigMap returns the policy's ConfigMap as it is, or nil.
func (r *PiiPolicyReconciler) previousConfigMap(ctx context.Context, policy *corev1alpha1.PiiPolicy) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: policy.Namespace, Name: policyfile.ConfigMapName(policy.Name)}
	if err := r.Get(ctx, key, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return cm, nil
}
