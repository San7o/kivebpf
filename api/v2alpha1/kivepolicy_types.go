/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

// +kubebuilder:conversion-gen=true
// +groupName=kivebpf.san7o.github.io
package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KivePolicySpec struct {
	// Version for KiveAlert output
	AlertVersion string `json:"alertVersion,omitempty"`
	// List of traps
	Traps []KiveTrap `json:"traps,omitempty"`
}

// THE FOLLOWING LINES ARE COMMENTED OUT ON PURPOSE.
// This would create the base manifests for MutatingWebhookConfiguration and
// ValidatingWebhookConfiguration, but we do create them dynamically with an init
// container (and correct CA bundles) so we don't want kubebuilder to generate them. If
// you would like to know what the webhooks looked like, e.g., if you need to change the
// template used by the init container, you can briefly uncomment them, generate the
// manifests, and then comment them out again.
//
// // +kubebuilder:webhook:path=/mutate-kive-kivepolicy,mutating=true,failurePolicy=fail,groups=kivebpf.san7o.github.io,resources=kivepolicies,verbs=create;update,versions=v1;v2alpha1,name=mutate.kivepolicy.kivebpf.san7o.github.io,admissionReviewVersions=v1,sideEffects=none
// // +kubebuilder:webhook:path=/validate-kive-kivepolicy,mutating=false,failurePolicy=fail,groups=kivebpf.san7o.github.io,resources=kivepolivies,verbs=create;update,versions=v1;v2alpha1,name=validate.kivepolicy.kivebpf.san7o.github.io,sideEffects=None,admissionReviewVersions=v1

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type KivePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KivePolicySpec `json:"spec,omitempty"`
}

func (*KivePolicy) Hub() {}

// +kubebuilder:object:root=true

type KivePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KivePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KivePolicy{}, &KivePolicyList{})
}
