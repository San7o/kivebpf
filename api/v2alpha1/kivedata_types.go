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

// KiveDataSpec defines the desired state of KiveData
type KiveDataSpec struct {
	// The inode number of the file
	InodeNo uint64 `json:"inode-no,omitempty"`
	// The device number of the inode
	DevID uint32 `json:"dev-id,omitempty"`
	// (optional) Additional information
	Metadata map[string]string `json:"metadata,omitempty"`
}

// THE FOLLOWING LINES ARE COMMENTED OUT ON PURPOSE.
// This would create the base manifests for MutatingWebhookConfiguration and
// ValidatingWebhookConfiguration, but we do create them dynamically with an init
// container (and correct CA bundles) so we don't want kubebuilder to generate them. If
// you would like to know what the webhooks looked like, e.g., if you need to change the
// template used by the init container, you can briefly uncomment them, generate the
// manifests, and then comment them out again.
//
// // +kubebuilder:webhook:path=/mutate-kive-kivedata,mutating=true,failurePolicy=fail,groups=kivebpf.san7o.github.io,resources=kivedata,verbs=create;update,versions=v1;v2alpha1,name=mutate.kivedata.kivebpf.san7o.github.io,admissionReviewVersions=v1,sideEffects=none
// // +kubebuilder:webhook:path=/validate-kive-kivedata,mutating=false,failurePolicy=fail,groups=kivebpf.san7o.github.io,resources=kivedata,verbs=create;update,versions=v1;v2alpha1,name=validate.kivedata.kivebpf.san7o.github.io,sideEffects=None,admissionReviewVersions=v1

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type KiveData struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KiveDataSpec `json:"spec,omitempty"`
}

func (*KiveData) Hub() {}

// +kubebuilder:object:root=true

type KiveDataList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KiveData `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KiveData{}, &KiveDataList{})
}
