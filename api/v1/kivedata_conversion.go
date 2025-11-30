/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

package v1

import (
	v2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

// ConvertTo converts this KiveData (v1) to the Hub version (v2alpha1)
func (src *KiveData) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v2alpha1.KiveData)

	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()

	dst.Spec.InodeNo = src.Spec.InodeNo
	dst.Spec.DevID = src.Spec.DevID

	return nil
}

// ConvertFrom converts the Hub version (v2alpha1) to this KiveData (v1)
func (dst *KiveData) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v2alpha1.KiveData)

	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()

	dst.Spec.InodeNo = src.Spec.InodeNo
	dst.Spec.DevID = src.Spec.DevID

	return nil
}
