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
	"maps"

	v2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

// ConvertTo converts this KivePolicy (v1) to the Hub version (v2alpha1)
func (src *KivePolicy) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v2alpha1.KivePolicy)

	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec.AlertVersion = src.Spec.AlertVersion

	traps_v2 := []v2alpha1.KiveTrap{}
	for _, trap_v1 := range src.Spec.Traps {
		trap_v2 := v2alpha1.KiveTrap{}
		trap_v2.Path = trap_v1.Path
		trap_v2.Create = trap_v1.Create
		trap_v2.Mode = trap_v1.Mode
		trap_v2.Callback = trap_v1.Callback

		trap_v2.Metadata = map[string]string{}
		maps.Copy(trap_v2.Metadata, trap_v1.Metadata)

		matchany_v2 := []v2alpha1.KiveTrapMatch{}
		for _, match_v1 := range trap_v1.MatchAny {
			match_v2 := v2alpha1.KiveTrapMatch{}
			match_v2.PodName = match_v1.PodName
			match_v2.ContainerName = match_v1.ContainerName
			match_v2.Namespace = match_v1.Namespace
			match_v2.IP = match_v1.IP
			match_v2.MatchLabels = map[string]string{}
			maps.Copy(match_v2.MatchLabels, match_v1.MatchLabels)

			matchany_v2 = append(matchany_v2, match_v2)
		}

		trap_v2.MatchAny = matchany_v2
		traps_v2 = append(traps_v2, trap_v2)
	}

	dst.Spec.Traps = traps_v2
	return nil
}

// ConvertFrom converts the Hub version (v2alpha1) to this KivePolicy (v1)
func (dst *KivePolicy) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v2alpha1.KivePolicy)

	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec.AlertVersion = src.Spec.AlertVersion

	traps_v1 := []KiveTrap{}
	for _, trap_v2 := range src.Spec.Traps {
		trap_v1 := KiveTrap{}
		trap_v1.Path = trap_v2.Path
		trap_v1.Create = trap_v2.Create
		trap_v1.Mode = trap_v2.Mode
		trap_v1.Callback = trap_v2.Callback

		trap_v1.Metadata = map[string]string{}
		maps.Copy(trap_v1.Metadata, trap_v2.Metadata)

		matchany_v1 := []KiveTrapMatch{}
		for _, match_v2 := range trap_v2.MatchAny {
			match_v1 := KiveTrapMatch{}
			match_v1.PodName = match_v2.PodName
			match_v1.ContainerName = match_v2.ContainerName
			match_v1.Namespace = match_v2.Namespace
			match_v1.IP = match_v2.IP
			match_v1.MatchLabels = map[string]string{}
			maps.Copy(match_v1.MatchLabels, match_v2.MatchLabels)

			matchany_v1 = append(matchany_v1, match_v1)
		}

		trap_v1.MatchAny = matchany_v1
		traps_v1 = append(traps_v1, trap_v1)
	}

	dst.Spec.Traps = traps_v1
	return nil
}
