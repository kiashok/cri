//go:build !windows

/*
Copyright 2017 The Kubernetes Authors.

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

package server

import (
	api "github.com/containerd/cri/pkg/api/v1"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	sandboxstore "github.com/containerd/cri/pkg/store/sandbox"
)

func (c *criService) resetSandbox(ctx context.Context, sandbox sandboxstore.Sandbox) (retErr error) {
	return errors.New("ResetPodSandbox not implemented on unix")
}
